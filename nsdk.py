# FROM nodal_sdk/__init__.py:
# nodal_sdk/__init__.py

import nodal_sdk.types as types
from nodal_sdk.component import Component
from nodal_sdk.feeder import Feeder
from nodal_sdk.mitigator import Mitigator
from nodal_sdk.reporter import Reporter

__version__ = "0.1.0"
__all__ = ["Component", "Mitigator", "Feeder", "Reporter", "types"]


# FROM nodal_sdk/auth.py:
import asyncio
from typing import List

import zmq
import zmq.asyncio


class CurveAuthenticator:
    socket: zmq.Socket
    poller: zmq.Poller
    allow: List[bytes]

    def __init__(self, allow: List[bytes]):
        ctx = zmq.Context.instance()
        sock = ctx.socket(zmq.ROUTER)
        sock.bind("inproc://zeromq.zap.01")

        self.poller = zmq.asyncio.Poller()
        self.poller.register(sock, zmq.POLLIN)

        self.socket = sock
        self.allow = allow
        self.task = None

    def auth_handler(self, msgb: List[bytes]):
        auth_server = msgb[0]
        delim = msgb[1]
        version = msgb[2]
        request_id = msgb[3]
        address = msgb[5]
        curve_publickey = msgb[8]

        reply = [
            auth_server,
            delim,
            version,
            request_id,
            b"403",
            b"denied",
            address,
            b"",
        ]
        if curve_publickey in self.allow:
            reply[4] = b"200"
            reply[5] = b"allowed"
            print("Brain at %s authenticated" % address.decode("utf-8"))

        self.socket.send_multipart(reply)

    async def _start(self):
        while True:
            socks = dict(await self.poller.poll(100))
            try:
                while self.socket in socks:
                    try:
                        msgb = self.socket.recv_multipart(zmq.DONTWAIT)
                        self.auth_handler(msgb)
                    except zmq.Again:
                        break
                    except Exception as e:
                        print(e)
                        break
            except Exception as e:
                print(e)

    async def start(self):
        if not self.task:
            self.task = asyncio.create_task(self._start())

    def stop(self):
        try:
            self.task.cancel()
        except Exception as e:
            return


# FROM nodal_sdk/component.py:
import json
from typing import AsyncGenerator, Callable, Dict, List, Tuple

import requests
import zmq
import zmq.asyncio
import zmq.auth
import zmq.utils
import zmq.utils.z85

from nodal_sdk.auth import CurveAuthenticator
from nodal_sdk.curve import Curve


class Component:
    name: str
    component_type: str
    port: int

    context: zmq.Context
    socket: zmq.Socket
    poller: zmq.asyncio.Poller

    curve_private: bytes
    curve_public: bytes

    authserver: CurveAuthenticator

    def __init__(self, name: str, component_type: str, port: int, context: zmq.Context):
        self.name = name
        self.component_type = component_type
        self.port = port
        self.context = context
        self.poller = zmq.asyncio.Poller()

    def _handshake(self, ip: str, handshake_url: str, token: str):
        existing_brain = Curve.load_keyspace_brain(self.name)
        if existing_brain is not None:
            print("Using key from previous handshake...")
            return existing_brain

        partial_definition = {
            "name": self.name,
            "component_type": self.component_type,
            "ip": ip,
            "port": self.port,
            "token": token,
            "public_key": self.curve_public,
        }

        resp = requests.post(handshake_url, json=partial_definition)
        if resp.status_code != 200:
            raise Exception(f"Handshake failed with ghost {resp.status_code}")

        resp = resp.json()

        if not resp["z85_brain_publickey"]:
            raise Exception(
                f"Handshake failed - could not find 'z85_brain_pubkey' in response"
            )

        z85_brain_pubkey = resp["z85_brain_publickey"]
        Curve.write_brain_key(self.name, z85_brain_pubkey)

        print(f"Handshake with ghost at {handshake_url} completed")
        return z85_brain_pubkey

    async def _authserver(self, public_key: str):
        b_pubkey = zmq.utils.z85.decode(public_key)
        self.authserver = CurveAuthenticator([b_pubkey])
        await self.authserver.start()

    async def _bind(self, sock_type: zmq.SocketType):
        self.socket = self.context.socket(sock_type)

        self.socket.setsockopt(zmq.RCVHWM, 100)
        self.socket.setsockopt(zmq.SNDHWM, 100)

        self.socket.setsockopt(zmq.CURVE_SERVER, True)
        self.socket.setsockopt(zmq.CURVE_PUBLICKEY, self.curve_public.encode("utf-8"))
        self.socket.setsockopt(zmq.CURVE_SECRETKEY, self.curve_private.encode("utf-8"))

        self.socket.bind(f"tcp://*:{self.port}")

        self.poller.register(self.socket, zmq.POLLIN)

    async def register(self, ip: str, handshake_uri: str, token: str):
        self.curve_public, self.curve_private = Curve.with_curve_keys(self.name)
        await self._authserver(self._handshake(ip, handshake_uri, token))
        await self._bind(zmq.DEALER)

    def send(self, cmd: str, data: Dict):
        try:
            msgb = [cmd.encode("utf-8"), json.dumps(data).encode("utf-8")]
            self.socket.send_multipart(msgb, zmq.DONTWAIT)
        except zmq.Again:
            print(f"{self.component_type} '{self.name}' not connected to brain...")
        except Exception as e:
            print(e)

    async def recv(self) -> AsyncGenerator[Tuple[str, Dict], None]:
        socks = dict(await self.poller.poll(100))

        while self.socket in socks:
            try:
                msgb = self.socket.recv_multipart(zmq.DONTWAIT)
                cmd = msgb[0].decode("utf-8")
                data = json.loads(msgb[1].decode("utf-8"))
                yield (cmd, data)
            except zmq.Again:
                break
            except Exception as e:
                print(e)
                break


# FROM nodal_sdk/curve.py:
import os
from typing import Tuple

import zmq
from zmq.utils import z85


class Curve:
    @staticmethod
    def with_curve_keys(name: str) -> Tuple[str, str]:
        namespace = f"./curve/{name}"
        if not os.path.exists(namespace):
            os.makedirs(namespace)

        pub_keyspace = os.path.join(namespace, "curve.pub")
        priv_keyspace = os.path.join(namespace, "curve.key")

        if not os.path.exists(pub_keyspace) or not os.path.exists(priv_keyspace):
            if os.path.exists(pub_keyspace):
                os.unlink(pub_keyspace)

            if os.path.exists(priv_keyspace):
                os.unlink(priv_keyspace)

            pub_key, priv_key = zmq.curve_keypair()
            pub_key = pub_key.decode("utf-8")
            priv_key = priv_key.decode("utf-8")

            with open(pub_keyspace, "w") as f:
                f.write(pub_key)
                f.flush()

            with open(priv_keyspace, "w") as f:
                f.write(priv_key)
                f.flush()

        pub = open(pub_keyspace, "r").read()
        priv = open(priv_keyspace, "r").read()

        return (pub, priv)

    @staticmethod
    def as_binary(keys: Tuple[str, str]) -> Tuple[bytes, bytes]:
        return tuple(z85.decode(k) for k in keys)

    @staticmethod
    def namespace(name: str) -> str:
        namespace = f"./curve/{name}/"
        if not os.path.exists(namespace):
            os.makedirs(namespace)

        return namespace

    @staticmethod
    def write_public_key(name: str, z85_key: str):
        namespace = f"./curve/{name}"
        if not os.path.exists(namespace):
            os.makedirs(namespace)

        keyspace = os.path.join(namespace, "curve.pub")
        if os.path.exists(keyspace):
            os.unlink(keyspace)

        with open(keyspace, "w") as f:
            f.write(z85_key)
            f.flush()

    @staticmethod
    def write_brain_key(name: str, z85_key: str):
        namespace = f"./curve/{name}"
        if not os.path.exists(namespace):
            os.makedirs(namespace)

        keyspace = os.path.join(namespace, "brain.pub")
        if os.path.exists(keyspace):
            os.unlink(keyspace)

        with open(keyspace, "w") as f:
            f.write(z85_key)
            f.flush()

    @staticmethod
    def load_keyspace_public(name: str) -> str | None:
        namespace = f"./curve/{name}"
        if not os.path.exists(namespace):
            return None

        keyspace = os.path.join(namespace, "curve.pub")
        if not os.path.exists(keyspace):
            return None

        publickey = open(keyspace, "r").read()
        return publickey

    @staticmethod
    def load_keyspace_brain(name: str) -> str | None:
        namespace = f"./curve/{name}"
        if not os.path.exists(namespace):
            return None

        keyspace = os.path.join(namespace, "brain.pub")
        if not os.path.exists(keyspace):
            return None

        publickey = open(keyspace, "r").read()
        return publickey


# FROM nodal_sdk/feeder.py:
import zmq

from nodal_sdk.component import Component


class Feeder(Component):
    def __init__(self, name: str, port: int):
        context = zmq.Context.instance()
        super().__init__(name, "Feeder", port, context)


# FROM nodal_sdk/mitigator.py:
import zmq

from nodal_sdk.component import Component


class Mitigator(Component):
    def __init__(self, name: str, port: int):
        context = zmq.Context.instance()
        super().__init__(name, "Mitigator", port, context)


# FROM nodal_sdk/reporter.py:
import zmq

from nodal_sdk.component import Component


class Reporter(Component):
    def __init__(self, name: str, port: int):
        context = zmq.Context.instance()
        super().__init__(name, "Reporter", port, context)


# FROM nodal_sdk/types.py:
from typing import Dict, List, TypedDict

from numpy.typing import NDArray


class MitigationRequest(TypedDict):
    mitigation_request_id: str
    action: str
    tag: str
    int_ip: str
    ext_ip: str
    mac: str
    duration: float
    expiry: float


class MitigationResponse(TypedDict):
    mitigation_request_id: str
    mitigation_id: str
    int_ip: str
    ext_ip: str
    mac: str
    duration: float
    expiry: float
    tag: str
    reason: str
    active: bool


class FeedEvent(TypedDict):
    event_id: str
    ts: float
    issues: List[str]
    mac: str
    ips: List[str]
    peer_mac: str
    peer_ip: str


class Event(TypedDict):
    event_id: str
    ts: float
    issues: List[str]
    mac: str
    ips: List[str]
    peer_mac: str
    peer_ip: str
    trigger_packet: Dict
    ns: Dict[str, Dict]
    ew: Dict[str, Dict]


class Inference:
    inference_id: str
    ts: float
    actor_mac: str
    gw_ip: str
    ns_ip: str
    chain_key: str
    model_name: str
    pred: NDArray


class Case:
    case_id: str
    variant: str
    description: str
    mac: str
    int_ip: str
    gw_ip: str
    ext_ip: str
    events: List[Event]
    inferences: List[Inference]
    expiry: float
    ts: float
    closed: bool
