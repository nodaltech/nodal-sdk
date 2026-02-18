import json
from typing import Any, AsyncGenerator, Tuple

import requests
import zmq
import zmq.asyncio
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

    curve_private: str
    curve_public: str

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

    async def _bind(self):
        sock_type = zmq.DEALER  # Mitigator
        if self.component_type == "Feeder":
            sock_type = zmq.PUB
        elif self.component_type == "Reporter":
            sock_type = zmq.SUB

        self.socket = self.context.socket(sock_type)

        if self.component_type == "Feeder":
            self.socket.setsockopt(zmq.SNDHWM, 200)
            self.socket.setsockopt(zmq.TCP_KEEPALIVE, 1)
            self.socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE, 30)
            self.socket.setsockopt(zmq.TCP_KEEPALIVE_INTVL, 10)
            self.socket.setsockopt(zmq.TCP_KEEPALIVE_CNT, 10)
        else:  # Mitigator
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
        await self._bind()

    def send(self, cmd: str, data: Any):
        try:
            msgb = [cmd.encode("utf-8"), json.dumps(data).encode("utf-8")]
            self.socket.send_multipart(msgb, zmq.DONTWAIT)
        except zmq.Again:
            print(f"{self.component_type} '{self.name}' not connected to brain...")
        except Exception as e:
            print(e)

    async def recv(self) -> AsyncGenerator[Tuple[str, Any], None]:
        socks = dict(await self.poller.poll(100))

        while self.socket in socks:
            try:
                msgb = self.socket.recv_multipart(zmq.DONTWAIT)
                cmd = msgb[0].decode("utf-8")

                # Handle ping command without data field
                if cmd != "ping":
                    data = json.loads(msgb[1].decode("utf-8"))
                    yield (cmd, data)
                else:
                    yield (cmd, {})

            except zmq.Again:
                break
            except Exception as e:
                print(e)
                break
