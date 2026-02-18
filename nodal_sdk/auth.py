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
