from typing import Awaitable, Callable
import zmq

from nodal_sdk.component import Component
from nodal_sdk.types import Case, Event


class Reporter(Component):
    def __init__(self, name: str, port: int):
        context = zmq.Context.instance()
        super().__init__(name, "Reporter", port, context)

    def subscribe_cases(self):
        self.socket.subscribe(b"case")

    def subscribe_events(self):
        self.socket.subscribe(b"event")

    def subscribe_all(self):
        self.socket.subscribe(b"")

    async def handle(
        self,
        handle_case: Callable[[Case], Awaitable[None]] | None = None,
        handle_event: Callable[[Event], Awaitable[None]] | None = None,
    ):
        async for cmd, data in self.recv():
            match cmd:
                case "case":
                    if handle_case:
                        await handle_case(data)
                    break
                case "event":
                    if handle_event:
                        await handle_event(data)
                    break
