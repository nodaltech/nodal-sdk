from time import time
from typing import Dict
from uuid import uuid4
import zmq

from nodal_sdk.component import Component
from nodal_sdk.types import DeviceKey, Event


class EventBuilder:
    event: Event

    def __init__(
        self,
        internal_mac: str | None = "ff02:",
        external_ip: str | None = None,
        desc: str = "Unconfigured event",
    ):
        device: DeviceKey = {"Internal": "ff02:"}

        if internal_mac:
            device["Internal"] = internal_mac
        elif external_ip:
            device["External"] = external_ip
        else:
            raise Exception(
                "An event needs either an internal MAC address or an external IP address as the event target."
            )

        self.event = {
            "event_id": str(uuid4()),
            "device": device,
            "description": desc,
            "ts": time(),
            "metadata": {},
        }

    def set_metadata(self, metadata: Dict[str, str]):
        self.event["metadata"] = metadata
        return self

    def set_internal_peer_mac(self, peer: str):
        self.event["peer"] = {"Internal": peer}

    def set_internal_peer_ip(self, peer: str):
        self.event["peer_ip"] = peer

    def set_external_peer_ip(self, peer: str):
        self.event["peer"] = {"External": peer}

    def set_identity(self, name: str, source: str):
        self.event["identity"] = {"name": name, "source": source}

    def get_data(self) -> Event:
        return self.event


class Feeder(Component):
    def __init__(self, name: str, port: int):
        context = zmq.Context.instance()
        super().__init__(name, "Feeder", port, context)
