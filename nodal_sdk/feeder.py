from time import time
from typing import Any, Dict, List
from uuid import uuid4
import ctypes
import json
import zmq

from nodal_sdk.component import Component
from nodal_sdk.types import DeviceKey, Event

class EventBuilder:
    event: Event

    def __init__(
        self,
        device: DeviceKey,
        desc: str = "Unconfigured event",
    ):
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

    """
    This controls how Nodal aggregates events.
    
    If you were to hash just description, all events containing that description would 
    be confined to the same bucket, and would have little aggregate effect on a case triggering.

    If you were to hash description + peer, each description + peer combination would 
    be given its own bucket, increasing influence of each event on case creation.

    The more you hash, the larger the area of effect on Nodal's case triggering.
    """
    def hash_bucket(self, *args):
        hash_data = json.dumps([*args])
        hash_value = ctypes.c_size_t(hash(hash_data)).value
        self.event['hash'] = hash_value

    """
    This controls the influence of each individual event on Nodal case triggering.
    Weight should be a float between 0 and 1, and should indicate importance of the event,
    with 0 corresponding to low importance and 1 corresponding to high.

    Low-signal / noisy events should be given a low weight.
    """
    def weight(self, weight: float):
        assert weight >= 0 and weight <= 1
        self.event['weight'] = weight

    def get_data(self) -> Event:
        return self.event


class Feeder(Component):
    def __init__(self, name: str, port: int):
        context = zmq.Context.instance()
        super().__init__(name, "Feeder", port, context)
