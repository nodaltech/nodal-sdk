from typing import Dict, List, Literal, NotRequired, Tuple, TypedDict
from numpy.typing import NDArray


class GlobalIpMitigation(TypedDict):
    ext_ip: str


class IntExtIpMitigation(TypedDict):
    int_ip: str
    int_ports: List[int]
    ext_ip: str
    ext_ports: List[int]


class IsolationMitigation(TypedDict):
    ip: str
    mac: str


class DomainMitigation(TypedDict):
    fqdn: str


class MitigationType(TypedDict):
    GlobalIp: GlobalIpMitigation
    IntExtIp: IntExtIpMitigation
    Isolation: IsolationMitigation
    Domain: DomainMitigation


class Mitigation(TypedDict):
    mitigation_id: str
    mitigator: str | None
    targets: MitigationType
    status: Literal["Requested", "Unrequested", "Enabled", "Disabled"]

    tag: str
    case_id: str | None
    ts: float
    expiry: float


class DeviceKey(TypedDict):
    Internal: NotRequired[str]
    External: NotRequired[str]


class IdentityData(TypedDict):
    name: str
    source: str


class Event(TypedDict):
    event_id: str
    device: DeviceKey
    peer: NotRequired[DeviceKey]
    description: str

    device_ip: NotRequired[str]
    peer_ip: NotRequired[str]
    trigger_packet: NotRequired[Dict]
    identity: NotRequired[IdentityData]
    metadata: Dict[str, str]
    ts: float


class Inference(TypedDict):
    inference_id: str
    ts: float
    c2_chain: List[Tuple[DeviceKey, NDArray]]
    average: float
    histogram: List[float]


class Case(TypedDict):
    case_id: str
    variant: str
    description: str
    mac: str
    ips: Dict[str, float]
    ns_ip: str
    events: List[Event]
    inferences: List[Inference]
    fabric: NDArray
    expiry: float
    ts: float
    closed: bool
