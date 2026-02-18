# Nodal SDK

Python SDK for building external components that integrate with [Nodal Cyberbrain](https://nodaltechnologies.com).

The SDK provides three component types for interacting with the Cyberbrain over encrypted ZeroMQ connections:

- **Mitigator** — Receives block/unblock requests and enacts firewall rules
- **Feeder** — Pushes security events into the Cyberbrain from external sources
- **Reporter** — Subscribes to cases and events for downstream reporting

## Installation

Install from source:

```bash
git clone https://github.com/nodaltech/nodal-sdk.git && cd nodal-sdk
pip install -e .
```

**Dependencies:** `zmq`, `requests`

## Quick Start

Every component follows the same pattern: create an instance, register with Ghost (the Cyberbrain's auth proxy), then run your logic in an async loop.

```python
import asyncio

async def main():
    # 1. Create your component
    # 2. Register with Ghost
    # 3. Run your event loop

if __name__ == "__main__":
    asyncio.run(main())
```

### Registration

All components authenticate through Ghost before communicating with the Cyberbrain. Call `register()` with:

- **ip** — The IP address your component is reachable at
- **ghost_uri** — The Ghost handshake endpoint (e.g. `http://localhost:8080/api/components/handshake`)
- **token** — A shared secret configured in Ghost

```python
await component.register("127.0.0.1", "http://localhost:8080/api/components/handshake", "my_token")
```

Under the hood, this performs an ECC key exchange: the SDK generates a CurveZMQ keypair, sends the public key to Ghost, and receives the Cyberbrain's public key in return. All subsequent ZMQ traffic is encrypted and mutually authenticated. Keys are stored in `./curve/<component_name>/`.

## Mitigator

Mitigators receive mitigation requests from the Cyberbrain and enact network blocks (firewall rules, ACLs, device isolation, etc.). The SDK handles deduplication, expiry tracking, and persistence via a local SQLite database.

```python
import asyncio
from nodal_sdk import Mitigator
from nodal_sdk.mitigator import Mitigation

async def main():
    mitigator = Mitigator("my-firewall", 2000)
    await mitigator.register("127.0.0.1", "http://localhost:8080/api/components/handshake", "token")

    async def enable(mitigation: Mitigation) -> Mitigation | None:
        data = mitigation.get_data()

        if "IntExtIp" in data["targets"]:
            target = data["targets"]["IntExtIp"]
            # Block traffic between target["int_ip"] <-> target["ext_ip"]
            # target["int_ports"] and target["ext_ports"] are also available

        elif "GlobalIp" in data["targets"]:
            target = data["targets"]["GlobalIp"]
            # Block all traffic to/from target["ext_ip"]

        elif "Isolation" in data["targets"]:
            target = data["targets"]["Isolation"]
            # Isolate device with target["mac"] / target["ip"]

        elif "Domain" in data["targets"]:
            target = data["targets"]["Domain"]
            # Block target["fqdn"]

        mitigation.set_enabled()
        return mitigation

    async def disable(mitigation: Mitigation) -> Mitigation | None:
        data = mitigation.get_data()
        # Reverse whatever was done in enable()
        mitigation.set_disabled()
        return mitigation

    async def refresh(mitigation: Mitigation) -> Mitigation | None:
        # Called when Brain extends an existing mitigation's expiry.
        # The SDK auto-updates the expiry in SQLite — usually no action needed.
        pass

    while True:
        await mitigator.handle(enable, disable, refresh)

if __name__ == "__main__":
    asyncio.run(main())
```

### Handler Rules

- **Return the `Mitigation` object** to persist it to the local SQLite database. Return `None` to skip persistence.
- Call `mitigation.set_enabled()` after successfully enacting a block, and `mitigation.set_disabled()` after removing one.
- The SDK automatically calls your `disable` handler when a mitigation expires.
- Duplicate mitigations are deduplicated automatically — `enable` is only called for new mitigations.

### Storing Custom Data

Use `set_user_data()` / `get_user_data()` to attach implementation-specific state (e.g. a firewall rule ID) that persists across enable/disable:

```python
async def enable(mitigation: Mitigation) -> Mitigation | None:
    rule_id = create_firewall_rule(...)
    mitigation.set_user_data({"rule_id": rule_id})
    mitigation.set_enabled()
    return mitigation

async def disable(mitigation: Mitigation) -> Mitigation | None:
    rule_id = mitigation.get_user_data()["rule_id"]
    delete_firewall_rule(rule_id)
    mitigation.set_disabled()
    return mitigation
```

### Mitigation Target Types

The `targets` dict will contain exactly one of these keys:

| Key | Fields | Use Case |
|-----|--------|----------|
| `GlobalIp` | `ext_ip` | Block all traffic to/from an external IP |
| `IntExtIp` | `int_ip`, `int_ports`, `ext_ip`, `ext_ports` | Block traffic between a specific internal/external pair |
| `Isolation` | `ip`, `mac` | Completely isolate an internal device |
| `Domain` | `fqdn` | Block a domain |

## Feeder

Feeders push security events into the Cyberbrain from external sources (log feeds, threat intel, etc.). Use `EventBuilder` to construct events.

```python
import asyncio
from nodal_sdk import Feeder
from nodal_sdk.feeder import EventBuilder

async def main():
    feeder = Feeder("my-feed", 4002)
    await feeder.register("127.0.0.1", "http://localhost:8080/api/components/handshake", "token")

    # Build an event targeting an internal device by MAC
    event = EventBuilder(internal_mac="aa:bb:cc:dd:ee:ff", desc="Suspicious outbound traffic")

    # Or target an external IP instead:
    # event = EventBuilder(external_ip="203.0.113.50", desc="Known C2 server activity")

    # Optional fields
    event.set_internal_peer_ip("192.168.1.244")    # peer IP involved
    event.set_external_peer_ip("203.0.113.50")     # or set an external peer
    event.set_internal_peer_mac("11:22:33:44:55:66")  # or a peer by MAC
    event.set_metadata({"source": "ids", "severity": "high"})
    event.set_identity("user@corp.com", "active-directory")  # (name, source)

    feeder.send("event", event.get_data())

if __name__ == "__main__":
    asyncio.run(main())
```

### EventBuilder

| Method | Description |
|--------|-------------|
| `EventBuilder(internal_mac=..., desc=...)` | Create event targeting an internal device by MAC |
| `EventBuilder(external_ip=..., desc=...)` | Create event targeting an external IP |
| `set_metadata(dict)` | Attach key-value metadata |
| `set_identity(name, source)` | Tag the device's identity (e.g. username, hostname) |
| `set_internal_peer_ip(ip)` | Set the peer's internal IP |
| `set_internal_peer_mac(mac)` | Set the peer by internal MAC |
| `set_external_peer_ip(ip)` | Set the peer as an external IP |
| `get_data()` | Returns the constructed `Event` dict |

## Reporter

Reporters subscribe to cases and/or events from the Cyberbrain for downstream processing (SIEM integration, webhook delivery, alerting, etc.).

```python
import asyncio
from nodal_sdk import Reporter
from nodal_sdk.types import Case, Event

async def main():
    reporter = Reporter("my-reporter", 4001)
    await reporter.register("127.0.0.1", "http://localhost:8080/api/components/handshake", "token")

    # Subscribe to what you need:
    reporter.subscribe_all()       # cases and events
    # reporter.subscribe_cases()   # cases only
    # reporter.subscribe_events()  # events only

    async def handle_case(case: Case):
        print(f"Case {case['case_id']}: {case['description']}")
        # case['events'] — list of associated events
        # case['inferences'] — ML-generated threat inferences
        # case['mac'] — target device MAC
        # case['ns_ip'] — suspected C2 / north-south IP
        # case['ips'] — dict of IPs to confidence scores

    async def handle_event(event: Event):
        print(f"Event {event['event_id']}: {event['description']}")

    while True:
        await reporter.handle(handle_case=handle_case, handle_event=handle_event)

if __name__ == "__main__":
    asyncio.run(main())
```

## Types Reference

All types are defined in `nodal_sdk.types` as `TypedDict` classes.

### Case

| Field | Type | Description |
|-------|------|-------------|
| `case_id` | `str` | Unique case identifier |
| `variant` | `str` | `"Activity"` or `"Analyst"` |
| `description` | `str` | Human-readable case description |
| `mac` | `str` | Target device MAC address |
| `ips` | `Dict[str, float]` | Associated IPs with confidence scores |
| `ns_ip` | `str` | Suspected north-south (C2) IP |
| `events` | `List[Event]` | Events that contributed to this case |
| `inferences` | `List[Inference]` | ML threat inferences |
| `fabric` | `NDArray` | Visualization matrix (remove before serializing) |
| `expiry` | `float` | Unix timestamp |
| `ts` | `float` | Unix timestamp |
| `closed` | `bool` | Whether the case is closed |

### Event

| Field | Type | Description |
|-------|------|-------------|
| `event_id` | `str` | Unique event identifier |
| `device` | `DeviceKey` | Target device (`Internal` MAC or `External` IP) |
| `peer` | `DeviceKey` | (optional) Peer device |
| `description` | `str` | Event description |
| `device_ip` | `str` | (optional) Device IP |
| `peer_ip` | `str` | (optional) Peer IP |
| `trigger_packet` | `Dict` | (optional) Packet that triggered the event |
| `identity` | `IdentityData` | (optional) Device identity (`name`, `source`) |
| `metadata` | `Dict[str, str]` | Key-value metadata |
| `ts` | `float` | Unix timestamp |

### Mitigation

| Field | Type | Description |
|-------|------|-------------|
| `mitigation_id` | `str` | Unique identifier |
| `mitigator` | `str \| None` | Name of the mitigator that handled it |
| `targets` | `MitigationType` | Contains one of: `GlobalIp`, `IntExtIp`, `Isolation`, `Domain` |
| `status` | `str` | `"Requested"`, `"Unrequested"`, `"Enabled"`, or `"Disabled"` |
| `tag` | `str` | Descriptive tag |
| `case_id` | `str \| None` | Associated case |
| `ts` | `float` | Unix timestamp |
| `expiry` | `float` | Unix timestamp |

## Examples

The `examples/` directory contains production-ready component implementations:

| Example | Type | Description |
|---------|------|-------------|
| `aws_acl.py` | Mitigator | AWS Network ACL deny rules via boto3 |
| `meraki_mitigator.py` | Mitigator | Cisco Meraki L3 firewall rules |
| `local_ufw.py` | Mitigator | Linux UFW route deny rules |
| `case_printer.py` | Reporter | Print cases to stdout |
| `webhook_case_reporter.py` | Reporter | POST cases to a webhook URL |
| `syslog.py` | Reporter | Syslog output in JSON or CEF format |
| `webhooks/CaseInvestigator.py` | Reporter | AI-powered case investigation with Claude |

## Project Structure

```
nodal-sdk/
├── nodal_sdk/           # SDK package
│   ├── __init__.py      # Exports: Mitigator, Feeder, Reporter, Component
│   ├── types.py         # TypedDict definitions
│   ├── component.py     # Base Component class (ZMQ + handshake)
│   ├── mitigator.py     # Mitigator + Mitigation wrapper
│   ├── feeder.py        # Feeder + EventBuilder
│   ├── reporter.py      # Reporter (subscribe + handle)
│   ├── auth.py          # CurveZMQ authenticator
│   └── curve.py         # ECC key management
├── base/                # Minimal implementation skeletons
├── examples/            # Production-ready examples
└── pyproject.toml
```
