"""
Mapping from Microsoft Graph driveItem changes to Nodal feeder events.

One shape comes in: a `driveItem` from a `delta` response, fetched after a
change notification. It carries the item's latest state and who touched it last.

Delta reports state, not history, so the action is inferred:

  a `deleted` facet                      -> deleted
  createdDateTime == lastModifiedDateTime -> created
  anything else                           -> edited

Graph reports no client address for file activity, so there is no real device to
key these events on. The actor's identity is the meaningful key, and it is what
lets Brain line them up with the rest of the fabric and request identity
mitigations. Brain needs a device regardless, so the configured `DEVICE_IP` is
attached to every event - an attribution placeholder, not an observation.
"""

import ipaddress
import logging
from typing import Any, Dict, Iterable, List, Optional

from nodal_sdk.feeder import EventBuilder
from nodal_sdk.types import DeviceKey, Event

from o365_graph import parse_ts

log = logging.getLogger("o365.events")

IDENTITY_SOURCE = "office365"

# action -> (label, weight key)
ACTIONS = {
    "create": ("file created", "file_created"),
    "edit": ("file edited", "file_edited"),
    "delete": ("file deleted", "file_deleted"),
}

DEFAULT_WEIGHTS = {
    "file_created": 0.15,
    "file_edited": 0.10,
    # bulk deletion is the ransomware shape, and the sharpest signal delta gives
    "file_deleted": 0.30,
}

# Used only to decide whether the configured DEVICE_IP is internal or external.
# `is_private` is not used, because it also covers the documentation and
# benchmarking ranges, which would land a real public IP on the internal side.
INTERNAL_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",  # carrier grade NAT, common on corporate VPN pools
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
]


def device_key(ip: str) -> DeviceKey:
    """
    Key an address as internal or external.

    An internal address becomes `RoutedInternal` rather than `Internal`: there is
    no MAC to key on, and there never will be for a cloud feed.

    Raises ValueError on a missing or unparseable address, so a bad DEVICE_IP
    stops the feeder at startup rather than at the first event.
    """
    if not str(ip or "").strip():
        raise ValueError(
            "DEVICE_IP is required - every event needs a device, and Graph "
            "reports no address for file activity, so one has to be configured"
        )
    addr = ipaddress.ip_address(str(ip).strip())
    nets = [ipaddress.ip_network(c) for c in INTERNAL_CIDRS]
    if any(addr.version == net.version and addr in net for net in nets):
        return {"RoutedInternal": str(addr)}
    return {"External": str(addr)}


class EventMapper:
    def __init__(
        self,
        device_ip: str,
        weights: Optional[Dict[str, float]] = None,
        upn_resolver=None,
    ):
        self.weights = dict(DEFAULT_WEIGHTS)
        self.weights.update(weights or {})
        # GraphClient.user_upn, so an actor known only by object id still gets a
        # usable identity. Optional to keep the mapper testable offline.
        self.upn_resolver = upn_resolver

        # Resolved once, and required: the same stand-in device rides on every
        # event in the feed.
        self.device_ip = str(device_ip or "").strip()
        self.device: DeviceKey = device_key(self.device_ip)

    def actor_identity(self, actor: Dict[str, Any]) -> Optional[str]:
        """
        Pull a usable identity out of a Graph identitySet.

        Preference order is UPN, then email, then a resolved lookup on the object
        id, then the display name. The display name is a poor key - not unique,
        and not what other feeds report - so it is a last resort.
        """
        user = (actor or {}).get("user") or {}

        for field in ("userPrincipalName", "email"):
            value = str(user.get(field) or "").strip()
            if value:
                return value

        user_id = str(user.get("id") or "").strip()
        if user_id and self.upn_resolver is not None:
            resolved = self.upn_resolver(user_id)
            if resolved:
                return resolved

        display = str(user.get("displayName") or "").strip()
        if display:
            return display

        # an application or service principal acting on its own behalf
        for kind in ("application", "device"):
            name = str(((actor or {}).get(kind) or {}).get("displayName") or "").strip()
            if name:
                return name

        return None

    def map_item(self, item: Dict[str, Any], drive: Dict[str, str]) -> Optional[Event]:
        """Turn one changed driveItem into an Event, or None if we skip it."""
        # the drive root comes back on every delta as the hierarchy's parent
        if item.get("root") is not None:
            return None

        deleted = item.get("deleted") is not None
        is_folder = item.get("folder") is not None
        if is_folder and not deleted:
            return None  # folder metadata churn is noise; a deletion is not

        created = parse_ts(item.get("createdDateTime"))
        modified = parse_ts(item.get("lastModifiedDateTime"))

        if deleted:
            action = "delete"
        elif created and modified and created == modified:
            action = "create"
        else:
            action = "edit"

        label, weight_key = ACTIONS[action]
        desc = f"{drive.get('label', 'OneDrive')} {label}"

        actor = item.get("lastModifiedBy") or item.get("createdBy") or {}
        identity = self.actor_identity(actor)
        if identity is None:
            log.debug("skipping %s of %s - no identifiable actor", action, item.get("id"))
            return None

        # The device is the configured stand-in, not something Graph told us -
        # identity is the key that actually means anything here.
        event = EventBuilder(self.device, desc=desc)
        event.weight(self.weights.get(weight_key, 0.15))
        event.set_identity(identity, IDENTITY_SOURCE)

        # A bucket per (action, user, item) means one file touched repeatedly
        # stays quiet, while a user working through many distinct files piles up
        # buckets fast - the shape worth catching.
        item_id = str(item.get("id", ""))
        event.hash_bucket(desc, identity, item_id)

        parent = item.get("parentReference") or {}
        metadata = {
            "action": action,
            "item_id": item_id,
            "item_name": str(item.get("name", "")),
            "item_path": str(parent.get("path", "")),
            "item_type": "folder" if is_folder else "file",
            "web_url": str(item.get("webUrl", "")),
            "size": str(item.get("size", "")),
            "mime_type": str(((item.get("file") or {}).get("mimeType")) or ""),
            "created": str(item.get("createdDateTime", "")),
            "modified": str(item.get("lastModifiedDateTime", "")),
            "actor": identity,
            "actor_display": str(((actor.get("user") or {}).get("displayName")) or ""),
            "drive_id": drive.get("drive_id", ""),
            "drive_type": drive.get("drive_type", ""),
            "drive_owner": drive.get("owner", ""),
        }
        event.set_metadata({k: str(v) for k, v in metadata.items() if v not in (None, "")})

        data = event.get_data()
        data["device_ip"] = self.device_ip

        # use Microsoft's timestamp, not ingestion time - notifications average
        # under a minute but can lag far longer, and events would otherwise
        # cluster at the wrong moment
        when = modified or created
        if when is not None:
            data["ts"] = when.timestamp()

        return data

    def map_items(self, items: Iterable[Dict[str, Any]], drive: Dict[str, str]) -> List[Event]:
        events = []
        for item in items:
            try:
                event = self.map_item(item, drive)
            except Exception:
                log.exception("failed to map driveItem %s", item.get("id"))
                continue
            if event is not None:
                events.append(event)
        return events
