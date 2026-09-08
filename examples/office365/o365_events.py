"""
Mapping from Microsoft Graph itemActivity records to Nodal feeder events.

One shape comes in: an `itemActivity` from a drive's activity feed. It names the
action, who did it, and when - a file accessed, created, edited, deleted, moved,
renamed or shared.

Graph reports no client address for file activity, so there is no real device to
key these events on. The actor's identity is the meaningful key, and it is what
lets Brain line them up with the rest of the fabric and request identity
mitigations.

Brain needs a device regardless, so the configured `DEVICE_IP` is attached to
every event. It is an attribution placeholder, not an observation: the whole
feed shares it, whoever acted and wherever they were.
"""

import ipaddress
import logging
from typing import Any, Dict, Iterable, List, Optional

from nodal_sdk.types import DeviceKey

from nodal_sdk.feeder import EventBuilder
from nodal_sdk.types import Event

from o365_graph import parse_ts

log = logging.getLogger("o365.events")

IDENTITY_SOURCE = "office365"

# itemActionSet keys we feed, mapped to (label, weight key). Anything else Graph
# reports - comment, mention, version, restore - is dropped as noise.
ACTIONS = {
    "access": ("file accessed", "file_accessed"),
    "create": ("file created", "file_created"),
    "edit": ("file edited", "file_edited"),
    "delete": ("file deleted", "file_deleted"),
    "move": ("file moved", "file_moved"),
    "rename": ("file renamed", "file_renamed"),
    "share": ("file shared", "file_shared"),
}

# Used only to decide whether the configured DEVICE_IP is an internal or an
# external address. `is_private` is not used, because it also covers the
# documentation and benchmarking ranges, which would land a real public IP on
# the internal side of the fabric.
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

DEFAULT_WEIGHTS = {
    # a read is the exfiltration shape, and the reason this feed polls at all
    "file_accessed": 0.25,
    "file_created": 0.15,
    "file_edited": 0.10,
    # bulk deletion is the ransomware shape
    "file_deleted": 0.30,
    "file_moved": 0.15,
    "file_renamed": 0.15,
    # a share is the only one of these that can hand data to an outsider
    "file_shared": 0.40,
}


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

    # ---------------------------------------------------------------- helpers

    def actor_identity(self, actor: Dict[str, Any]) -> Optional[str]:
        """
        Pull a usable identity out of a Graph identitySet.

        Preference order is UPN, then email, then a resolved lookup on the object
        id, then the display name. The display name is a poor key - it is not
        unique and not what other feeds report - so it is a last resort.
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

    @staticmethod
    def action_of(activity: Dict[str, Any]) -> Optional[str]:
        """
        Find the action on an activity.

        v1.0 puts the action keys at the top level (`{"access": {}}`); the beta
        endpoint nests them under `action`. Both are accepted so switching the
        endpoint does not silently produce an empty feed.
        """
        for source in (activity, activity.get("action") or {}):
            for name in ACTIONS:
                if source.get(name) is not None:
                    return name
        return None

    @staticmethod
    def when_of(activity: Dict[str, Any]) -> Any:
        """v1.0 says activityDateTime, beta says times.recordedTime."""
        return parse_ts(
            activity.get("activityDateTime")
            or (activity.get("times") or {}).get("recordedTime")
        )

    @staticmethod
    def _item_fields(item: Dict[str, Any]) -> Dict[str, str]:
        parent = item.get("parentReference") or {}
        return {
            "item_id": str(item.get("id", "")),
            "item_name": str(item.get("name", "")),
            "item_path": str(parent.get("path", "")),
            "web_url": str(item.get("webUrl", "")),
            "size": str(item.get("size", "")),
            "mime_type": str(((item.get("file") or {}).get("mimeType")) or ""),
        }

    # ----------------------------------------------------------------- mapping

    def map_activity(self, activity: Dict[str, Any], drive: Dict[str, str]) -> Optional[Event]:
        """Turn one itemActivity into an Event, or None if we don't feed its action."""
        action = self.action_of(activity)
        if action is None:
            return None

        label, weight_key = ACTIONS[action]
        desc = f"{drive.get('label', 'OneDrive')} {label}"

        identity = self.actor_identity(activity.get("actor") or {})
        if identity is None:
            # nothing to key the event on: no address, and now no user either
            log.debug("skipping activity %s - no identifiable actor", activity.get("id"))
            return None

        # The device is the configured stand-in, not something Graph told us -
        # identity is the key that actually means anything here.
        event = EventBuilder(self.device, desc=desc)
        event.weight(self.weights.get(weight_key, 0.15))
        event.set_identity(identity, IDENTITY_SOURCE)

        fields = self._item_fields(activity.get("driveItem") or {})

        # A bucket per (action, user, item) means one file touched repeatedly
        # stays quiet, while a user working through many distinct files piles up
        # buckets fast - the exfiltration shape worth catching.
        #
        # Drive-wide activity listings do not always expand driveItem, and there
        # is no $expand to ask with. Without an item, bucket on the user alone:
        # that under-counts, which is the safe direction - bucketing on the
        # activity id instead would give every single read its own bucket and
        # drive cases on ordinary work.
        if fields["item_id"]:
            event.hash_bucket(desc, identity, fields["item_id"])
        else:
            event.hash_bucket(desc, identity)

        metadata = dict(fields)
        metadata.update(
            {
                "action": action,
                "activity_id": str(activity.get("id", "")),
                "activity_time": str(
                    activity.get("activityDateTime")
                    or (activity.get("times") or {}).get("recordedTime")
                    or ""
                ),
                "actor": identity,
                "actor_display": str(
                    (((activity.get("actor") or {}).get("user") or {}).get("displayName")) or ""
                ),
                "drive_id": drive.get("drive_id", ""),
                "drive_type": drive.get("drive_type", ""),
                "drive_owner": drive.get("owner", ""),
            }
        )
        event.set_metadata({k: str(v) for k, v in metadata.items() if v not in (None, "")})

        data = event.get_data()
        data["device_ip"] = self.device_ip

        # use Microsoft's timestamp, not ingestion time - the activity feed lags
        # by an unspecified amount, and events would otherwise cluster at the
        # wrong moment
        when = self.when_of(activity)
        if when is not None:
            data["ts"] = when.timestamp()

        return data

    def map_activities(
        self, activities: Iterable[Dict[str, Any]], drive: Dict[str, str]
    ) -> List[Event]:
        events = []
        for activity in activities:
            try:
                event = self.map_activity(activity, drive)
            except Exception:
                log.exception("failed to map activity %s", activity.get("id"))
                continue
            if event is not None:
                events.append(event)
        return events
