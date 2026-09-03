"""
Mapping from Office 365 audit records to Nodal feeder events.

Two record families are handled:

  Entra ID sign-ins   Audit.AzureActiveDirectory / UserLoggedIn, UserLoginFailed
  OneDrive downloads  Audit.SharePoint / FileDownloaded, FileSyncDownloadedFull

Office 365 events have no MAC address, so the device key comes from the client
IP: RFC1918 (or any configured internal CIDR) becomes `RoutedInternal`, anything
else becomes `External`. The user principal name rides along as the event
identity, which is what lets Brain correlate these with the rest of the fabric
and request identity mitigations.
"""

import ipaddress
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

from nodal_sdk.feeder import EventBuilder
from nodal_sdk.types import DeviceKey, Event

from o365_mgmt import parse_ts

log = logging.getLogger("o365.events")

IDENTITY_SOURCE = "office365"

# Operation -> (description, weight key)
SIGNIN_OPS = {
    "UserLoggedIn": ("Entra ID sign-in succeeded", "entra_signin_success"),
    "UserLoginFailed": ("Entra ID sign-in failed", "entra_signin_failed"),
}

DOWNLOAD_OPS = {
    "FileDownloaded": ("file downloaded", "file_download"),
    "FileSyncDownloadedFull": ("file sync download", "file_sync_download"),
}

DEFAULT_WEIGHTS = {
    "entra_signin_success": 0.05,  # extremely common, keep it quiet
    "entra_signin_failed": 0.35,
    "file_download": 0.25,
    "file_sync_download": 0.15,
}

DEFAULT_INTERNAL_CIDRS = [
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


class EventMapper:
    def __init__(
        self,
        internal_cidrs: Optional[Iterable[str]] = None,
        weights: Optional[Dict[str, float]] = None,
        onedrive_only: bool = True,
    ):
        self.internal_nets = []
        for cidr in internal_cidrs if internal_cidrs is not None else DEFAULT_INTERNAL_CIDRS:
            try:
                self.internal_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log.warning("ignoring unparseable internal CIDR %r", cidr)

        self.weights = dict(DEFAULT_WEIGHTS)
        self.weights.update(weights or {})
        self.onedrive_only = onedrive_only

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def parse_ip(value: Any) -> Optional[str]:
        """
        Normalise the many shapes ClientIP arrives in.

        Seen in the wild: "1.2.3.4", "1.2.3.4:52130", "[2001:db8::1]:443",
        "2001:db8::1", "" and the occasional comma separated pair.
        """
        if not value:
            return None

        text = str(value).strip()
        if "," in text:
            text = text.split(",")[0].strip()

        if text.startswith("["):  # bracketed v6, optionally with a port
            text = text[1:].split("]")[0]
        elif text.count(":") == 1:  # v4 with a port
            text = text.split(":")[0]

        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            log.debug("could not parse client ip %r", value)
            return None

    def device_key(self, ip: str) -> DeviceKey:
        """
        Internal addresses key as RoutedInternal, everything else as External.

        Classification is driven purely by INTERNAL_CIDRS - `is_private` is not
        used, because it also covers the documentation and benchmarking ranges,
        which would land real public IPs on the internal side of the fabric.
        """
        addr = ipaddress.ip_address(ip)
        if any(addr.version == net.version and addr in net for net in self.internal_nets):
            # internal but reached us over a router, so there is no MAC to key on
            return {"RoutedInternal": ip}
        return {"External": ip}

    @staticmethod
    def extended_properties(record: Dict[str, Any]) -> Dict[str, str]:
        props = {}
        for entry in record.get("ExtendedProperties") or []:
            name = entry.get("Name")
            if name:
                props[str(name)] = str(entry.get("Value", ""))
        return props

    @staticmethod
    def device_properties(record: Dict[str, Any]) -> Dict[str, str]:
        props = {}
        for entry in record.get("DeviceProperties") or []:
            name = entry.get("Name")
            if name:
                props[str(name)] = str(entry.get("Value", ""))
        return props

    @staticmethod
    def client_ip_of(record: Dict[str, Any]) -> Any:
        # the field name is inconsistent across workloads
        for field in ("ClientIP", "ClientIp", "ActorIpAddress", "ClientIPAddress"):
            if record.get(field):
                return record[field]
        return None

    # ----------------------------------------------------------------- mapping

    def map_record(self, record: Dict[str, Any]) -> Optional[Event]:
        """Turn one audit record into an Event, or None if we don't care about it."""
        operation = str(record.get("Operation", ""))
        workload = str(record.get("Workload", ""))

        if operation in SIGNIN_OPS:
            return self._map_signin(record, operation)

        if operation in DOWNLOAD_OPS:
            if self.onedrive_only and workload != "OneDrive":
                return None
            return self._map_download(record, operation, workload)

        return None

    def _base(
        self,
        record: Dict[str, Any],
        desc: str,
        weight_key: str,
    ) -> Optional[Tuple[EventBuilder, str]]:
        ip = self.parse_ip(self.client_ip_of(record))
        if ip is None:
            # without an IP there is no device to attach the event to
            log.debug(
                "skipping %s record %s - no usable client ip",
                record.get("Operation"),
                record.get("Id"),
            )
            return None

        event = EventBuilder(self.device_key(ip), desc=desc)
        event.weight(self.weights.get(weight_key, 0.2))

        user = str(record.get("UserId") or "").strip()
        if user and user.lower() not in ("", "n/a", "system"):
            event.set_identity(user, IDENTITY_SOURCE)

        return event, ip

    def _finish(
        self,
        event: EventBuilder,
        record: Dict[str, Any],
        ip: str,
        metadata: Dict[str, str],
    ) -> Event:
        data = event.get_data()
        data["device_ip"] = ip

        # keep the audit trail: Id lets an analyst find the original record
        metadata.setdefault("audit_id", str(record.get("Id", "")))
        metadata.setdefault("operation", str(record.get("Operation", "")))
        metadata.setdefault("workload", str(record.get("Workload", "")))
        metadata.setdefault("record_type", str(record.get("RecordType", "")))
        event.set_metadata({k: str(v) for k, v in metadata.items() if v not in (None, "")})

        # use Microsoft's timestamp, not ingestion time - notifications lag by
        # minutes and events would otherwise cluster at the wrong moment
        created = parse_ts(str(record.get("CreationTime", "")))
        if created is not None:
            data["ts"] = created.timestamp()

        return data

    def _map_signin(self, record: Dict[str, Any], operation: str) -> Optional[Event]:
        desc, weight_key = SIGNIN_OPS[operation]
        built = self._base(record, desc, weight_key)
        if built is None:
            return None
        event, ip = built

        ext = self.extended_properties(record)
        dev = self.device_properties(record)
        user = str(record.get("UserId") or "unknown")
        device = event.get_data()["device"]

        # Successful sign-ins are constant background noise, so every sign-in for
        # a user shares one bucket. Failures are the interesting signal, so they
        # get a bucket per (user, source ip) and carry proportionally more.
        if operation == "UserLoginFailed":
            event.hash_bucket(desc, device, user)
        else:
            event.hash_bucket(desc, user)

        metadata = {
            "user": user,
            "result": str(record.get("ResultStatus", "")),
            "logon_error": str(record.get("LogonError", "")),
            "error_number": ext.get("ErrorNumber", ""),
            "result_detail": ext.get("ResultStatusDetail", ""),
            "request_type": ext.get("RequestType", ""),
            "user_agent": ext.get("UserAgent", "") or str(record.get("UserAgent", "")),
            "application": str(record.get("ApplicationId", "")),
            "device_os": dev.get("OS", ""),
            "device_browser": dev.get("BrowserType", ""),
            "device_compliant": dev.get("IsCompliant", ""),
            "device_managed": dev.get("IsCompliantAndManaged", ""),
            "trusted_location": dev.get("TrustType", ""),
        }
        return self._finish(event, record, ip, metadata)

    def _map_download(
        self,
        record: Dict[str, Any],
        operation: str,
        workload: str,
    ) -> Optional[Event]:
        label, weight_key = DOWNLOAD_OPS[operation]
        desc = f"{workload or 'SharePoint'} {label}"

        built = self._base(record, desc, weight_key)
        if built is None:
            return None
        event, ip = built

        user = str(record.get("UserId") or "unknown")
        file_name = str(record.get("SourceFileName") or "")
        file_path = str(record.get("SourceRelativeUrl") or record.get("ObjectId") or "")

        # A bucket per (user, file) means one file fetched repeatedly stays quiet
        # while a user pulling many distinct files piles up buckets fast - which
        # is exactly the exfiltration shape worth catching.
        event.hash_bucket(desc, user, file_path or file_name)

        metadata = {
            "user": user,
            "file_name": file_name,
            "file_path": file_path,
            "file_extension": str(record.get("SourceFileExtension", "")),
            "file_size": str(record.get("ObjectSizeInBytes", "")),
            "site_url": str(record.get("SiteUrl", "")),
            "user_agent": str(record.get("UserAgent", "")),
            "auth_type": str(record.get("AuthenticationType", "")),
            "sharing_scope": str(record.get("EventSource", "")),
            "app_name": str(record.get("ApplicationDisplayName", "")),
        }
        return self._finish(event, record, ip, metadata)

    def map_records(self, records: Iterable[Dict[str, Any]]) -> List[Event]:
        events = []
        for record in records:
            try:
                event = self.map_record(record)
            except Exception:
                log.exception("failed to map audit record %s", record.get("Id"))
                continue
            if event is not None:
                events.append(event)
        return events
