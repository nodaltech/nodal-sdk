"""CrowdStrike Falcon feeder — stream Falcon detections into Nodal Ghost as events.

A standalone SDK Feeder example: it holds a long-lived Falcon **Event Streams** connection and, for each
detection CrowdStrike pushes, emits a Nodal `Event` keyed by the host MAC (endpoint verdicts that enrich
the brain's network-derived cases). This is the feeder half of a full CrowdStrike integration, carved out
to show the pattern; it does no containment.

Event shape (what the brain receives), same as the production bridge:
  - `device: {Internal: <mac>}`  — a single, host-keyed device. **No `peer`** (endpoint detections are not
    network edges); a detection with no MAC falls back to `{External: <local_ip>}`.
  - `description` — a human-readable attack-type tag (DetectName, else MITRE technique/tactic).
  - `metadata` — the full CrowdStrike context (severity, MITRE tactic/technique, sha256, aid, …), all
    stringified; the brain scores it and links it to the host's case.

Config (environment variables):
  FALCON_CLIENT_ID / FALCON_CLIENT_SECRET   Falcon API client (scopes: Event Streams Read, Hosts Read)
  FALCON_BASE_URL                           Falcon cloud region (default https://api.us-2.crowdstrike.com)
  GHOST_HANDSHAKE_URL                       Ghost component handshake URL
                                            (default http://localhost:8080/api/components/handshake)
  COMPONENT_IP                              address the brain can reach this feeder on (default 127.0.0.1)
  FEEDER_TOKEN                              Ghost component token for this feeder
  FEEDER_NAME / FEEDER_PORT                 component name / bind port (default crowdstrike_feeder / 4011)
  FEEDER_APP_ID                             Event Streams app id (default nodal-crowdstrike-feed)
  FEED_LOOKBACK_SECS                        drop backlog older than this on (re)connect (default 300)

Run:  pip install crowdstrike-falconpy  &&  python examples/crowdstrike_feeder.py
"""
import asyncio
import json
import os
import queue
import threading
import time

import requests
from falconpy import EventStreams

from nodal_sdk import Feeder
from nodal_sdk.feeder import EventBuilder

# ---- config ----
FALCON = dict(client_id=os.environ.get("FALCON_CLIENT_ID", ""),
              client_secret=os.environ.get("FALCON_CLIENT_SECRET", ""),
              base_url=os.environ.get("FALCON_BASE_URL", "https://api.us-2.crowdstrike.com"))
GHOST_HANDSHAKE_URL = os.environ.get("GHOST_HANDSHAKE_URL", "http://localhost:8080/api/components/handshake")
COMPONENT_IP = os.environ.get("COMPONENT_IP", "127.0.0.1")
FEEDER_TOKEN = os.environ.get("FEEDER_TOKEN", "feed_token")
FEEDER_NAME = os.environ.get("FEEDER_NAME", "crowdstrike_feeder")
FEEDER_PORT = int(os.environ.get("FEEDER_PORT", "4011"))
FEEDER_APP_ID = os.environ.get("FEEDER_APP_ID", "nodal-crowdstrike-feed")
FEED_LOOKBACK_SECS = float(os.environ.get("FEED_LOOKBACK_SECS", "300"))

DETECTION_EVENT_TYPES = {"DetectionSummaryEvent", "EppDetectionSummaryEvent"}
# `description` is the first non-empty of these fields (detection dict, then its MITRE block).
TYPE_FIELDS = ["DetectName", "Name", "Technique", "Tactic", "Objective"]


# ---- detection -> Nodal Event mapping ----
def norm_mac_colon(m):
    """Normalize a MAC to lowercase colon form (CrowdStrike uses dashes), or '' if it isn't a MAC."""
    hexd = "".join(c for c in str(m or "").lower() if c in "0123456789abcdef")
    return ":".join(hexd[i:i + 2] for i in range(0, 12, 2)) if len(hexd) == 12 else ""


def attack_type(d):
    """Stable, human-readable attack-type tag for the event `description`."""
    mitre = (d.get("MitreAttack") or [{}])[0]
    for k in TYPE_FIELDS:
        v = d.get(k) or (mitre.get(k) if mitre else None)
        if v is not None and str(v).strip():
            return str(v).strip()
    return "Endpoint Detection"


def metadata(d, tag):
    """The full CrowdStrike context, stringified into the event metadata bag (empty fields dropped).
    Handles both DetectionSummaryEvent and EppDetectionSummaryEvent field spellings."""
    mitre = (d.get("MitreAttack") or [{}])[0]
    md = {
        "source": "crowdstrike",
        "attack_type": tag,  # mirrors `description` so it's queryable in metadata too
        "detect_name": d.get("DetectName") or d.get("Name", ""),
        "detect_description": (d.get("DetectDescription") or d.get("Description", "") or "")[:500],
        "severity": str(d.get("SeverityName", "")),
        "severity_value": str(d.get("Severity", "")),
        "confidence": str(d.get("Confidence", "")),
        "risk_score": str(d.get("RiskScore", "")),
        "tactic": d.get("Tactic", "") or mitre.get("Tactic", ""),
        "technique": d.get("Technique", "") or mitre.get("Technique", ""),
        "technique_id": d.get("TechniqueId", "") or mitre.get("TechniqueID", ""),
        "objective": d.get("Objective", ""),
        "scenario": d.get("Scenario", ""),
        "pattern_disposition": d.get("PatternDispositionDescription", ""),
        "aid": d.get("AgentId", "") or d.get("SensorId", ""),
        "composite_id": d.get("CompositeId", "") or d.get("DetectId", ""),
        "computer": d.get("Hostname") or d.get("ComputerName", ""),
        "local_ip": d.get("LocalIP", ""),
        "mac": d.get("MACAddress", ""),
        "username": d.get("UserName", ""),
        "filename": d.get("FileName", ""),
        "filepath": d.get("FilePath", ""),
        "sha256": d.get("SHA256String", ""),
        "md5": d.get("MD5String", ""),
        "cmdline": (d.get("CommandLine", "") or "")[:500],
        "ioc_type": d.get("IOCType", ""),
        "ioc_value": d.get("IOCValue", ""),
        "falcon_link": d.get("FalconHostLink", ""),
    }
    return {k: v for k, v in md.items() if v is not None and str(v).strip() != ""}


def build_event(d):
    """Map a raw CrowdStrike detection -> a Nodal Event (or None if it has no MAC and no IP)."""
    mac = norm_mac_colon(d.get("MACAddress"))
    ip = d.get("LocalIP", "")
    if not mac and not ip:
        return None
    tag = attack_type(d)
    eb = EventBuilder(internal_mac=mac, external_ip=(None if mac else ip), desc=tag)
    if ip:
        eb.event["device_ip"] = ip
    eb.set_identity(d.get("UserName") or "unknown", "CrowdStrike")
    eb.set_metadata(metadata(d, tag))
    return eb.get_data()


# ---- Falcon Event Streams firehose (blocking; runs in a thread -> queue) ----
def firehose_thread(q, stop, seen):
    """Hold the Falcon Event Streams firehose and put current detections on the queue. CrowdStrike
    replays a recent backlog on each (re)connect, so only detections newer than FEED_LOOKBACK_SECS are
    forwarded (plus CompositeId dedup)."""
    es = EventStreams(**FALCON)
    cutoff_ms = (time.time() - FEED_LOOKBACK_SECS) * 1000.0 if FEED_LOOKBACK_SECS > 0 else 0.0
    while not stop.is_set():
        try:
            avail = es.list_available_streams(app_id=FEEDER_APP_ID)
            if avail["status_code"] != 200 or not avail["body"].get("resources"):
                print(f"[feeder] no streams ({avail['status_code']}); retry 15s")
                stop.wait(15)
                continue
            s = avail["body"]["resources"][0]
            url, token = s["dataFeedURL"], s["sessionToken"]["token"]
            deadline = time.time() + (int(s.get("refreshActiveSessionInterval", 1800)) - 120)
            print(f"[feeder] firehose connected (lookback {FEED_LOOKBACK_SECS:.0f}s)")
            with requests.get(url, headers={"Authorization": f"Token {token}", "Connection": "Keep-Alive"},
                              stream=True, timeout=(10, 65)) as r:
                for line in r.iter_lines():
                    if stop.is_set() or time.time() > deadline:
                        break
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except Exception:
                        continue
                    meta = evt.get("metadata", {})
                    if meta.get("eventType") not in DETECTION_EVENT_TYPES:
                        continue
                    if cutoff_ms and float(meta.get("eventCreationTime", 0) or 0) < cutoff_ms:
                        continue  # stale backlog replay
                    d = evt.get("event", {})
                    cid = d.get("CompositeId") or d.get("DetectId") or f"{d.get('AgentId','')}|{d.get('SHA256String','')}"
                    if cid in seen:
                        continue
                    seen.add(cid)
                    q.put(d)
        except requests.exceptions.RequestException as e:
            print(f"[feeder] stream error, reconnecting: {e}")
            stop.wait(5)
        except Exception as e:
            print(f"[feeder] unexpected: {e}")
            stop.wait(5)


async def keepalive(feeder, interval=3.0):
    """The SDK never sends an unsolicited heartbeat, and a PUB feeder only emits on a detection — so an
    idle feeder looks dead to the brain and its worker churns, dropping detections published in the gap.
    A steady no-op 'ping' keeps the socket warm so every real detection is delivered. Keep interval well
    under the brain's ~9s heartbeat window."""
    while True:
        try:
            feeder.send("ping", {})
        except Exception:
            pass
        await asyncio.sleep(interval)


async def main():
    feeder = Feeder(FEEDER_NAME, FEEDER_PORT)
    await feeder.register(COMPONENT_IP, GHOST_HANDSHAKE_URL, FEEDER_TOKEN)
    print(f"[feeder] registered '{FEEDER_NAME}' -> Ghost {GHOST_HANDSHAKE_URL}")

    q = queue.Queue()
    stop = threading.Event()
    seen = set()
    threading.Thread(target=firehose_thread, args=(q, stop, seen), daemon=True).start()
    asyncio.create_task(keepalive(feeder))

    try:
        while True:
            while True:
                try:
                    d = q.get_nowait()
                except queue.Empty:
                    break
                event = build_event(d)
                if event:
                    feeder.send("event", event)
                    print(f"[feeder] -> Ghost event '{event['description']}'  device={event['device']}  "
                          f"sev={event['metadata'].get('severity','?')}")
            await asyncio.sleep(0.5)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        stop.set()
        print("[feeder] shutting down")


if __name__ == "__main__":
    asyncio.run(main())
