"""
Office 365 -> Nodal Cyberbrain feeder, on Microsoft Graph.

Polls the itemActivity feed of every watched OneDrive and SharePoint drive and
pushes what it finds into the Cyberbrain as feeder events.

The whole service is one loop:

    every POLL_INTERVAL_SECS, for each drive:
        GET /drives/{id}/activities -> keep what is newer than the cursor -> send

There is no webhook, no subscription to maintain, no inbound endpoint and no
seen-set. Each drive's cursor is a single timestamp - the newest
activityDateTime already fed - and an activity is fed when it is newer than
that. Re-reading the same page is therefore harmless, which is the whole reason
no set of seen ids is needed.

Why polling: reading a file does not change it, so a file access fires no Graph
change notification. Asking is the only way to see one, and reads are the
signal this feed exists for.

Moving parts:

  poll thread        sweeps every drive, sends what is new
  discovery thread   refreshes the drive list on a slow timer, so new users and
                     new sites get picked up
  asyncio main loop  keeps the SDK's ZAP authenticator alive for Brain

Run: python3 o365_feeder.py [--dry-run] [--replay activities.json] [--once]
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import yaml

from nodal_sdk import Feeder
from nodal_sdk.types import Event

from o365_events import DEFAULT_WEIGHTS, EventMapper
from o365_graph import GraphClient, GraphError

CONFIG_FILE = "o365_feeder.yaml"

# Stand-in device for every emitted event, when DEVICE_IP is not in the config.
DEFAULT_DEVICE_IP = "10.0.1.11"

CONFIG_TEMPLATE = """\
# ---- Nodal component ----
COMPONENT_NAME: "office365" # Component name configured in your ghost
COMPONENT_TOKEN: "" # Component token configured in your ghost
COMPONENT_IP: "127.0.0.1" # Addr where brain can reach this component
LISTEN_PORT: 4002  # Port for brain to connect to this component on
GHOST_URL: "http://localhost:8080/api/components/handshake" # usually https://<ghost fqdn>/api/components/handshake

# ---- Entra app registration ----
# Needs the Microsoft Graph *application* permissions Files.Read.All (or
# Sites.Read.All) and User.Read.All, with admin consent granted.
TENANT_ID: "" # Directory (tenant) ID
CLIENT_ID: "" # Application (client) ID
CLIENT_SECRET: "" # Client secret value

# ---- What to watch ----
# "*" means everything. On a large tenant that is a lot of drives to sweep every
# POLL_INTERVAL_SECS, so MAX_DRIVES is the brake - see the README on cost.
WATCH_USERS: # OneDrive: list of UPNs, or ["*"], or [] for none
  - "*"
WATCH_SITES: [] # SharePoint: list of site ids/paths, or ["*"], or [] for none
MAX_DRIVES: 200 # Ceiling on how many drives get polled

# ---- Device attribution ----
# Graph reports no client address for file activity, so there is no real device
# to key these events on - the actor's identity is the key that means anything.
# Brain needs a device regardless, so this address is attached to every emitted
# event. It is a placeholder, not an observation: all users' activity shares it.
# Point it at an address that is NOT a real host, or Brain may request a
# mitigation against whatever is really there. Required.
DEVICE_IP: "%(device_ip)s"

# ---- Polling ----
POLL_INTERVAL_SECS: 20 # How often every drive is swept
POLL_WORKERS: 8 # Drives swept in parallel; one sweep must finish inside one interval
MAX_ACTIVITY_PAGES: 2 # Cap on activity pages per drive per sweep
DISCOVER_INTERVAL_SECS: 3600 # How often the drive list is refreshed

# Per-event influence on Brain's case triggering, 0.0 - 1.0
WEIGHTS:
%(weights)s
"""

log = logging.getLogger("o365.feeder")


def load_config() -> Dict[str, Any]:
    if os.path.isfile(CONFIG_FILE):
        print("loading config from " + CONFIG_FILE, flush=True)
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f)

    with open(CONFIG_FILE, "w") as fout:
        fout.write(
            CONFIG_TEMPLATE
            % {
                "device_ip": DEFAULT_DEVICE_IP,
                "weights": "\n".join(f"  {k}: {v}" for k, v in DEFAULT_WEIGHTS.items()),
            }
        )
    print("wrote config file " + CONFIG_FILE + " in local dir, please edit it")
    sys.exit(1)


@dataclass
class Drive:
    """A polled drive and how far into its activity feed we have got."""

    drive_id: str
    label: str  # "OneDrive" or "SharePoint", used in event descriptions
    drive_type: str
    owner: str

    # The entire cursor: the newest activityDateTime already fed. An activity is
    # new when it is strictly newer than this, so re-reading the same page feeds
    # nothing and no set of seen ids is needed.
    #
    # Primed to discovery time, not zero: a drive joining the feed must not
    # replay its whole retained activity history into Brain.
    cursor: float = 0.0

    def as_metadata(self) -> Dict[str, str]:
        return {
            "drive_id": self.drive_id,
            "label": self.label,
            "drive_type": self.drive_type,
            "owner": self.owner,
        }


class O365Feed:
    def __init__(self, conf: Dict[str, Any], dry_run: bool = False):
        self.conf = conf
        self.dry_run = dry_run

        self.poll_interval = float(conf.get("POLL_INTERVAL_SECS") or 20)
        self.poll_workers = int(conf.get("POLL_WORKERS") or 8)
        self.max_pages = int(conf.get("MAX_ACTIVITY_PAGES") or 2)
        self.discover_interval = float(conf.get("DISCOVER_INTERVAL_SECS") or 3600)
        self.max_drives = int(conf.get("MAX_DRIVES") or 200)

        self.client = GraphClient(conf["TENANT_ID"], conf["CLIENT_ID"], conf["CLIENT_SECRET"])
        # A missing or malformed DEVICE_IP raises here, at startup, rather than
        # at the first event the feeder tries to emit.
        self.mapper = EventMapper(
            device_ip=conf.get("DEVICE_IP", DEFAULT_DEVICE_IP),
            weights=conf.get("WEIGHTS"),
            upn_resolver=self.client.user_upn,
        )
        log.info("events will be keyed on device %s", self.mapper.device)

        self.drives: Dict[str, Drive] = {}
        self.drives_lock = threading.Lock()

        self.feeder: Optional[Feeder] = None
        self.stop = threading.Event()
        self.stats = {"sweeps": 0, "activities": 0, "events": 0, "errors": 0}

    # ------------------------------------------------------------------- send

    def send(self, events: List[Event]) -> None:
        """
        Push events to Brain.

        Only ever called from the poll thread, which is why there is no lock
        here: the SDK's PUB socket is not thread safe, so the workers hand their
        events back rather than sending them.
        """
        for event in events:
            if self.feeder is None:
                log.info("event: %s", json.dumps(event))
            else:
                self.feeder.send("event", event)
        self.stats["events"] += len(events)

    # --------------------------------------------------------------- the work

    def poll_drive(self, drive: Drive) -> List[Event]:
        """Fetch one drive's new activity. Returns events; does not send them."""
        try:
            activities = self.client.activities(drive.drive_id, max_pages=self.max_pages)
        except GraphError as e:
            # a drive with no activity feed provisioned, a permission gap, or
            # throttling. The next sweep retries, and the cursor has not moved.
            log.warning("could not poll drive %s: %s", drive.drive_id, e)
            self.stats["errors"] += 1
            return []

        fresh = []
        newest = drive.cursor

        for activity in activities:
            when = self.mapper.when_of(activity)
            if when is None:
                continue
            stamp = when.timestamp()
            if stamp <= drive.cursor:
                continue
            fresh.append(activity)
            newest = max(newest, stamp)

        # advance only after the whole page has been read, so a mid-page failure
        # leaves the cursor where it was and the next sweep picks it all up
        drive.cursor = newest

        if not fresh:
            return []

        self.stats["activities"] += len(fresh)
        return self.mapper.map_activities(fresh, drive.as_metadata())

    def sweep(self) -> int:
        """One pass over every drive. Returns the event count."""
        with self.drives_lock:
            drives = list(self.drives.values())
        if not drives:
            return 0

        with ThreadPoolExecutor(max_workers=self.poll_workers) as pool:
            batches = list(pool.map(self.poll_drive, drives))

        events = [event for batch in batches for event in batch]
        self.send(events)
        self.stats["sweeps"] += 1
        return len(events)

    # -------------------------------------------------------------- discovery

    def discover(self) -> None:
        """
        Resolve the configured users and sites to drives.

        Runs on its own slow timer: "*" costs one Graph call per user, which has
        no business happening on the poll interval.
        """
        found: List[Drive] = []

        users = self.conf.get("WATCH_USERS") or []
        if users:
            for drive in self.client.user_drives(users, self.max_drives):
                found.append(
                    Drive(
                        drive_id=drive["id"],
                        label="OneDrive",
                        drive_type=str(drive.get("driveType", "")),
                        owner=str(drive.get("_owner_upn", "")),
                    )
                )

        sites = self.conf.get("WATCH_SITES") or []
        if sites and len(found) < self.max_drives:
            for drive in self.client.site_drives(sites, self.max_drives - len(found)):
                owner = str(
                    ((drive.get("owner") or {}).get("user") or {}).get("displayName")
                    or drive.get("name", "")
                )
                found.append(
                    Drive(
                        drive_id=drive["id"],
                        label="SharePoint",
                        drive_type=str(drive.get("driveType", "")),
                        owner=owner,
                    )
                )

        now = time.time()
        added = 0
        with self.drives_lock:
            for drive in found:
                if drive.drive_id in self.drives:
                    continue  # already watched, keep its cursor
                # start from now, so adopting a drive does not replay its history
                drive.cursor = now
                self.drives[drive.drive_id] = drive
                added += 1

            total = len(self.drives)

        if added:
            log.info("discovered %d new drive(s), watching %d", added, total)
        else:
            log.debug("no new drives, watching %d", total)

    # ---------------------------------------------------------------- threads

    def poll_worker(self) -> None:
        while not self.stop.is_set():
            started = time.time()
            try:
                fed = self.sweep()
                if fed:
                    log.info("sweep fed %d event(s)", fed)
            except Exception:
                log.exception("unexpected error in poll sweep")
                self.stats["errors"] += 1

            elapsed = time.time() - started
            if elapsed > self.poll_interval:
                # the sweep cannot keep up: too many drives for POLL_WORKERS, or
                # Graph is slow. Left as a warning rather than silently drifting.
                log.warning(
                    "sweep of %d drive(s) took %.1fs, longer than the %.0fs interval "
                    "- raise POLL_WORKERS or POLL_INTERVAL_SECS",
                    len(self.drives),
                    elapsed,
                    self.poll_interval,
                )
            self.stop.wait(max(0.0, self.poll_interval - elapsed))

    def discovery_worker(self) -> None:
        last = time.time()  # discover() already ran before this thread started
        while not self.stop.is_set():
            if time.time() - last >= self.discover_interval:
                last = time.time()
                try:
                    self.discover()
                except Exception:
                    log.exception("unexpected error in drive discovery")
            self.stop.wait(5.0)

    def start_threads(self) -> None:
        self.discover()
        threading.Thread(target=self.poll_worker, name="poll", daemon=True).start()
        threading.Thread(target=self.discovery_worker, name="discovery", daemon=True).start()


async def run(feed: O365Feed, dry_run: bool) -> None:
    conf = feed.conf

    if dry_run:
        log.warning("dry run: not registering with ghost, events will only be logged")
    else:
        feeder = Feeder(conf["COMPONENT_NAME"], conf["LISTEN_PORT"])
        await feeder.register(conf["COMPONENT_IP"], conf["GHOST_URL"], conf["COMPONENT_TOKEN"])
        feed.feeder = feeder
        log.info("registered feeder '%s' with ghost", conf["COMPONENT_NAME"])

    feed.start_threads()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, feed.stop.set)
        except NotImplementedError:
            pass

    # Sending happens on the poll thread, so this loop feeds nothing. It stays
    # running because the SDK's curve authenticator is an asyncio task on it -
    # without a live loop Brain cannot authenticate to the socket.
    last_report = time.time()
    while not feed.stop.is_set():
        await asyncio.sleep(0.5)
        if time.time() - last_report >= 60.0:
            last_report = time.time()
            log.info(
                "drives=%d sweeps=%d activities=%d events=%d errors=%d",
                len(feed.drives),
                feed.stats["sweeps"],
                feed.stats["activities"],
                feed.stats["events"],
                feed.stats["errors"],
            )

    log.info("shutting down")


def replay(feed: O365Feed, path: str) -> None:
    """Map a saved activities response to events - handy for testing without a tenant."""
    with open(path, "r") as f:
        body = json.load(f)

    records = body.get("value") if isinstance(body, dict) else body
    records = records or []

    drive = Drive(
        drive_id="replay-drive", label="OneDrive", drive_type="business", owner="replay"
    ).as_metadata()

    events = feed.mapper.map_activities(records, drive)
    for event in events:
        print(json.dumps(event, indent=2))
    print(f"\n{len(events)} event(s) from {len(records)} activity record(s)", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Office 365 Nodal feeder")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="poll for real but log events instead of sending them",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="discover, run a single sweep, print what it found and exit",
    )
    parser.add_argument(
        "--replay",
        metavar="FILE",
        help="map a JSON activities response to events and exit",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    )

    conf = load_config()
    feed = O365Feed(conf, dry_run=args.dry_run or args.once)

    if args.replay:
        replay(feed, args.replay)
        return

    if args.once:
        # Handy against a live tenant: it shows whether the activity feed returns
        # anything at all, which is the first thing to check on a new tenant.
        feed.discover()
        with feed.drives_lock:
            for drive in feed.drives.values():
                drive.cursor = 0.0  # this once, take whatever the feed retains
        fed = feed.sweep()
        print(f"\n{fed} event(s) from {len(feed.drives)} drive(s)", file=sys.stderr)
        return

    try:
        asyncio.run(run(feed, args.dry_run))
    except KeyboardInterrupt:
        pass
    except Exception as e:
        traceback.print_exception(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
