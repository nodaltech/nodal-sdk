"""
Office 365 -> Nodal Cyberbrain feeder, on Microsoft Graph change notifications.

A small Flask webserver (meant to sit behind nginx) that receives Graph change
notifications for OneDrive and SharePoint drives, fetches what changed, and
pushes it into the Cyberbrain as feeder events.

The whole service is one path:

    notification -> delta (what changed) -> map -> feeder.send -> 200

No queue, no seen-set. Each drive's delta link is the only cursor, and it is
what makes that path safe: Graph retries an undelivered notification for up to
four hours, and a retry after the cursor has advanced returns nothing to feed.

What this feed does NOT see: reads. A download does not change the file, so it
fires no notification and appears in no delta. Downloads live only in the
unified audit log, via the Management Activity API, ~30 minutes behind.

Moving parts:

  webserver thread     answers Graph's validationToken handshake, then does the
                       real work inline and returns 200
  subscription thread  creates and renews subscriptions, so an expired or
                       dropped subscription repairs itself
  asyncio main loop    keeps the SDK's ZAP authenticator alive for Brain

Run: python3 o365_feeder.py [--dry-run] [--replay changes.json]
"""

import argparse
import asyncio
import hmac
import json
import logging
import os
import signal
import sys
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml
from flask import Flask, Response, jsonify, request

from nodal_sdk import Feeder
from nodal_sdk.types import Event

from o365_events import DEFAULT_WEIGHTS, EventMapper
from o365_graph import GraphClient, GraphError, parse_ts

CONFIG_FILE = "o365_feeder.yaml"

# Stand-in device for every emitted event, when DEVICE_IP is not in the config.
DEFAULT_DEVICE_IP = "10.0.1.11"

# Subscription lifetime and upkeep. driveItem allows up to 42,300 minutes; three
# days is plenty given the maintenance pass renews a day out. Not configurable -
# there is no reason to tune it.
SUBSCRIPTION_MINUTES = 4230
RENEW_MARGIN_SECS = 24 * 3600
MAINTAIN_INTERVAL_SECS = 300

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

# ---- Notification receiver ----
# NOTIFICATION_URL is the public HTTPS address nginx exposes. Graph POSTs there
# and requires a valid, publicly trusted certificate - self signed will not do.
NOTIFICATION_URL: "https://o365-feed.example.com/webhook/o365"
WEBHOOK_PATH: "/webhook/o365" # Local path nginx proxies to
WEBHOOK_HOST: "127.0.0.1" # Bind address, keep on loopback behind nginx
WEBHOOK_PORT: 8099 # Bind port nginx proxies to
CLIENT_STATE: "%(client_state)s" # Shared secret Graph echoes back on every notification

# ---- What to watch ----
# One subscription per drive. "*" means everything, which on a large tenant is a
# lot of subscriptions - MAX_DRIVES is the brake.
WATCH_USERS: # OneDrive: list of UPNs, or ["*"], or [] for none
  - "*"
WATCH_SITES: [] # SharePoint: list of site ids/paths, or ["*"], or [] for none
MAX_DRIVES: 200 # Ceiling on how many drives get subscribed

# ---- Device attribution ----
# Graph reports no client address for file activity, so there is no real device
# to key these events on - the actor's identity is the key that means anything.
# Brain needs a device regardless, so this address is attached to every emitted
# event. It is a placeholder, not an observation: all users' activity shares it.
# Point it at an address that is NOT a real host, or Brain may request a
# mitigation against whatever is really there. Required.
DEVICE_IP: "%(device_ip)s"

# ---- Feed behaviour ----
MAX_PAGES: 3 # Cap on delta pages fetched per notification, to bound latency

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
                "client_state": str(uuid.uuid4()),
                "device_ip": DEFAULT_DEVICE_IP,
                "weights": "\n".join(f"  {k}: {v}" for k, v in DEFAULT_WEIGHTS.items()),
            }
        )
    print("wrote config file " + CONFIG_FILE + " in local dir, please edit it")
    sys.exit(1)


@dataclass
class Drive:
    """A watched drive, its subscription, and its place in the change stream."""

    drive_id: str
    label: str  # "OneDrive" or "SharePoint", used in event descriptions
    drive_type: str
    owner: str

    subscription_id: str = ""
    expires: float = 0.0

    # the only cursor this service keeps
    delta_link: str = ""

    # Held while a drive is processed, so two notifications for the same drive -
    # which Graph will happily deliver at once - cannot both advance the cursor
    # and double-feed the same changes.
    lock: threading.Lock = field(default_factory=threading.Lock)

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

        self.notification_url: str = conf["NOTIFICATION_URL"]
        self.webhook_path: str = conf.get("WEBHOOK_PATH") or "/webhook/o365"
        self.client_state: str = str(conf.get("CLIENT_STATE") or "")
        self.max_pages = int(conf.get("MAX_PAGES") or 3)
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

        self.drives: Dict[str, Drive] = {}  # drive id -> Drive
        self.by_subscription: Dict[str, Drive] = {}  # subscription id -> Drive
        self.registry_lock = threading.Lock()

        self.feeder: Optional[Feeder] = None
        # The SDK's PUB socket is not thread safe and the webserver threads are
        # what send, so all sends are serialised here.
        self.send_lock = threading.Lock()

        self.stop = threading.Event()
        self.stats = {"notifications": 0, "changes": 0, "events": 0}

    # ------------------------------------------------------------------- send

    def send(self, events: List[Event]) -> None:
        if not events:
            return
        self.stats["events"] += len(events)
        with self.send_lock:
            for event in events:
                if self.feeder is None:
                    log.info("event: %s", json.dumps(event))
                else:
                    print("EVENT: " + str(event))
                    dummy = {'event_id': '557a3473-6f9b-4c9c-b865-69341391db45', 'device': {'Internal': '00:94:a2:7d:0f:a3'}, 'description': 'Using invalid cert', 'ts': 1789157427.0292294, 'metadata': {'danger': 'lowkey'}, 'peer_ip': '192.168.1.12', 'identity': {'name': 'nathan', 'source': 'hubspot'}, 'hash': 10764745265420991227}
                    print("DUMMY: " + str(dummy))
                    self.feeder.send("event", event)
                    self.feeder.send("event", dummy)

    # --------------------------------------------------------------- the work

    def process_drive(self, drive: Drive) -> int:
        """Fetch what changed in one drive and push it to Brain."""
        with drive.lock:
            items, drive.delta_link = self.client.delta(
                drive.drive_id, drive.delta_link, max_pages=self.max_pages
            )
            if not items:
                return 0

            self.stats["changes"] += len(items)
            events = self.mapper.map_items(items, drive.as_metadata())
            self.send(events)
            return len(events)

    def authorized(self, notification: Dict[str, Any]) -> bool:
        """
        Graph echoes the clientState recorded at subscription time on every
        notification. It is the only thing distinguishing a real notification
        from anything else that finds the endpoint, since Microsoft publishes no
        stable source range for these.
        """
        if not self.client_state:
            return True
        return hmac.compare_digest(
            str(notification.get("clientState") or "").encode("utf-8"),
            self.client_state.encode("utf-8"),
        )

    def handle_notifications(self, payload: Any) -> int:
        """Process one notification batch. Returns how many events were fed."""
        notifications = None
        if isinstance(payload, dict) and "value" in payload:
            notifications = payload.get("value")
        elif isinstance(payload, list):
            notifications = payload

        self.stats["notifications"] += len(notifications)

        # A batch routinely carries several notifications for the same drive.
        # Collapsing them means one delta call, not five identical ones.
        drives: Dict[str, Drive] = {}
        for notification in notifications:
            if not isinstance(notification, dict):
                continue
            if not self.authorized(notification):
                log.warning(
                    "rejected notification for subscription %s: bad clientState",
                    notification.get("subscriptionId"),
                )
                continue

            sub_id = str(notification.get("subscriptionId") or "")
            with self.registry_lock:
                drive = self.by_subscription.get(sub_id)
            if drive is None:
                log.warning("notification for unknown subscription %s", sub_id)
                continue
            drives[drive.drive_id] = drive

        fed = 0
        for drive in drives.values():
            # Raising here returns 503, which makes Graph redeliver. The cursor
            # has not moved, so nothing is lost by asking for that.
            fed += self.process_drive(drive)
        return fed

    # -------------------------------------------------------------- webserver

    def flask_app(self) -> Flask:
        app = Flask("o365-feeder")
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

        @app.route(self.webhook_path, methods=["POST"])
        def notifications():
            # Graph validates an endpoint by POSTing a validationToken and
            # wanting it back as plain text, within 10 seconds, during the
            # subscription create call. An encoded or JSON-wrapped body fails.
            token = request.args.get("validationToken")
            if token is not None:
                log.info("answered graph endpoint validation handshake")
                return Response(token, status=200, mimetype="text/plain")

            payload = request.get_json(force=True, silent=True)
            if payload is None:
                return jsonify({"error": "expected json"}), 400

            try:
                fed = self.handle_notifications(payload)
            except GraphError as e:
                # 5xx asks Graph to retry; the cursors have not advanced
                log.error("graph fetch failed handling notification: %s", e)
                return jsonify({"error": "graph fetch failed"}), 503
            except Exception:
                log.exception("unexpected error handling notification")
                return jsonify({"error": "internal error"}), 500

            if fed:
                log.info("notification fed %d event(s)", fed)
            return jsonify({}), 200

        return app

    def serve_forever(self) -> None:
        app = self.flask_app()
        host = self.conf.get("WEBHOOK_HOST") or "127.0.0.1"
        port = int(self.conf.get("WEBHOOK_PORT") or 8099)

        try:
            from waitress import serve

            log.info("webhook listening on http://%s:%d%s (waitress)", host, port, self.webhook_path)
            serve(app, host=host, port=port, threads=8, clear_untrusted_proxy_headers=True)
        except ImportError:
            log.warning("waitress not installed, falling back to the flask dev server")
            log.info("webhook listening on http://%s:%d%s", host, port, self.webhook_path)
            app.run(host=host, port=port, threaded=True)

    # ----------------------------------------------------------- maintenance

    def discover(self) -> None:
        """Resolve the configured users and sites to drives, once at startup."""
        found: List[Drive] = []

        users = self.conf.get("WATCH_USERS") or []
        if users:
            found += [
                Drive(d["id"], "OneDrive", str(d.get("driveType", "")), str(d.get("_owner", "")))
                for d in self.client.user_drives(users, self.max_drives)
            ]

        sites = self.conf.get("WATCH_SITES") or []
        if sites and len(found) < self.max_drives:
            found += [
                Drive(d["id"], "SharePoint", str(d.get("driveType", "")), str(d.get("_owner", "")))
                for d in self.client.site_drives(sites, self.max_drives - len(found))
            ]

        for drive in found:
            self.drives.setdefault(drive.drive_id, drive)

        log.info("watching %d drive(s)", len(self.drives))

    def maintain(self) -> None:
        """Bring every watched drive to "subscribed, not close to expiry"."""
        for drive in self.drives.values():
            if self.stop.is_set():
                return
            if drive.subscription_id and drive.expires - time.time() > RENEW_MARGIN_SECS:
                continue

            if drive.subscription_id:
                try:
                    sub = self.client.renew_subscription(drive.subscription_id, SUBSCRIPTION_MINUTES)
                    drive.expires = self._expiry_of(sub)
                    log.info("renewed subscription for drive %s", drive.drive_id)
                    continue
                except GraphError as e:
                    log.warning(
                        "could not renew subscription for drive %s (%s), recreating",
                        drive.drive_id,
                        e,
                    )
                    with self.registry_lock:
                        self.by_subscription.pop(drive.subscription_id, None)
                    drive.subscription_id = ""

            try:
                sub = self.client.create_subscription(
                    drive.drive_id,
                    self.notification_url,
                    self.client_state,
                    SUBSCRIPTION_MINUTES,
                )
            except GraphError as e:
                # one drive failing is no reason to leave the rest unsubscribed
                log.error("subscription for drive %s failed: %s", drive.drive_id, e)
                continue

            drive.subscription_id = str(sub.get("id") or "")
            drive.expires = self._expiry_of(sub)
            with self.registry_lock:
                self.by_subscription[drive.subscription_id] = drive

            # Start from "now". Without this the drive's first delta enumerates
            # its whole existing hierarchy, and every file anyone has ever put
            # there arrives as a freshly created event.
            if not drive.delta_link:
                try:
                    drive.delta_link = self.client.delta_latest(drive.drive_id)
                except GraphError as e:
                    log.warning("could not prime delta for drive %s: %s", drive.drive_id, e)

            log.info("subscribed drive %s (%s)", drive.drive_id, drive.owner or drive.label)

    @staticmethod
    def _expiry_of(sub: Dict[str, Any]) -> float:
        when = parse_ts(sub.get("expirationDateTime"))
        return when.timestamp() if when else time.time() + SUBSCRIPTION_MINUTES * 60

    def maintenance_worker(self) -> None:
        last = 0.0
        while not self.stop.is_set():
            if time.time() - last >= MAINTAIN_INTERVAL_SECS:
                last = time.time()
                try:
                    self.maintain()
                except Exception:
                    log.exception("unexpected error in subscription maintenance")
            self.stop.wait(5.0)

    def start_threads(self) -> None:
        threading.Thread(target=self.serve_forever, name="webserver", daemon=True).start()

        # the webserver has to be up before any subscription is created, or
        # Graph's validation POST has nowhere to land
        time.sleep(1.0)

        self.discover()

        # A restart inside a subscription's lifetime would otherwise leave the
        # old subscriptions live and get every change notified twice.
        try:
            dropped = self.client.delete_our_subscriptions(self.notification_url)
            if dropped:
                log.info("deleted %d subscription(s) from a previous run", dropped)
        except GraphError as e:
            log.warning("could not clear previous subscriptions: %s", e)

        threading.Thread(
            target=self.maintenance_worker, name="subscriptions", daemon=True
        ).start()


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

    # Sending happens on the webserver threads, so this loop feeds nothing. It
    # stays running because the SDK's curve authenticator is an asyncio task on
    # it - without a live loop Brain cannot authenticate to the socket.
    last_report = time.time()
    while not feed.stop.is_set():
        await asyncio.sleep(0.5)
        if time.time() - last_report >= 60.0:
            last_report = time.time()
            with feed.registry_lock:
                subscribed = len(feed.by_subscription)
            log.info(
                "drives=%d subscribed=%d notifications=%d changes=%d events=%d",
                len(feed.drives),
                subscribed,
                feed.stats["notifications"],
                feed.stats["changes"],
                feed.stats["events"],
            )

    log.info("shutting down")


def replay(feed: O365Feed, path: str) -> None:
    """Map a saved delta response to events - handy for testing without a tenant."""
    with open(path, "r") as f:
        body = json.load(f)

    items = body.get("value") if isinstance(body, dict) else body
    drive = Drive("replay-drive", "OneDrive", "business", "replay").as_metadata()

    events = feed.mapper.map_items(items or [], drive)
    for event in events:
        print(json.dumps(event, indent=2))
    print(f"\n{len(events)} event(s) from {len(items or [])} changed item(s)", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Office 365 Nodal feeder")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="run the webhook and subscriptions but log events instead of sending them",
    )
    parser.add_argument(
        "--replay", metavar="FILE", help="map a JSON delta response to events and exit"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    )

    conf = load_config()
    feed = O365Feed(conf, dry_run=args.dry_run)

    if args.replay:
        replay(feed, args.replay)
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
