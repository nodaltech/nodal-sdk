"""
Office 365 -> Nodal Cyberbrain feeder.

A small Flask webserver (meant to sit behind nginx) that receives Office 365
Management Activity API webhook notifications, pulls the referenced audit
records, and pushes them into the Cyberbrain as feeder events.

Event sources: Entra ID sign-ins and OneDrive file downloads.

Moving parts:

  webserver thread     answers Microsoft's validation handshake and queues
                       incoming notifications (must reply within 5 seconds, so
                       it does no work of its own)
  content workers      fetch each content blob, map audit records to events
  subscription thread  (re)starts subscriptions as needed, so a dropped or
                       disabled webhook repairs itself
  asyncio main loop    owns the ZMQ socket and sends events to Brain

Run: python3 o365_feeder.py [--dry-run] [--replay records.json]
"""

import argparse
import asyncio
import hmac
import json
import logging
import os
import queue
import signal
import sys
import threading
import time
import traceback
import uuid
from typing import Any, Dict, List, Optional

import yaml
from flask import Flask, jsonify, request

from nodal_sdk import Feeder
from nodal_sdk.types import Event

from o365_events import DEFAULT_INTERNAL_CIDRS, DEFAULT_WEIGHTS, EventMapper
from o365_mgmt import Office365Error, Office365ManagementClient

CONFIG_FILE = "o365_feeder.yaml"

# how many times a content blob is retried before it is given up on
MAX_BLOB_ATTEMPTS = 3

# where the subscription's authId shows up on an incoming notification; the
# service uses the first, the second is only there for proxies that rewrite it
AUTH_HEADERS = ("Webhook-AuthID", "Authorization")

CONFIG_TEMPLATE = """\
# ---- Nodal component ----
COMPONENT_NAME: "office365" # Component name configured in your ghost
COMPONENT_TOKEN: "" # Component token configured in your ghost
COMPONENT_IP: "127.0.0.1" # Addr where brain can reach this component
LISTEN_PORT: 4002  # Port for brain to connect to this component on
GHOST_URL: "http://localhost:8080/api/components/handshake" # usually https://<ghost fqdn>/api/components/handshake

# ---- Entra app registration ----
# Needs the Office 365 Management APIs application permission ActivityFeed.Read,
# with admin consent granted.
TENANT_ID: "" # Directory (tenant) ID
CLIENT_ID: "" # Application (client) ID
CLIENT_SECRET: "" # Client secret value

# ---- Webhook receiver ----
# WEBHOOK_URL is the public HTTPS address nginx exposes; Microsoft will POST
# there and requires a valid, publicly trusted certificate.
WEBHOOK_URL: "https://o365-feed.example.com/webhook/o365"
WEBHOOK_PATH: "/webhook/o365" # Local path nginx proxies to
WEBHOOK_HOST: "127.0.0.1" # Bind address, keep on loopback behind nginx
WEBHOOK_PORT: 8099 # Bind port nginx proxies to
WEBHOOK_AUTH_ID: "%(auth_id)s" # Shared secret Microsoft echoes back in Webhook-AuthID
REQUIRE_AUTH_ID: true # Reject notifications whose Webhook-AuthID does not match

# ---- Feed behaviour ----
CONTENT_TYPES: # Audit.AzureActiveDirectory -> logins, Audit.SharePoint -> downloads
  - "Audit.AzureActiveDirectory"
  - "Audit.SharePoint"
ONEDRIVE_ONLY: true # Ignore download events from SharePoint sites (keep OneDrive only)
SUBSCRIBE_INTERVAL_SECS: 300 # How often to check/repair subscriptions
CONTENT_WORKERS: 2 # Threads fetching content blobs

# Any IP outside these ranges is treated as External; addresses inside them are
# treated as RoutedInternal (internal, but no MAC is knowable from a cloud log).
INTERNAL_CIDRS:
%(cidrs)s

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
                "auth_id": str(uuid.uuid4()),
                "cidrs": "\n".join(f'  - "{c}"' for c in DEFAULT_INTERNAL_CIDRS),
                "weights": "\n".join(f"  {k}: {v}" for k, v in DEFAULT_WEIGHTS.items()),
            }
        )
    print("wrote config file " + CONFIG_FILE + " in local dir, please edit it")
    sys.exit(1)


class TtlSet:
    """Seen-set with expiry, used to keep duplicate deliveries out of the feed."""

    def __init__(self, ttl: float, max_size: int = 500000):
        self.ttl = ttl
        self.max_size = max_size
        self._expiry: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._last_prune = 0.0

    def add_if_new(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            if now - self._last_prune > 60.0:
                self._prune(now)
            if self._expiry.get(key, 0.0) > now:
                return False
            self._expiry[key] = now + self.ttl
            return True

    def discard(self, key: str) -> None:
        with self._lock:
            self._expiry.pop(key, None)

    def _prune(self, now: float) -> None:
        self._last_prune = now
        self._expiry = {k: v for k, v in self._expiry.items() if v > now}
        if len(self._expiry) > self.max_size:
            # keep the newest entries, drop the rest
            newest = sorted(self._expiry.items(), key=lambda kv: kv[1], reverse=True)
            self._expiry = dict(newest[: self.max_size])


class O365Feed:
    """Everything that runs off the asyncio loop: webhook intake and content pulls."""

    def __init__(self, conf: Dict[str, Any], dry_run: bool = False):
        self.conf = conf
        self.dry_run = dry_run

        self.content_types: List[str] = list(
            conf.get("CONTENT_TYPES") or ["Audit.AzureActiveDirectory", "Audit.SharePoint"]
        )
        self.webhook_url: str = conf["WEBHOOK_URL"]
        self.webhook_path: str = conf.get("WEBHOOK_PATH") or "/webhook/o365"
        self.auth_id: str = str(conf.get("WEBHOOK_AUTH_ID") or "")
        self.require_auth_id: bool = bool(conf.get("REQUIRE_AUTH_ID", True))

        self.client = Office365ManagementClient(
            conf["TENANT_ID"], conf["CLIENT_ID"], conf["CLIENT_SECRET"]
        )
        self.mapper = EventMapper(
            internal_cidrs=conf.get("INTERNAL_CIDRS"),
            weights=conf.get("WEIGHTS"),
            onedrive_only=bool(conf.get("ONEDRIVE_ONLY", True)),
        )

        # blobs waiting to be fetched, events waiting to go to Brain
        self.blobs: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=10000)
        self.events: "queue.Queue[Event]" = queue.Queue(maxsize=50000)

        self.seen_blobs = TtlSet(ttl=8 * 3600)
        self.seen_records = TtlSet(ttl=24 * 3600)

        self.stop = threading.Event()
        self.stats = {"notifications": 0, "blobs": 0, "records": 0, "events": 0, "sent": 0}
        self._stats_lock = threading.Lock()

    # ------------------------------------------------------------------ stats

    def bump(self, key: str, amount: int = 1) -> None:
        with self._stats_lock:
            self.stats[key] += amount

    # ---------------------------------------------------------------- ingress

    def authorized(self, headers: Any) -> bool:
        """
        Microsoft identifies itself with the authId recorded at subscription
        start. It travels in the Webhook-AuthID header, on the validation POST
        and on every notification - not in Authorization, which the service
        never sets. Authorization is still accepted, for proxies or test rigs
        that move the value there.
        """
        if not self.require_auth_id or not self.auth_id:
            return True

        for name in AUTH_HEADERS:
            supplied = (headers.get(name) or "").strip()
            if supplied.lower().startswith("bearer "):
                supplied = supplied[7:].strip()
            if supplied and hmac.compare_digest(
                supplied.encode("utf-8"), self.auth_id.encode("utf-8")
            ):
                return True
        return False

    def queue_notification(self, payload: Any) -> int:
        """Queue the blobs referenced by one notification body. Returns how many."""
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            log.warning("ignoring notification with unexpected shape %s", type(payload))
            return 0

        queued = 0
        for blob in payload:
            if not isinstance(blob, dict) or not blob.get("contentUri"):
                continue
            content_id = str(blob.get("contentId") or blob["contentUri"])
            if not self.seen_blobs.add_if_new(content_id):
                continue
            try:
                self.blobs.put_nowait(blob)
                queued += 1
            except queue.Full:
                log.error("blob queue full, dropping notification for %s", content_id)
                self.seen_blobs.discard(content_id)
        self.bump("notifications")
        return queued

    def flask_app(self) -> Flask:
        app = Flask("o365-feeder")
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

        @app.route(self.webhook_path, methods=["POST"])
        def webhook():
            if not self.authorized(request.headers):
                seen = [h for h in AUTH_HEADERS if h in request.headers]
                log.warning(
                    "rejected notification with bad auth id (auth headers present: %s)",
                    ", ".join(seen) or "none",
                )
                return jsonify({"error": "unauthorized"}), 401

            payload = request.get_json(force=True, silent=True)

            # Subscription handshake: Microsoft POSTs a validation code, both as
            # the Webhook-ValidationCode header and in the body, when a webhook
            # is (re)started. It only wants a 200, within 5 seconds.
            code = request.headers.get("Webhook-ValidationCode")
            if code is None and isinstance(payload, dict):
                code = payload.get("validationCode")
            if code is not None:
                log.info("answered webhook validation handshake")
                return jsonify({"validationCode": code}), 200

            if payload is None:
                return jsonify({"error": "expected json"}), 400

            queued = self.queue_notification(payload)
            log.debug("notification queued %d blob(s)", queued)
            return jsonify({}), 200

        @app.route("/healthz", methods=["GET"])
        def healthz():
            with self._stats_lock:
                stats = dict(self.stats)
            return (
                jsonify(
                    {
                        "status": "ok",
                        "blob_queue": self.blobs.qsize(),
                        "event_queue": self.events.qsize(),
                        "stats": stats,
                    }
                ),
                200,
            )

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

    # ---------------------------------------------------------------- workers

    def content_worker(self) -> None:
        while not self.stop.is_set():
            try:
                blob = self.blobs.get(timeout=1.0)
            except queue.Empty:
                continue

            content_id = str(blob.get("contentId") or blob.get("contentUri") or "")
            try:
                records = self.client.fetch_content(blob["contentUri"])
            except Exception as e:
                if isinstance(e, Office365Error):
                    log.error("could not fetch content %s: %s", content_id, e)
                else:
                    log.exception("unexpected error fetching %s", content_id)
                self.retry_blob(blob, content_id)
                continue

            self.bump("blobs")
            self.bump("records", len(records))

            fresh = []
            for record in records:
                record_id = str(record.get("Id") or "")
                # Microsoft redelivers notifications, so the same blob can arrive twice
                if record_id and not self.seen_records.add_if_new(record_id):
                    continue
                fresh.append(record)

            for event in self.mapper.map_records(fresh):
                try:
                    self.events.put_nowait(event)
                    self.bump("events")
                except queue.Full:
                    log.error("event queue full, dropping event %s", event.get("event_id"))

    def retry_blob(self, blob: Dict[str, Any], content_id: str) -> None:
        """
        Put a blob we failed to fetch back in line, and give up once it is out of
        tries. Nothing re-reads it later by design: this feed is live only, so a
        blob that cannot be fetched now is dropped rather than arriving late.
        """
        attempts = int(blob.get("_attempts", 0)) + 1
        blob["_attempts"] = attempts

        if attempts < MAX_BLOB_ATTEMPTS:
            self.stop.wait(min(2.0 ** attempts, 15.0))
            try:
                self.blobs.put_nowait(blob)
                return
            except queue.Full:
                log.error("blob queue full, cannot retry %s", content_id)

        log.error(
            "giving up on content %s after %d attempt(s), its records are dropped",
            content_id,
            attempts,
        )
        # forget it, so a redelivery of the same notification is still accepted
        self.seen_blobs.discard(content_id)

    def subscription_worker(self) -> None:
        """Keep subscriptions alive - Microsoft disables webhooks that misbehave."""
        interval = float(self.conf.get("SUBSCRIBE_INTERVAL_SECS") or 300)
        last_check = 0.0

        while not self.stop.is_set():
            if time.time() - last_check >= interval:
                last_check = time.time()
                try:
                    self.client.ensure_subscriptions(
                        self.content_types, self.webhook_url, self.auth_id
                    )
                except Office365Error as e:
                    log.error("subscription check failed: %s", e)
                except Exception:
                    log.exception("unexpected error checking subscriptions")

            self.stop.wait(5.0)

    def start_threads(self) -> None:
        threading.Thread(target=self.serve_forever, name="webserver", daemon=True).start()

        for i in range(int(self.conf.get("CONTENT_WORKERS") or 2)):
            threading.Thread(
                target=self.content_worker, name=f"content-{i}", daemon=True
            ).start()

        # the webserver has to be up before subscriptions are started, otherwise
        # Microsoft's validation POST has nowhere to land
        time.sleep(1.0)
        threading.Thread(
            target=self.subscription_worker, name="subscriptions", daemon=True
        ).start()


async def run(feed: O365Feed, dry_run: bool) -> None:
    conf = feed.conf
    feeder: Optional[Feeder] = None

    if dry_run:
        log.warning("dry run: not registering with ghost, events will only be logged")
    else:
        feeder = Feeder(conf["COMPONENT_NAME"], conf["LISTEN_PORT"])
        await feeder.register(conf["COMPONENT_IP"], conf["GHOST_URL"], conf["COMPONENT_TOKEN"])
        log.info("registered feeder '%s' with ghost", conf["COMPONENT_NAME"])

    feed.start_threads()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, feed.stop.set)
        except NotImplementedError:
            pass

    last_report = time.time()

    while not feed.stop.is_set():
        drained = 0
        while drained < 500:
            try:
                event = feed.events.get_nowait()
            except queue.Empty:
                break

            drained += 1
            if feeder is None:
                log.info("event: %s", json.dumps(event))
            else:
                feeder.send("event", event)
                feed.bump("sent")

        if time.time() - last_report >= 60.0:
            last_report = time.time()
            with feed._stats_lock:
                log.info(
                    "notifications=%(notifications)d blobs=%(blobs)d records=%(records)d "
                    "events=%(events)d sent=%(sent)d" % feed.stats
                )

        if drained == 0:
            await asyncio.sleep(0.5)

    log.info("shutting down")


def replay(feed: O365Feed, path: str) -> None:
    """Map a saved audit-record dump to events - handy for testing without a tenant."""
    with open(path, "r") as f:
        records = json.load(f)
    if isinstance(records, dict):
        records = records.get("records") or [records]

    events = feed.mapper.map_records(records)
    for event in events:
        print(json.dumps(event, indent=2))
    print(f"\n{len(events)} event(s) from {len(records)} record(s)", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Office 365 Nodal feeder")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="run the webhook and subscriptions but log events instead of sending them",
    )
    parser.add_argument(
        "--replay",
        metavar="FILE",
        help="map a JSON file of audit records to events and exit",
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
