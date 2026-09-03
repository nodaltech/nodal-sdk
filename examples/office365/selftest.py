"""
Offline end-to-end check for the Office 365 feeder.

Stands up a fake Management Activity API on loopback, points the feeder at it,
and walks the whole path: token -> subscription start -> webhook validation
handshake -> notification -> content fetch -> Nodal events. No tenant, no ghost
and no network access needed, so it is a reasonable smoke test to run on a box
before pointing the real thing at a live tenant.

    python3 selftest.py
"""

import json
import logging
import queue
import sys
import threading
import time

from flask import Flask, jsonify, request

import o365_feeder
import o365_mgmt

TENANT = "selftest-tenant"
AUTH_ID = "selftest-shared-secret"
FAKE_PORT = 8098
WEBHOOK_PORT = 8099
WEBHOOK_PATH = "/webhook/o365"
WEBHOOK_URL = f"http://127.0.0.1:{WEBHOOK_PORT}{WEBHOOK_PATH}"
CONTENT_TYPES = ["Audit.AzureActiveDirectory", "Audit.SharePoint"]

log = logging.getLogger("o365.selftest")


class FakeManagementApi:
    """Just enough of manage.office.com to exercise the client."""

    def __init__(self, records):
        self.records = records
        self.subscriptions = {}
        self.validations = []
        self.tokens_issued = 0
        self.app = self._build()

    def _build(self) -> Flask:
        app = Flask("fake-o365")
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        feed = f"/api/v1.0/{TENANT}/activity/feed"

        @app.route(f"/{TENANT}/oauth2/v2.0/token", methods=["POST"])
        def token():
            self.tokens_issued += 1
            return jsonify({"access_token": "fake-token", "expires_in": 3600})

        @app.route(f"{feed}/subscriptions/list", methods=["GET"])
        def list_subs():
            return jsonify(list(self.subscriptions.values()))

        @app.route(f"{feed}/subscriptions/start", methods=["POST"])
        def start_sub():
            content_type = request.args.get("contentType")
            webhook = (request.get_json(silent=True) or {}).get("webhook")

            if webhook:
                # Microsoft validates the webhook inline, during this call
                import requests as rq

                resp = rq.post(
                    webhook["address"],
                    json={"validationCode": "abc-123"},
                    headers={"Authorization": webhook.get("authId", "")},
                    timeout=5,
                )
                self.validations.append((content_type, resp.status_code, resp.text.strip()))
                if resp.status_code != 200:
                    return jsonify({"error": "webhook validation failed"}), 400

            self.subscriptions[content_type] = {
                "contentType": content_type,
                "status": "enabled",
                "webhook": dict(webhook or {}, status="enabled"),
            }
            return jsonify(self.subscriptions[content_type])

        @app.route(f"{feed}/subscriptions/stop", methods=["POST"])
        def stop_sub():
            self.subscriptions.pop(request.args.get("contentType"), None)
            return jsonify({})

        @app.route(f"{feed}/audit/<blob_id>", methods=["GET"])
        def audit(blob_id):
            return jsonify(self.records)

        return app

    def serve(self) -> None:
        from waitress import serve

        serve(self.app, host="127.0.0.1", port=FAKE_PORT, threads=4)


def drain(events: "queue.Queue", timeout: float) -> list:
    """Collect whatever shows up on the event queue within `timeout`."""
    collected = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            collected.append(events.get(timeout=0.25))
        except queue.Empty:
            continue
    return collected


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s %(message)s"
    )

    with open("samples/audit_records.json") as f:
        records = json.load(f)

    fake = FakeManagementApi(records)
    threading.Thread(target=fake.serve, name="fake-api", daemon=True).start()

    # redirect the client at the fake tenant endpoints
    o365_mgmt.RESOURCE = f"http://127.0.0.1:{FAKE_PORT}"
    o365_mgmt.LOGIN_URL = f"http://127.0.0.1:{FAKE_PORT}/{{tenant}}/oauth2/v2.0/token"

    conf = {
        "COMPONENT_NAME": "office365-selftest",
        "COMPONENT_TOKEN": "unused",
        "COMPONENT_IP": "127.0.0.1",
        "LISTEN_PORT": 4002,
        "GHOST_URL": "http://127.0.0.1:8080/api/components/handshake",
        "TENANT_ID": TENANT,
        "CLIENT_ID": "client",
        "CLIENT_SECRET": "secret",
        "WEBHOOK_URL": WEBHOOK_URL,
        "WEBHOOK_PATH": WEBHOOK_PATH,
        "WEBHOOK_HOST": "127.0.0.1",
        "WEBHOOK_PORT": WEBHOOK_PORT,
        "WEBHOOK_AUTH_ID": AUTH_ID,
        "REQUIRE_AUTH_ID": True,
        "CONTENT_TYPES": CONTENT_TYPES,
        "ONEDRIVE_ONLY": True,
        "SUBSCRIBE_INTERVAL_SECS": 300,
        "CONTENT_WORKERS": 2,
    }

    feed = o365_feeder.O365Feed(conf, dry_run=True)
    feed.start_threads()
    time.sleep(3.0)  # let the maintenance pass start both subscriptions

    failures = []

    def check(name, ok, detail=""):
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{(' - ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    print("\nsubscriptions")
    check(
        "both content types subscribed",
        sorted(fake.subscriptions) == sorted(CONTENT_TYPES),
        str(sorted(fake.subscriptions)),
    )
    check("validation handshake answered 200", all(v[1] == 200 for v in fake.validations))
    check(
        "validation echoed the code",
        all("abc-123" in v[2] for v in fake.validations),
        fake.validations[0][2] if fake.validations else "no validations",
    )

    print("\nwebhook auth")
    import requests as rq

    notification = [
        {
            "contentType": "Audit.SharePoint",
            "contentId": "notif-1",
            "contentUri": f"http://127.0.0.1:{FAKE_PORT}/api/v1.0/{TENANT}/activity/feed/audit/notif-1",
        }
    ]
    bad = rq.post(WEBHOOK_URL, json=notification, headers={"Authorization": "wrong"}, timeout=5)
    check("bad Authorization rejected", bad.status_code == 401, str(bad.status_code))

    good = rq.post(WEBHOOK_URL, json=notification, headers={"Authorization": AUTH_ID}, timeout=5)
    check("good Authorization accepted", good.status_code == 200, str(good.status_code))

    print("\nevents")
    events = drain(feed.events, 5.0)
    descs = sorted(e["description"] for e in events)
    check("events produced", len(events) == 4, f"{len(events)} events: {descs}")
    check(
        "sharepoint download filtered out",
        all("SharePoint file" not in d for d in descs),
        str(descs),
    )
    check(
        "internal ip keyed RoutedInternal",
        any("RoutedInternal" in e["device"] for e in events),
    )
    check("external ip keyed External", any("External" in e["device"] for e in events))
    check("identities attached", all("identity" in e for e in events))
    check("weights set", all(0.0 <= e["weight"] <= 1.0 for e in events))
    check("buckets set", all(isinstance(e.get("hash"), int) for e in events))
    check(
        "microsoft timestamps preserved",
        all(e["ts"] < time.time() - 3600 for e in events),
    )

    print("\ndeduplication")
    rq.post(WEBHOOK_URL, json=notification, headers={"Authorization": AUTH_ID}, timeout=5)
    check("repeat notification produced nothing", len(drain(feed.events, 3.0)) == 0)

    print("\nsubscription repair")
    fake.subscriptions["Audit.SharePoint"]["webhook"]["status"] = "disabled"
    feed.client.ensure_subscriptions(CONTENT_TYPES, WEBHOOK_URL, AUTH_ID)
    check(
        "disabled webhook re-enabled",
        fake.subscriptions["Audit.SharePoint"]["webhook"]["status"] == "enabled",
    )
    fake.subscriptions.pop("Audit.AzureActiveDirectory")
    feed.client.ensure_subscriptions(CONTENT_TYPES, WEBHOOK_URL, AUTH_ID)
    check(
        "dropped subscription restarted",
        "Audit.AzureActiveDirectory" in fake.subscriptions,
    )

    feed.stop.set()
    print("")
    if failures:
        print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
