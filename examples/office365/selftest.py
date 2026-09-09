"""
Offline end-to-end check for the Office 365 feeder.

Stands up a fake Microsoft Graph on loopback, points the feeder at it, and walks
the whole path: token -> drive discovery -> subscription create -> validationToken
handshake -> change notification -> delta -> Nodal events. No tenant, no ghost
and no network access needed, so it is a reasonable smoke test to run on a box
before pointing the real thing at a live tenant.

    python3 selftest.py
"""

import json
import logging
import socket
import sys
import threading
import time
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests as rq
from flask import Flask, jsonify, request

import o365_events
import o365_feeder
import o365_graph

TENANT = "selftest-tenant"
CLIENT_STATE = "selftest-shared-secret"
DEVICE_IP = "10.0.1.11"
FAKE_PORT = 8098
WEBHOOK_PORT = 8099
WEBHOOK_PATH = "/webhook/o365"
NOTIFICATION_URL = f"http://127.0.0.1:{WEBHOOK_PORT}{WEBHOOK_PATH}"

USERS = ["alice@corp.example.com", "bob@corp.example.com"]
DRIVE_IDS = {"alice@corp.example.com": "b!alice", "bob@corp.example.com": "b!bob"}

log = logging.getLogger("o365.selftest")


class FakeGraph:
    """Just enough of graph.microsoft.com to exercise the client and the feeder."""

    def __init__(self, changes: List[Dict[str, Any]]):
        self.changes = changes
        self.subscriptions: Dict[str, Dict[str, Any]] = {}
        self.validations: List[Any] = []
        self.delta_calls: List[str] = []
        self.deleted: List[str] = []
        self.next_sub = 0
        # flipped per drive once its changes have been handed out, so a second
        # delta call returns an empty set like the real thing
        self.drained: Dict[str, bool] = {}
        # delta follows an absolute deltaLink, so pointing the client's base URL
        # at a dead port cannot break it - this is the switch that can
        self.fail_delta = False
        self.app = self._build()

    def _build(self) -> Flask:
        app = Flask("fake-graph")
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

        @app.route(f"/{TENANT}/oauth2/v2.0/token", methods=["POST"])
        def token():
            return jsonify({"access_token": "fake-token", "expires_in": 3600})

        @app.route("/v1.0/users", methods=["GET"])
        def users():
            return jsonify(
                {
                    "value": [
                        {"id": f"id-{u}", "userPrincipalName": u, "accountEnabled": True}
                        for u in USERS
                    ]
                }
            )

        @app.route("/v1.0/users/<user>", methods=["GET"])
        def user(user):
            return jsonify({"userPrincipalName": user.replace("id-", "")})

        @app.route("/v1.0/users/<upn>/drive", methods=["GET"])
        def drive(upn):
            if upn not in DRIVE_IDS:
                return jsonify({"error": {"code": "itemNotFound"}}), 404
            return jsonify({"id": DRIVE_IDS[upn], "driveType": "business"})

        @app.route("/v1.0/subscriptions", methods=["GET", "POST"])
        def subscriptions():
            if request.method == "GET":
                return jsonify({"value": list(self.subscriptions.values())})

            body = request.get_json(silent=True) or {}
            url = body.get("notificationUrl")

            # Graph validates the endpoint inline, during this very call
            resp = rq.post(url, params={"validationToken": "validate-me"}, timeout=5)
            self.validations.append(
                (urlparse(url).path, resp.status_code, resp.text, resp.headers.get("Content-Type", ""))
            )
            if resp.status_code != 200 or resp.text != "validate-me":
                return jsonify({"error": {"code": "InvalidRequest"}}), 400

            self.next_sub += 1
            sub_id = f"sub-{self.next_sub}"
            sub = dict(body, id=sub_id, expirationDateTime="2099-01-01T00:00:00.0000000Z")
            self.subscriptions[sub_id] = sub
            return jsonify(sub), 201

        @app.route("/v1.0/subscriptions/<sub_id>", methods=["PATCH", "DELETE"])
        def subscription(sub_id):
            if request.method == "DELETE":
                self.subscriptions.pop(sub_id, None)
                self.deleted.append(sub_id)
                return "", 204
            if sub_id not in self.subscriptions:
                return jsonify({"error": {"code": "ResourceNotFound"}}), 404
            self.subscriptions[sub_id]["expirationDateTime"] = "2099-06-01T00:00:00.0000000Z"
            return jsonify(self.subscriptions[sub_id])

        @app.route("/v1.0/drives/<drive_id>/root/delta", methods=["GET"])
        def delta(drive_id):
            self.delta_calls.append(drive_id)
            if self.fail_delta:
                return jsonify({"error": {"code": "serviceNotAvailable"}}), 503
            link = f"http://127.0.0.1:{FAKE_PORT}/v1.0/drives/{drive_id}/root/delta?token=next"

            if request.args.get("token") == "latest" or self.drained.get(drive_id):
                return jsonify({"value": [], "@odata.deltaLink": link})

            self.drained[drive_id] = True
            return jsonify({"value": self.changes, "@odata.deltaLink": link})

        return app

    def serve(self) -> None:
        from waitress import serve

        serve(self.app, host="127.0.0.1", port=FAKE_PORT, threads=8)


class RecordingFeeder:
    """Stands in for the SDK Feeder so nothing needs a ghost or a ZMQ socket."""

    def __init__(self):
        self.sent: List[Dict[str, Any]] = []
        self.lock = threading.Lock()

    def send(self, cmd: str, data: Any) -> None:
        with self.lock:
            self.sent.append(data)

    def drain(self) -> List[Dict[str, Any]]:
        with self.lock:
            sent, self.sent = self.sent, []
        return sent


def wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.25)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"nothing came up on port {port}")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s %(message)s"
    )

    with open("samples/drive_changes.json") as f:
        changes = json.load(f)["value"]

    fake = FakeGraph(changes)
    threading.Thread(target=fake.serve, name="fake-graph", daemon=True).start()
    wait_for_port(FAKE_PORT)

    # redirect the client at the fake tenant endpoints
    o365_graph.GRAPH = f"http://127.0.0.1:{FAKE_PORT}/v1.0"
    o365_graph.LOGIN_URL = f"http://127.0.0.1:{FAKE_PORT}/{{tenant}}/oauth2/v2.0/token"

    conf = {
        "COMPONENT_NAME": "office365-selftest",
        "COMPONENT_TOKEN": "unused",
        "COMPONENT_IP": "127.0.0.1",
        "LISTEN_PORT": 4002,
        "GHOST_URL": "http://127.0.0.1:8080/api/components/handshake",
        "TENANT_ID": TENANT,
        "CLIENT_ID": "client",
        "CLIENT_SECRET": "secret",
        "NOTIFICATION_URL": NOTIFICATION_URL,
        "WEBHOOK_PATH": WEBHOOK_PATH,
        "WEBHOOK_HOST": "127.0.0.1",
        "WEBHOOK_PORT": WEBHOOK_PORT,
        "CLIENT_STATE": CLIENT_STATE,
        "WATCH_USERS": ["*"],
        "WATCH_SITES": [],
        "MAX_DRIVES": 200,
        "DEVICE_IP": DEVICE_IP,
        "MAX_PAGES": 3,
    }

    feed = o365_feeder.O365Feed(conf, dry_run=True)
    recorder = RecordingFeeder()
    feed.feeder = recorder

    # a subscription left behind by a previous run, which startup must clear
    fake.subscriptions["stale-sub"] = {
        "id": "stale-sub",
        "notificationUrl": NOTIFICATION_URL,
        "resource": "/drives/b!alice/root",
        "expirationDateTime": "2099-01-01T00:00:00.0000000Z",
    }
    # and somebody else's, which it must leave alone
    fake.subscriptions["other-app"] = {
        "id": "other-app",
        "notificationUrl": "https://someone-else.example.com/hook",
        "resource": "/drives/b!alice/root",
        "expirationDateTime": "2099-01-01T00:00:00.0000000Z",
    }

    feed.start_threads()
    time.sleep(2.0)  # let the maintenance pass subscribe both drives

    failures = []

    def check(name, ok, detail=""):
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{(' - ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    print("\ndiscovery and subscriptions")
    check("both user drives discovered", sorted(feed.drives) == ["b!alice", "b!bob"], str(sorted(feed.drives)))
    check("stale subscription deleted at startup", "stale-sub" in fake.deleted)
    check("another app's subscription left alone", "other-app" in fake.subscriptions)
    live = [s for s in fake.subscriptions.values() if s["notificationUrl"] == NOTIFICATION_URL]
    check("exactly one subscription per drive", len(live) == 2, str(len(live)))
    check(
        "subscribed the right resources",
        sorted(s["resource"] for s in live) == ["/drives/b!alice/root", "/drives/b!bob/root"],
    )
    check("changeType is updated", all(s["changeType"] == "updated" for s in live))
    check("clientState sent on subscribe", all(s["clientState"] == CLIENT_STATE for s in live))

    print("\nendpoint validation handshake")
    check("both endpoints validated", len(fake.validations) == 2, str(len(fake.validations)))
    check("answered 200", all(v[1] == 200 for v in fake.validations))
    check("echoed the token verbatim", all(v[2] == "validate-me" for v in fake.validations))
    check(
        "answered as text/plain",
        all(v[3].startswith("text/plain") for v in fake.validations),
        fake.validations[0][3] if fake.validations else "none",
    )

    print("\ndelta primed to now")
    check("delta primed for both drives", len(fake.delta_calls) == 2, str(fake.delta_calls))
    check("nothing fed on subscribe", recorder.drain() == [])

    print("\nnotification -> events")

    def a_live_subscription() -> str:
        """Resolved at call time - the repair test below replaces these ids."""
        with feed.registry_lock:
            return sorted(feed.by_subscription)[0]

    def notify(state=CLIENT_STATE, sub=None):
        sub_id = sub or a_live_subscription()
        with feed.registry_lock:
            drive = feed.by_subscription.get(sub_id)
        drive_id = drive.drive_id if drive else "b!unknown"
        return rq.post(
            NOTIFICATION_URL,
            json={
                "value": [
                    {
                        "subscriptionId": sub_id,
                        "clientState": state,
                        "changeType": "updated",
                        "resource": f"drives/{drive_id}/root",
                        "tenantId": TENANT,
                    }
                ]
            },
            timeout=10,
        )

    resp = notify()
    check("notification accepted", resp.status_code == 200, str(resp.status_code))

    events = recorder.drain()
    descs = sorted(e["description"] for e in events)
    # created, edited, file deleted, folder deleted; root and folder-churn skipped
    check("four events fed", len(events) == 4, f"{len(events)}: {descs}")
    check("file created mapped", "OneDrive file created" in descs)
    check("file edited mapped", "OneDrive file edited" in descs)
    check("deletions mapped", descs.count("OneDrive file deleted") == 2, str(descs))
    check("drive root skipped", not any(e["metadata"].get("item_name") == "root" for e in events))
    check(
        "folder churn skipped but folder deletion kept",
        sorted(e["metadata"]["item_type"] for e in events) == ["file", "file", "file", "folder"],
        str(sorted(e["metadata"]["item_type"] for e in events)),
    )

    print("\nevent shape")
    check(
        "configured device on every event",
        all(e.get("device") == {"RoutedInternal": DEVICE_IP} for e in events),
        str({json.dumps(e.get("device")) for e in events}),
    )
    check("device_ip set alongside it", all(e.get("device_ip") == DEVICE_IP for e in events))
    check("identity on every event", all("identity" in e for e in events))
    check(
        "identity is a upn, not a display name",
        all("@" in e["identity"]["name"] for e in events),
        str(sorted({e["identity"]["name"] for e in events})),
    )
    check("identity source is office365", all(e["identity"]["source"] == "office365" for e in events))
    check("weights set", all(0.0 <= e["weight"] <= 1.0 for e in events))
    check("buckets set", all(isinstance(e.get("hash"), int) for e in events))
    check(
        "buckets distinct per item",
        len({e["hash"] for e in events}) == len(events),
        str(len({e["hash"] for e in events})),
    )
    check("microsoft timestamps preserved", all(e["ts"] < time.time() - 3600 for e in events))
    check("action recorded in metadata", all(e["metadata"].get("action") for e in events))

    print("\nno seen-set needed")
    # the delta cursor has advanced, so a redelivery must feed nothing
    resp = notify()
    check("redelivered notification accepted", resp.status_code == 200, str(resp.status_code))
    check("redelivery fed nothing", recorder.drain() == [])

    print("\nauthentication")
    bad = notify(state="wrong")
    check("bad clientState fed nothing", bad.status_code == 200 and recorder.drain() == [])
    unknown = notify(sub="sub-does-not-exist")
    check("unknown subscription fed nothing", unknown.status_code == 200 and recorder.drain() == [])

    print("\nsubscription repair")
    fake.subscriptions.clear()
    for drive in feed.drives.values():
        with feed.registry_lock:
            feed.by_subscription.pop(drive.subscription_id, None)
        drive.subscription_id = ""
        drive.expires = 0.0
    feed.maintain()
    check("dropped subscriptions recreated", len(fake.subscriptions) == 2, str(len(fake.subscriptions)))
    check("cursor survived the resubscribe", all(d.delta_link for d in feed.drives.values()))

    print("\ndevice key configuration")
    check(
        "internal ip keys RoutedInternal",
        o365_events.EventMapper(device_ip="10.0.1.11").device == {"RoutedInternal": "10.0.1.11"},
    )
    check(
        "public ip keys External",
        o365_events.EventMapper(device_ip="203.0.113.44").device == {"External": "203.0.113.44"},
    )
    for bad_ip, why in (("", "empty"), ("10.0.1.999", "malformed"), (None, "missing")):
        try:
            o365_events.EventMapper(device_ip=bad_ip)
            check(f"{why} DEVICE_IP rejected", False, "no error raised")
        except ValueError:
            check(f"{why} DEVICE_IP rejected", True)

    print("\nno sdk changes needed")
    import inspect

    from nodal_sdk.feeder import EventBuilder
    from nodal_sdk.types import Event as EventType

    check(
        "EventBuilder.device has no default",
        inspect.signature(EventBuilder.__init__).parameters["device"].default
        is inspect.Parameter.empty,
    )
    check("Event.device is required in the SDK", "device" in EventType.__required_keys__)
    check(
        "every emitted event satisfies that",
        all(isinstance(e.get("device"), dict) and e["device"] for e in events),
    )

    print("\ngraph failure handling")
    # A change is waiting, but Graph is refusing to serve delta. The feeder must
    # answer non-2xx so Graph redelivers, and must not move the cursor past a
    # change it never actually read.
    fake.fail_delta = True
    fake.drained.clear()
    feed.client.max_retries = 0  # fail fast, this is not a retry test
    cursors = {d.drive_id: d.delta_link for d in feed.drives.values()}

    broken = notify()
    check("503 returned so graph redelivers", broken.status_code == 503, str(broken.status_code))
    check("nothing fed on failure", recorder.drain() == [])
    check(
        "cursors untouched by a failed fetch",
        all(d.delta_link == cursors[d.drive_id] for d in feed.drives.values()),
    )

    # and once Graph recovers, the redelivered notification picks the change up
    fake.fail_delta = False
    recovered = notify()
    check("recovers on redelivery", recovered.status_code == 200, str(recovered.status_code))
    check("the missed change is fed after recovery", len(recorder.drain()) == 4)

    feed.stop.set()
    print("")
    if failures:
        print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
