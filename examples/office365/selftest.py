"""
Offline end-to-end check for the Office 365 feeder.

Stands up a fake Microsoft Graph on loopback, points the feeder at it, and walks
the whole path: token -> drive discovery -> activity poll -> cursor -> Nodal
events. No tenant, no ghost and no network access needed, so it is a reasonable
smoke test to run on a box before pointing the real thing at a live tenant.

    python3 selftest.py
"""

import json
import logging
import sys
import threading
import time
from typing import Any, Dict, List

from flask import Flask, jsonify

import o365_events
import o365_feeder
import o365_graph

TENANT = "selftest-tenant"
FAKE_PORT = 8098

USERS = ["alice@corp.example.com", "bob@corp.example.com"]
DRIVE_IDS = {"alice@corp.example.com": "b!alice", "bob@corp.example.com": "b!bob"}

log = logging.getLogger("o365.selftest")


class FakeGraph:
    """Just enough of graph.microsoft.com to exercise the client and the feeder."""

    def __init__(self, activities: List[Dict[str, Any]]):
        self.activities = list(activities)
        self.tokens_issued = 0
        self.activity_calls: List[str] = []
        self.users_calls = 0
        self.upn_lookups = 0
        self.app = self._build()

    def _build(self) -> Flask:
        app = Flask("fake-graph")
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

        @app.route(f"/{TENANT}/oauth2/v2.0/token", methods=["POST"])
        def token():
            self.tokens_issued += 1
            return jsonify({"access_token": "fake-token", "expires_in": 3600})

        @app.route("/v1.0/users", methods=["GET"])
        def users():
            self.users_calls += 1
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
            self.upn_lookups += 1
            return jsonify({"userPrincipalName": user.replace("id-", "")})

        @app.route("/v1.0/users/<upn>/drive", methods=["GET"])
        def drive(upn):
            if upn not in DRIVE_IDS:
                return jsonify({"error": {"code": "itemNotFound"}}), 404
            return jsonify({"id": DRIVE_IDS[upn], "driveType": "business"})

        @app.route("/v1.0/drives/<drive_id>/activities", methods=["GET"])
        def activities(drive_id):
            self.activity_calls.append(drive_id)
            return jsonify({"value": self.activities})

        return app

    def serve(self) -> None:
        from waitress import serve

        serve(self.app, host="127.0.0.1", port=FAKE_PORT, threads=8)


class RecordingFeeder:
    """Stands in for the SDK Feeder so nothing needs a ghost or a ZMQ socket."""

    def __init__(self):
        self.sent: List[Dict[str, Any]] = []

    def send(self, cmd: str, data: Any) -> None:
        self.sent.append(data)

    def drain(self) -> List[Dict[str, Any]]:
        sent, self.sent = self.sent, []
        return sent


def wait_for_port(port: int, timeout: float = 10.0) -> None:
    """Block until the fake Graph is accepting connections."""
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.25)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"fake graph never came up on port {port}")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s %(message)s"
    )

    with open("samples/drive_activities.json") as f:
        activities = json.load(f)["value"]

    fake = FakeGraph(activities)
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
        "WATCH_USERS": ["*"],
        "WATCH_SITES": [],
        "MAX_DRIVES": 200,
        "POLL_INTERVAL_SECS": 20,
        "POLL_WORKERS": 4,
        "MAX_ACTIVITY_PAGES": 2,
        "DISCOVER_INTERVAL_SECS": 3600,
        "DEVICE_IP": "10.0.1.11",
    }

    feed = o365_feeder.O365Feed(conf, dry_run=True)
    recorder = RecordingFeeder()
    feed.feeder = recorder

    failures = []

    def check(name, ok, detail=""):
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{(' - ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    print("\ndiscovery")
    feed.discover()
    check("both user drives discovered", sorted(feed.drives) == ["b!alice", "b!bob"], str(sorted(feed.drives)))
    check(
        "cursor primed to now, not zero",
        all(d.cursor > time.time() - 10 for d in feed.drives.values()),
    )

    print("\na new drive does not replay history")
    # every sample activity predates startup, so a freshly adopted drive must
    # feed nothing at all
    check("first sweep on a new drive fed nothing", feed.sweep() == 0)
    check("nothing sent", recorder.drain() == [])

    print("\npolling")
    # rewind both cursors to before the sample data, as if the feed had been
    # running since then
    with feed.drives_lock:
        for drive in feed.drives.values():
            drive.cursor = 0.0

    calls_before = len(fake.activity_calls)
    fed = feed.sweep()
    check("one activity call per drive", len(fake.activity_calls) - calls_before == 2, str(len(fake.activity_calls) - calls_before))

    events = recorder.drain()
    descs = sorted(e["description"] for e in events)
    # 6 feedable activities per drive x 2 drives; the comment is dropped
    check("events fed for both drives", fed == 12 and len(events) == 12, f"{fed}/{len(events)}: {sorted(set(descs))}")
    check("accessed mapped", descs.count("OneDrive file accessed") == 6, str(descs.count("OneDrive file accessed")))
    check("shared mapped", descs.count("OneDrive file shared") == 2)
    check("deleted mapped", descs.count("OneDrive file deleted") == 2)
    check("comment activity dropped", not any("comment" in d for d in descs))

    print("\nbeta and v1.0 activity shapes")
    # v1.0 puts actions at the top level, beta nests them under `action` and uses
    # times.recordedTime - both must map, so switching endpoints cannot silently
    # produce an empty feed
    check("beta-shaped activity mapped", descs.count("OneDrive file edited") == 2, str(descs.count("OneDrive file edited")))
    beta = [e for e in events if e["metadata"]["activity_id"].startswith("BETASHAPED")]
    check("beta timestamp read from times.recordedTime", all(e["ts"] > 0 for e in beta) and len(beta) == 2)

    print("\ncursor, not a seen-list")
    check("re-polling fed nothing", feed.sweep() == 0)
    check("nothing sent on re-poll", recorder.drain() == [])

    # one new activity, newer than the cursor, must come through on its own
    fake.activities.append(
        {
            "id": "BRANDNEWACCESS999==",
            "access": {},
            "activityDateTime": "2026-09-02T09:00:00Z",
            "actor": {"user": {"userPrincipalName": "bob@corp.example.com"}},
            "driveItem": {"id": "01NEWITEM", "name": "salaries.xlsx"},
        }
    )
    fed = feed.sweep()
    check("only the new activity fed", fed == 2, str(fed))
    new_events = recorder.drain()
    check(
        "new activity is the right one",
        all(e["metadata"]["item_name"] == "salaries.xlsx" for e in new_events),
        str([e["metadata"].get("item_name") for e in new_events]),
    )

    print("\nevent shape")
    check(
        "configured device on every event",
        all(e.get("device") == {"RoutedInternal": "10.0.1.11"} for e in events),
        str({json.dumps(e.get("device")) for e in events}),
    )
    check("device_ip set alongside it", all(e.get("device_ip") == "10.0.1.11" for e in events))
    check("identity on every event", all("identity" in e for e in events))
    check(
        "identity is a upn, not a display name",
        all("@" in e["identity"]["name"] for e in events),
        str(sorted({e["identity"]["name"] for e in events})),
    )
    check("identity source is office365", all(e["identity"]["source"] == "office365" for e in events))
    check("weights set", all(0.0 <= e["weight"] <= 1.0 for e in events))
    check("buckets set", all(isinstance(e.get("hash"), int) for e in events))
    check("microsoft timestamps preserved", all(e["ts"] < time.time() - 3600 for e in events))
    check("action recorded in metadata", all(e["metadata"].get("action") for e in events))

    print("\nbucketing")
    per_drive = [e for e in events if e["metadata"]["drive_id"] == "b!bob"]
    # customer-list.csv is accessed once and shared once: different actions on
    # the same file must land in different buckets
    same_file = [e for e in per_drive if e["metadata"].get("item_name") == "customer-list.csv"]
    check("same file, different action, different bucket", len({e["hash"] for e in same_file}) == 2, str(len(same_file)))
    # two distinct files accessed by one user must land in different buckets
    accesses = [
        e for e in per_drive if e["metadata"]["action"] == "access" and e["metadata"].get("item_id")
    ]
    check("distinct files bucket separately", len({e["hash"] for e in accesses}) == len(accesses), str(len(accesses)))
    # an activity with no expanded driveItem falls back to a per-user bucket
    itemless = [e for e in events if not e["metadata"].get("item_id")]
    check("item-less activity still mapped", len(itemless) == 2, str(len(itemless)))
    check("item-less activity buckets per user", all(isinstance(e["hash"], int) for e in itemless))

    print("\nidentity resolution")
    check(
        "email used when upn absent",
        any(e["identity"]["name"] == "alice@corp.example.com" for e in events),
    )
    # every sample actor already carries a upn or an email, so the resolver must
    # not have been called - a lookup per event would be a real cost at volume
    check("no wasted upn lookups", fake.upn_lookups == 0, str(fake.upn_lookups))

    # an actor known only by object id has to fall back to the resolver
    lookups_before = fake.upn_lookups
    resolved = feed.mapper.actor_identity(
        {"user": {"id": "id-carol@corp.example.com", "displayName": "Carol Chen"}}
    )
    check("object id resolved to a upn", resolved == "carol@corp.example.com", str(resolved))
    check("resolver was actually called", fake.upn_lookups == lookups_before + 1)
    # and the answer is cached, so a second actor with the same id costs nothing
    feed.mapper.actor_identity({"user": {"id": "id-carol@corp.example.com"}})
    check("resolved upn is cached", fake.upn_lookups == lookups_before + 1)

    # display name is the last resort, and an unresolvable actor still maps
    check(
        "display name used as a last resort",
        feed.mapper.actor_identity({"user": {"displayName": "Dave Davis"}}) == "Dave Davis",
    )
    check("actor with nothing usable is skipped", feed.mapper.actor_identity({}) is None)

    print("\ndevice key configuration")
    # an internal address keys as RoutedInternal - there is no MAC for a cloud
    # feed, and never will be
    internal = o365_events.EventMapper(device_ip="10.0.1.11")
    check("internal ip keys RoutedInternal", internal.device == {"RoutedInternal": "10.0.1.11"}, str(internal.device))
    public = o365_events.EventMapper(device_ip="203.0.113.44")
    check("public ip keys External", public.device == {"External": "203.0.113.44"}, str(public.device))
    v6 = o365_events.EventMapper(device_ip="fc00::1")
    check("internal v6 keys RoutedInternal", v6.device == {"RoutedInternal": "fc00::1"}, str(v6.device))

    # DEVICE_IP is required and validated at startup, not at the first event
    for bad, why in (("", "empty"), ("10.0.1.999", "malformed"), (None, "missing")):
        try:
            o365_events.EventMapper(device_ip=bad)
            check(f"{why} DEVICE_IP rejected", False, "no error raised")
        except ValueError:
            check(f"{why} DEVICE_IP rejected", True)

    print("\nno sdk changes needed")
    # the stock EventBuilder takes a device positionally and always sets it, so
    # nothing here depends on a patched SDK
    import inspect

    from nodal_sdk.feeder import EventBuilder
    from nodal_sdk.types import Event as EventType

    sig = inspect.signature(EventBuilder.__init__)
    check(
        "EventBuilder.device has no default",
        sig.parameters["device"].default is inspect.Parameter.empty,
    )
    check("Event.device is required in the SDK", "device" in EventType.__required_keys__)
    check(
        "every emitted event satisfies that",
        all(isinstance(e.get("device"), dict) and e["device"] for e in events),
    )

    print("\nfailure handling")
    o365_graph.GRAPH = "http://127.0.0.1:1/v1.0"  # nothing listening
    cursors = {d.drive_id: d.cursor for d in feed.drives.values()}
    errors_before = feed.stats["errors"]
    check("sweep survives graph being down", feed.sweep() == 0)
    check("errors counted", feed.stats["errors"] > errors_before)
    check(
        "cursors untouched by a failed poll",
        all(d.cursor == cursors[d.drive_id] for d in feed.drives.values()),
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
