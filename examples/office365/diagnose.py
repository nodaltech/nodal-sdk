"""
Check that a tenant can actually drive the Office 365 feeder, and measure how
fast it sees a change.

Talks to a real tenant and prints the raw truth at each step:

  1. token     does the app authenticate, and which roles did admin consent grant
  2. drive     does the named user have a OneDrive, and which id
  3. delta     does Graph report changes in that drive
  4. latency   edit a file, then time how long delta takes to report it

Step 4 is the number worth having. Microsoft documents an average of under a
minute for driveItem change *notifications* (with a 6 hour maximum), and
publishes nothing at all for delta. This measures your tenant instead of
trusting a table.

    python3 diagnose.py user@corp.example.com
    python3 diagnose.py user@corp.example.com --latency

Reads credentials from o365_feeder.yaml. Read-only unless --latency is given,
which creates and then deletes one small file in the named user's OneDrive.
"""

import argparse
import base64
import json
import sys
import time
from typing import Any, Dict, List, Optional

import requests
import yaml

CONFIG_FILE = "o365_feeder.yaml"
GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

PROBE_NAME = "nodal-feeder-latency-probe.txt"


def head(text: str) -> None:
    print(f"\n{'=' * 4} {text} {'=' * max(4, 68 - len(text))}")


def call(
    access: str,
    method: str,
    path: str,
    label: str,
    quiet: bool = False,
    **kwargs: Any,
) -> Optional[Dict[str, Any]]:
    """Make one Graph call and print exactly what came back."""
    url = path if path.startswith("http") else GRAPH + path
    resp = requests.request(
        method, url, headers={"Authorization": f"Bearer {access}"}, timeout=30, **kwargs
    )
    if not quiet:
        print(f"  {label}")
        print(f"    {method} {url.replace(GRAPH, '')}")
        print(f"    -> HTTP {resp.status_code}")

    if resp.status_code >= 300:
        if not quiet:
            print(f"    {resp.text[:500]}")
        return None
    return resp.json() if resp.content else {}


def get_token(conf: Dict[str, Any]) -> str:
    head("1. token")
    resp = requests.post(
        LOGIN.format(tenant=conf["TENANT_ID"]),
        data={
            "grant_type": "client_credentials",
            "client_id": conf["CLIENT_ID"],
            "client_secret": conf["CLIENT_SECRET"],
            "scope": "https://graph.microsoft.com/.default",
        },
        timeout=30,
    )
    if resp.status_code != 200:
        print(f"  FAILED {resp.status_code}: {resp.text[:400]}")
        print("\n  -> wrong tenant/client id, or a bad or expired client secret")
        sys.exit(1)

    access = resp.json()["access_token"]
    print("  got a token")

    # the roles claim is the only proof admin consent actually applied; the
    # portal lists a permission whether or not it was granted
    payload = access.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    roles = claims.get("roles") or []
    print(f"  roles: {roles or '(none)'}")

    if not ({"Files.Read.All", "Files.ReadWrite.All", "Sites.Read.All"} & set(roles)):
        print("  MISSING Files.Read.All -> delta and subscriptions will 403")
    if "User.Read.All" not in roles:
        print("  MISSING User.Read.All -> drive discovery and UPN resolution will fail")

    return access


def drive_of(access: str, upn: str) -> Optional[str]:
    head("2. drive")
    body = call(access, "GET", f"/users/{upn}/drive?$select=id,driveType,webUrl", f"OneDrive for {upn}")
    if body is None:
        print("\n  -> 404 here means the user has never opened OneDrive, so no")
        print("     drive exists. 403 means Files.Read.All was not consented.")
        return None

    print(f"    drive id:   {body.get('id')}")
    print(f"    drive type: {body.get('driveType')}")
    return body.get("id")


def show_delta(access: str, drive_id: str) -> Optional[str]:
    """Print the drive's current changes and return a delta link for 'now'."""
    head("3. delta")
    body = call(access, "GET", f"/drives/{drive_id}/root/delta", "recent changes")
    if body is None:
        print("\n  -> delta failing means auth or the wrong drive, and the")
        print("     feeder cannot work at all until this returns 200")
        return None

    items = [i for i in body.get("value") or [] if i.get("root") is None]
    print(f"    {len(items)} changed item(s) in the current enumeration")
    for item in items[:10]:
        kind = "folder" if item.get("folder") else "file"
        if item.get("deleted"):
            kind += " (deleted)"
        actor = ((item.get("lastModifiedBy") or {}).get("user") or {}).get("displayName", "?")
        print(f"      {kind:18} {item.get('name', '(name omitted)'):40} by {actor}")

    link = body.get("@odata.deltaLink")
    while not link and body.get("@odata.nextLink"):
        body = call(access, "GET", body["@odata.nextLink"], "next page", quiet=True) or {}
        link = body.get("@odata.deltaLink")

    print("\n    delta works. This is the mechanism the feeder uses after each")
    print("    change notification, so the feeder can see this drive.")
    return link


def measure_latency(access: str, drive_id: str, timeout: float) -> None:
    """Create a file, then time how long delta takes to report it."""
    head("4. latency")

    # a cursor for "now", so the probe is the only thing delta will report
    latest = call(
        access, "GET", f"/drives/{drive_id}/root/delta?token=latest", "cursor at now", quiet=True
    )
    if not latest or not latest.get("@odata.deltaLink"):
        print("  could not get a delta cursor, skipping")
        return
    cursor = latest["@odata.deltaLink"]

    print(f"  creating {PROBE_NAME}")
    created = requests.put(
        f"{GRAPH}/drives/{drive_id}/root:/{PROBE_NAME}:/content",
        headers={"Authorization": f"Bearer {access}", "Content-Type": "text/plain"},
        data=b"nodal feeder latency probe",
        timeout=30,
    )
    if created.status_code >= 300:
        print(f"  FAILED {created.status_code}: {created.text[:300]}")
        print("  -> needs Files.ReadWrite.All to write the probe. The feeder")
        print("     itself only needs read, so this is a diagnostic-only gap;")
        print("     edit a file by hand and re-run without --latency instead.")
        return

    item_id = created.json().get("id")
    started = time.time()
    print(f"  created at {time.strftime('%H:%M:%S')}, polling delta...")

    seen_after: Optional[float] = None
    try:
        while time.time() - started < timeout:
            body = call(access, "GET", cursor, "poll", quiet=True) or {}
            names = [i.get("name") for i in body.get("value") or []]
            if PROBE_NAME in names:
                seen_after = time.time() - started
                break
            time.sleep(2.0)
    finally:
        if item_id:
            call(
                access, "DELETE", f"/drives/{drive_id}/items/{item_id}", "cleanup", quiet=True
            )
            print(f"  deleted {PROBE_NAME}")

    print()
    if seen_after is None:
        print(f"  NOT SEEN within {timeout:.0f}s.")
        print("  delta is not reporting a change this drive definitely had, so")
        print("  the feeder would not have reported it either.")
    else:
        print(f"  delta reported the change after {seen_after:.1f}s")
        print()
        print("  That is delta's own lag. The feeder adds the notification")
        print("  delivery time on top, which Microsoft documents as averaging")
        print("  under a minute with a 6 hour maximum - so treat this as the")
        print("  floor, not the end-to-end figure.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check a tenant against the Office 365 feeder")
    parser.add_argument("upn", help="the UPN whose OneDrive to check")
    parser.add_argument(
        "--latency",
        action="store_true",
        help="create and delete a probe file to measure how fast delta reports it",
    )
    parser.add_argument(
        "--timeout", type=float, default=300.0, help="how long to wait for the probe (seconds)"
    )
    args = parser.parse_args()

    with open(CONFIG_FILE) as f:
        conf = yaml.safe_load(f)

    access = get_token(conf)

    drive_id = drive_of(access, args.upn)
    if drive_id is None:
        sys.exit(1)

    if show_delta(access, drive_id) is None:
        sys.exit(1)

    if args.latency:
        measure_latency(access, drive_id, args.timeout)
    else:
        head("4. latency")
        print("  skipped. Re-run with --latency to measure how fast delta")
        print("  reports a change (creates and deletes one small probe file).")


if __name__ == "__main__":
    main()
