"""
Thin Microsoft Graph client for the Office 365 feeder.

Covers exactly what the feeder needs:

  auth           client credentials token for https://graph.microsoft.com
  discovery      which drives to watch (user OneDrives, SharePoint libraries)
  subscriptions  create, renew and delete change notification subscriptions
  delta          what changed in a drive, since last time

A driveItem change notification says only "something in this drive changed" -
never what, never by whom. `delta` answers those, and its delta link doubles as
the cursor that makes redelivered notifications free.

Reads are not available on this transport at all. Reading a file does not change
it, so a download fires no notification and appears in no delta. That signal
lives only in the unified audit log, via the Office 365 Management Activity API,
at roughly 30 minutes behind.

App registration needs the Microsoft Graph *application* permissions
`Files.Read.All` (or `Sites.Read.All`) and `User.Read.All`, with admin consent.
"""

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

import requests

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
SCOPE = "https://graph.microsoft.com/.default"

log = logging.getLogger("o365.graph")


class GraphError(Exception):
    pass


def parse_ts(value: Any) -> Optional[datetime]:
    """Parse the ISO-8601 timestamps Graph returns, with or without fractions."""
    if not value:
        return None

    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        log.debug("could not parse timestamp %r", value)
        return None

    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class GraphClient:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        timeout: float = 10.0,
        max_retries: int = 2,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

        # Kept tight. Delta runs inline in the webhook handler, and Graph marks
        # an endpoint "slow" once more than 10% of responses miss its 3 second
        # budget - better to fail a fetch and let Graph redeliver.
        self.timeout = timeout
        self.max_retries = max_retries

        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._token_expiry = 0.0

        # user object id -> UPN. Graph gives an actor's id and display name but
        # not always their UPN, and identity is what Brain correlates on here.
        self._upns: Dict[str, Optional[str]] = {}
        self._upn_lock = threading.Lock()

    # ------------------------------------------------------------------ auth

    def token(self, force: bool = False) -> str:
        with self._lock:
            if not force and self._token and time.time() < self._token_expiry:
                return self._token

            try:
                resp = requests.post(
                    LOGIN_URL.format(tenant=self.tenant_id),
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "scope": SCOPE,
                    },
                    timeout=30.0,
                )
            except requests.RequestException as e:
                raise GraphError(f"token request failed: {e}") from e

            if resp.status_code != 200:
                raise GraphError(f"token request failed {resp.status_code}: {resp.text[:400]}")

            body = resp.json()
            self._token = body["access_token"]
            # renew a minute early so in-flight requests don't race the expiry
            self._token_expiry = time.time() + float(body.get("expires_in", 3600)) - 60
            log.info("acquired graph token for tenant %s", self.tenant_id)
            return self._token

    # --------------------------------------------------------------- request

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        expected: Sequence[int] = (200,),
    ) -> requests.Response:
        if not url.startswith("http"):
            url = GRAPH + url

        force_token = False
        last_error: Optional[str] = None

        for attempt in range(self.max_retries + 1):
            try:
                resp = requests.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers={"Authorization": f"Bearer {self.token(force=force_token)}"},
                    timeout=self.timeout,
                )
            except requests.RequestException as e:
                last_error = str(e)
                log.warning("%s %s errored (%s)", method, url, e)
                time.sleep(min(2.0 ** attempt, 5.0))
                continue

            if resp.status_code in expected:
                return resp

            last_error = f"{resp.status_code}: {resp.text[:400]}"

            # a delta link that has aged out; the caller re-primes
            if resp.status_code == 410:
                raise GraphError(f"resync required: {last_error}")

            if resp.status_code == 401 and not force_token:
                force_token = True
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                wait = min(2.0 ** attempt, 5.0)
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = max(wait, min(float(retry_after), 10.0))
                    except ValueError:
                        pass
                log.warning("%s %s throttled (%s), waiting %.0fs", method, url, resp.status_code, wait)
                time.sleep(wait)
                continue

            break  # anything else is a hard error

        raise GraphError(f"{method} {url} failed - {last_error}")

    def get_json(self, url: str, **kwargs: Any) -> Dict[str, Any]:
        return self.request("GET", url, **kwargs).json() or {}

    def paged(self, url: str, max_pages: int = 5, **kwargs: Any) -> Iterator[Dict[str, Any]]:
        """Walk @odata.nextLink, stopping after max_pages."""
        pages = 0
        while url and pages < max_pages:
            body = self.get_json(url, **kwargs)
            pages += 1
            for item in body.get("value") or []:
                yield item
            url = body.get("@odata.nextLink") or ""
            kwargs.pop("params", None)  # nextLink already carries them

        if url:
            log.warning("stopped paging %s after %d page(s)", url.split("?")[0], pages)

    # ------------------------------------------------------------- discovery

    def user_upn(self, user_id: str) -> Optional[str]:
        """Resolve a directory object id to a UPN, cached for the process."""
        if not user_id:
            return None
        with self._upn_lock:
            if user_id in self._upns:
                return self._upns[user_id]

        upn: Optional[str] = None
        try:
            upn = self.get_json(
                f"/users/{user_id}", params={"$select": "userPrincipalName"}
            ).get("userPrincipalName")
        except GraphError as e:
            # a deleted user, or a service principal that is not a user at all
            log.debug("could not resolve upn for %s: %s", user_id, e)

        with self._upn_lock:
            self._upns[user_id] = upn
        return upn

    def user_drives(self, upns: Sequence[str], limit: int) -> List[Dict[str, Any]]:
        """
        Resolve the OneDrive of each requested user.

        `upns` of ["*"] means every enabled user in the tenant. There is no
        tenant-wide drive listing in Graph, so this is one call per user.
        """
        if list(upns) == ["*"]:
            wanted = [
                u["userPrincipalName"]
                for u in self.paged(
                    "/users",
                    max_pages=50,
                    params={"$select": "id,userPrincipalName,accountEnabled", "$top": 999},
                )
                if u.get("userPrincipalName") and u.get("accountEnabled", True)
            ]
        else:
            wanted = [u for u in upns if u]

        drives = []
        for upn in wanted:
            if len(drives) >= limit:
                log.warning("stopping drive discovery at MAX_DRIVES=%d", limit)
                break
            try:
                drive = self.get_json(
                    f"/users/{upn}/drive", params={"$select": "id,driveType"}
                )
            except GraphError as e:
                # common: a user who has never opened OneDrive has no drive
                log.debug("no drive for %s: %s", upn, e)
                continue
            if drive.get("id"):
                drive["_owner"] = upn
                drives.append(drive)

        return drives

    def site_drives(self, sites: Sequence[str], limit: int) -> List[Dict[str, Any]]:
        """Resolve the document libraries of each requested SharePoint site."""
        if list(sites) == ["*"]:
            wanted = [
                s["id"]
                for s in self.paged("/sites", max_pages=20, params={"search": "*", "$select": "id"})
                if s.get("id")
            ]
        else:
            wanted = [s for s in sites if s]

        drives = []
        for site in wanted:
            if len(drives) >= limit:
                log.warning("stopping site drive discovery at MAX_DRIVES=%d", limit)
                break
            try:
                for drive in self.paged(
                    f"/sites/{site}/drives", max_pages=5, params={"$select": "id,driveType,name"}
                ):
                    if drive.get("id"):
                        drive["_owner"] = str(drive.get("name", ""))
                        drives.append(drive)
            except GraphError as e:
                log.error("could not list drives for site %s: %s", site, e)

        return drives

    # --------------------------------------------------------- subscriptions

    def create_subscription(
        self, drive_id: str, notification_url: str, client_state: str, minutes: int
    ) -> Dict[str, Any]:
        """
        Subscribe to changes in one drive.

        Graph validates the endpoint *during this call*: it POSTs a
        validationToken to `notification_url` and wants it echoed back as plain
        text within 10 seconds, so the webserver must already be reachable.
        """
        resp = self.request(
            "POST",
            "/subscriptions",
            json_body={
                "changeType": "updated",  # the only changeType driveItem supports
                "resource": f"/drives/{drive_id}/root",
                "notificationUrl": notification_url,
                "clientState": client_state,
                "expirationDateTime": (
                    datetime.now(timezone.utc) + timedelta(minutes=minutes)
                ).strftime("%Y-%m-%dT%H:%M:%S.0000000Z"),
            },
            expected=(201,),
        )
        return resp.json() or {}

    def renew_subscription(self, subscription_id: str, minutes: int) -> Dict[str, Any]:
        resp = self.request(
            "PATCH",
            f"/subscriptions/{subscription_id}",
            json_body={
                "expirationDateTime": (
                    datetime.now(timezone.utc) + timedelta(minutes=minutes)
                ).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
            },
        )
        return resp.json() or {}

    def delete_our_subscriptions(self, notification_url: str) -> int:
        """
        Delete every subscription pointing at our own endpoint.

        Called at startup: a restart inside a subscription's lifetime would
        otherwise leave the old one live and get every change notified twice.
        Deleting and recreating is simpler than reconciling what survived, and
        the drives resubscribe on the first maintenance pass.
        """
        deleted = 0
        for sub in self.paged("/subscriptions", max_pages=20):
            if str(sub.get("notificationUrl") or "") != notification_url:
                continue  # somebody else's subscription, leave it alone
            try:
                self.request("DELETE", f"/subscriptions/{sub['id']}", expected=(204, 404))
                deleted += 1
            except GraphError as e:
                log.warning("could not delete old subscription %s: %s", sub.get("id"), e)
        return deleted

    # ---------------------------------------------------------------- delta

    def delta_latest(self, drive_id: str) -> str:
        """
        A delta link representing "now", without enumerating the drive.

        This is how a drive is adopted. Without it the first delta walks the
        whole existing hierarchy and every file in the tenant arrives as a
        freshly created event.
        """
        return self.get_json(
            f"/drives/{drive_id}/root/delta", params={"token": "latest"}
        ).get("@odata.deltaLink") or ""

    def delta(
        self, drive_id: str, delta_link: str, max_pages: int = 3
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Fetch what changed since `delta_link`, and the link to use next time.

        An absent or aged-out link yields no changes and a fresh "now" link -
        deliberately, since re-enumerating a whole drive would flood Brain with
        events for files that have sat there for years.
        """
        if not delta_link:
            return [], self.delta_latest(drive_id)

        items: List[Dict[str, Any]] = []
        url = delta_link

        try:
            for _ in range(max_pages):
                body = self.get_json(url)
                items.extend(body.get("value") or [])

                if body.get("@odata.deltaLink"):
                    return items, body["@odata.deltaLink"]
                url = body.get("@odata.nextLink") or ""
                if not url:
                    return items, delta_link
        except GraphError as e:
            if "resync required" not in str(e):
                raise
            log.warning("delta link for drive %s aged out, re-priming", drive_id)
            return [], self.delta_latest(drive_id)

        # More pages than we will walk inline. The nextLink is a valid cursor,
        # so the rest arrives on the next notification rather than being lost.
        log.info("drive %s has more changes pending", drive_id)
        return items, url
