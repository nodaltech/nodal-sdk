"""
Thin Microsoft Graph client for the Office 365 feeder.

Covers exactly what the feeder needs:

  auth        client credentials token for https://graph.microsoft.com
  discovery   which drives to watch (user OneDrives, SharePoint libraries)
  activities  a drive's recent itemActivity feed - the whole event source

Why Graph and not the Office 365 Management Activity API: latency. Management
API notifications trail the activity itself by roughly half an hour, because
they only fire once a content blob is sealed. That is fine for an audit trail
and useless to a realtime system.

Why polling and not Graph change notifications: reads. Reading a file does not
change it, so a file access fires no change notification - the only way to see
one is to ask. `/drives/{id}/activities` is where Graph keeps them, and it is a
poll by construction: the endpoint accepts no OData parameters, so it cannot be
filtered by time, has no delta, and offers no subscription. The caller polls it
and tracks how far it has got.

App registration needs the Microsoft Graph *application* permissions
`Files.Read.All` (or `Sites.Read.All`) and `User.Read.All`, with admin consent.
"""

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Sequence

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

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class GraphClient:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        timeout: float = 20.0,
        max_retries: int = 2,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.max_retries = max_retries

        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._token_expiry = 0.0

        # user object id -> UPN. Graph gives an actor's id and display name but
        # not always their UPN, and identity is the only key these events have,
        # so it is worth one lookup per user - cached for the process.
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

            if resp.status_code == 401 and not force_token:
                # the token may have been revoked early; one forced refresh
                force_token = True
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                # SharePoint throttles on a resource budget per site collection,
                # so Retry-After is the only number worth obeying here
                wait = min(2.0 ** attempt, 5.0)
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = max(wait, min(float(retry_after), 30.0))
                    except ValueError:
                        pass
                log.warning("%s %s throttled (%s), waiting %.0fs", method, url, resp.status_code, wait)
                time.sleep(wait)
                continue

            # anything else is a hard error, retrying will not help
            break

        raise GraphError(f"{method} {url} failed - {last_error}")

    def get_json(self, url: str, **kwargs: Any) -> Dict[str, Any]:
        return self.request("GET", url, **kwargs).json() or {}

    def paged(self, url: str, max_pages: int = 2, **kwargs: Any) -> Iterator[Dict[str, Any]]:
        """Walk @odata.nextLink, stopping after max_pages so a poll stays bounded."""
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
            body = self.get_json(f"/users/{user_id}", params={"$select": "userPrincipalName"})
            upn = body.get("userPrincipalName")
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
        tenant-wide drive listing in Graph, so this is one call per user - which
        is why it runs on its own slow timer, not on the poll interval.
        """
        if list(upns) == ["*"]:
            users = self.paged(
                "/users",
                max_pages=50,
                params={"$select": "id,userPrincipalName,accountEnabled", "$top": 999},
            )
            wanted = [
                u["userPrincipalName"]
                for u in users
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
                    f"/users/{upn}/drive", params={"$select": "id,driveType,webUrl,owner"}
                )
            except GraphError as e:
                # extremely common: users who have never opened OneDrive have no
                # drive provisioned yet, which is a 404, not a problem
                log.debug("no drive for %s: %s", upn, e)
                continue
            if drive.get("id"):
                drive["_owner_upn"] = upn
                drives.append(drive)

        return drives

    def site_drives(self, sites: Sequence[str], limit: int) -> List[Dict[str, Any]]:
        """Resolve the document libraries of each requested SharePoint site."""
        if list(sites) == ["*"]:
            found = self.paged("/sites", max_pages=20, params={"search": "*", "$select": "id"})
            wanted = [s["id"] for s in found if s.get("id")]
        else:
            wanted = [s for s in sites if s]

        drives = []
        for site in wanted:
            if len(drives) >= limit:
                log.warning("stopping site drive discovery at MAX_DRIVES=%d", limit)
                break
            try:
                for drive in self.paged(
                    f"/sites/{site}/drives",
                    max_pages=5,
                    params={"$select": "id,driveType,name,webUrl,owner"},
                ):
                    if drive.get("id"):
                        drive["_site"] = site
                        drives.append(drive)
            except GraphError as e:
                log.error("could not list drives for site %s: %s", site, e)

        return drives

    # ------------------------------------------------------------ activities

    def activities(self, drive_id: str, max_pages: int = 2) -> List[Dict[str, Any]]:
        """
        The drive's recent itemActivity feed - the feeder's only event source.

        Returns newest-first in practice, but nothing documents that, so the
        caller filters rather than assuming an order.
        """
        return list(self.paged(f"/drives/{drive_id}/activities", max_pages=max_pages))
