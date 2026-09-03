"""
Thin client for the Office 365 Management Activity API.

This is the API that carries both of the event sources this feeder cares about:

  Audit.AzureActiveDirectory -> Entra ID sign-ins   (UserLoggedIn / UserLoginFailed)
  Audit.SharePoint           -> OneDrive downloads  (FileDownloaded / FileSyncDownloadedFull)

Microsoft Graph change notifications are NOT usable here: Graph has no
subscription for sign-in logs, and its drive subscriptions report item
*changes*, not downloads. The Management Activity API is webhook driven and its
subscriptions need to be (re)started periodically, which is what
`ensure_subscriptions` is for.

App registration needs the "Office 365 Management APIs" application permission
ActivityFeed.Read, with admin consent granted.
"""

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests

LOGIN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
RESOURCE = "https://manage.office.com"
SCOPE = RESOURCE + "/.default"

TS_FMT = "%Y-%m-%dT%H:%M:%S"

log = logging.getLogger("o365.mgmt")


class Office365Error(Exception):
    pass


def parse_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip().rstrip("Z")
    # audit records carry fractional seconds sometimes, sometimes not
    for fmt in (TS_FMT + ".%f", TS_FMT):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class Office365ManagementClient:
    """Token handling, subscription management and content retrieval."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        publisher_id: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 4,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        # optional, only affects which throttling bucket we land in
        self.publisher_id = publisher_id or tenant_id
        self.timeout = timeout
        self.max_retries = max_retries

        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._token_expiry = 0.0

    @property
    def feed_url(self) -> str:
        return f"{RESOURCE}/api/v1.0/{self.tenant_id}/activity/feed"

    # ------------------------------------------------------------------ auth

    def token(self, force: bool = False) -> str:
        with self._lock:
            if not force and self._token and time.time() < self._token_expiry:
                return self._token

            url = LOGIN_URL.format(tenant=self.tenant_id)
            try:
                resp = requests.post(
                    url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "scope": SCOPE,
                    },
                    timeout=self.timeout,
                )
            except requests.RequestException as e:
                raise Office365Error(f"token request failed: {e}") from e

            if resp.status_code != 200:
                raise Office365Error(
                    f"token request failed {resp.status_code}: {resp.text[:400]}"
                )

            body = resp.json()
            self._token = body["access_token"]
            # renew a minute early so in-flight requests don't race the expiry
            self._token_expiry = time.time() + float(body.get("expires_in", 3600)) - 60
            log.info("acquired management api token for tenant %s", self.tenant_id)
            return self._token

    # --------------------------------------------------------------- request

    def _request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        expected: Sequence[int] = (200,),
    ) -> requests.Response:
        params = dict(params or {})
        params.setdefault("PublisherIdentifier", self.publisher_id)

        force_token = False
        last_error: Optional[str] = None

        for attempt in range(self.max_retries + 1):
            backoff = min(2.0 ** attempt, 30.0)
            headers = {"Authorization": f"Bearer {self.token(force=force_token)}"}

            try:
                resp = requests.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                    timeout=self.timeout,
                )
            except requests.RequestException as e:
                last_error = str(e)
                log.warning("%s %s errored (%s), retrying", method, url, e)
                time.sleep(backoff)
                continue

            if resp.status_code in expected:
                return resp

            last_error = f"{resp.status_code}: {resp.text[:400]}"

            if resp.status_code == 401:
                # token might have been revoked early - one forced refresh
                force_token = True
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                wait = backoff
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = max(wait, float(retry_after))
                    except ValueError:
                        pass
                log.warning(
                    "%s %s throttled/failed (%s), waiting %.0fs",
                    method,
                    url,
                    resp.status_code,
                    wait,
                )
                time.sleep(wait)
                continue

            # anything else is a hard error, no point retrying
            break

        raise Office365Error(f"{method} {url} failed - {last_error}")

    # --------------------------------------------------------- subscriptions

    def list_subscriptions(self) -> List[Dict[str, Any]]:
        resp = self._request("GET", f"{self.feed_url}/subscriptions/list")
        return resp.json() or []

    def start_subscription(
        self,
        content_type: str,
        webhook_url: Optional[str] = None,
        auth_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Start (or re-enable) a subscription.

        If a webhook is supplied, Microsoft POSTs a validation notification to it
        *during this call* and expects a 200 within 5 seconds - the webserver has
        to already be reachable at `webhook_url` before this is called. The
        `auth_id` is what the service will send back as the Webhook-AuthID
        header, on that validation POST and on every later notification.
        """
        body = None
        if webhook_url:
            body = {
                "webhook": {
                    "address": webhook_url,
                    "authId": auth_id or "",
                    "expiration": "",
                }
            }

        resp = self._request(
            "POST",
            f"{self.feed_url}/subscriptions/start",
            params={"contentType": content_type},
            json_body=body,
        )
        return resp.json() or {}

    def stop_subscription(self, content_type: str) -> None:
        self._request(
            "POST",
            f"{self.feed_url}/subscriptions/stop",
            params={"contentType": content_type},
            expected=(200, 204),
        )

    def ensure_subscriptions(
        self,
        content_types: Sequence[str],
        webhook_url: str,
        auth_id: str,
    ) -> List[Tuple[str, str]]:
        """
        Bring every requested content type to "subscribed, webhook enabled".

        Returns the (content_type, action) pairs that were carried out, so the
        caller can log only real changes. A content type whose start call fails
        is logged and skipped; the rest are still brought up, and the next pass
        retries it.
        """
        subs = {}
        for sub in self.list_subscriptions():
            subs[str(sub.get("contentType", "")).lower()] = sub

        actions: List[Tuple[str, str]] = []

        for content_type in content_types:
            sub = subs.get(content_type.lower())
            status = str((sub or {}).get("status", "")).lower()
            webhook = (sub or {}).get("webhook") or {}
            webhook_status = str(webhook.get("status", "")).lower()

            if sub is None or status != "enabled":
                action = "start"
            elif not webhook:
                # subscription exists but is polling-only
                action = "attach-webhook"
            elif webhook.get("address") != webhook_url or (
                "authId" in webhook and str(webhook.get("authId") or "") != auth_id
            ):
                # neither the address nor the authId can be edited in place, the
                # subscription has to be stopped and started again
                action = "readdress"
            elif webhook_status and webhook_status != "enabled":
                # Microsoft disables webhooks that fail repeatedly; calling
                # start again re-validates and re-enables them
                action = "re-enable"
            else:
                continue

            try:
                if action == "readdress":
                    log.warning(
                        "%s webhook registered as %s, restarting it as %s",
                        content_type,
                        webhook.get("address"),
                        webhook_url,
                    )
                    self.stop_subscription(content_type)

                self.start_subscription(content_type, webhook_url, auth_id)
            except Office365Error as e:
                # one content type failing is not a reason to leave the others
                # unsubscribed, so log it and carry on to the next
                log.error("subscription %s (%s) failed: %s", content_type, action, e)
                continue

            log.info("subscription %s: %s", content_type, action)
            actions.append((content_type, action))

        return actions

    # -------------------------------------------------------------- content

    def fetch_content(self, content_uri: str) -> List[Dict[str, Any]]:
        """Retrieve the audit records inside one content blob."""
        resp = self._request("GET", content_uri)
        records = resp.json() or []
        if isinstance(records, dict):
            records = [records]
        return records
