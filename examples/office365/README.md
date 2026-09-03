# Office 365 Feeder

A Nodal SDK **feeder** that turns Office 365 activity into Cyberbrain events. It
is a small Flask webserver, meant to run behind nginx, that receives Office 365
webhook notifications, pulls the referenced audit records, and pushes them into
Brain over the SDK's encrypted ZMQ channel.

Two event sources to start with:

| Source | Content type | Operations |
|--------|--------------|------------|
| Entra ID logins | `Audit.AzureActiveDirectory` | `UserLoggedIn`, `UserLoginFailed` |
| OneDrive file downloads | `Audit.SharePoint` | `FileDownloaded`, `FileSyncDownloadedFull` |

Subscriptions are (re)started automatically: the feeder checks them every few
minutes and repairs anything Microsoft has dropped or disabled, so there is no
manual subscription step and no expiry to babysit.

The feed is live only. Nothing is replayed or swept up after the fact — if a
notification never arrives, or its content cannot be fetched while it is in
hand, those records are dropped rather than turning up later as stale events.

## Why the Management Activity API and not Graph

Microsoft Graph change notifications cannot carry either of these signals: Graph
has no subscription for sign-in logs, and its drive subscriptions report item
*changes*, not downloads. Both live in the unified audit log, which is exposed by
the **Office 365 Management Activity API** — a webhook-driven API whose
subscriptions have to be started (and periodically re-validated) by the
subscriber. That is the API this feeder speaks.

## How it fits together

```
   Microsoft 365 ──POST notification──> nginx (TLS) ──> Flask webhook (loopback)
                                                              │ blob queue
                                        content workers <─────┘
                                              │ GET contentUri (audit records)
                                              │ map -> EventBuilder
                                              ▼ event queue
                                        asyncio loop ──ZMQ (curve)──> Brain
   subscription thread ──> subscriptions/list, subscriptions/start
```

* **webhook** answers Microsoft's validation handshake and queues notifications.
  It does no work of its own — Microsoft expects a 200 within 5 seconds.
* **content workers** fetch each content blob and map audit records to events.
  Microsoft redelivers notifications, so records are deduplicated by audit `Id`.
* **subscription thread** keeps subscriptions enabled, restarting any that
  Microsoft has dropped, disabled or that point at the wrong address.
* **asyncio loop** owns the ZMQ socket and is the only thread that sends.

A content blob that fails to fetch is retried a few times in place, then given
up on with a log line — deliberately, since re-reading it later would push stale
activity into Brain. Webhook delivery is best effort on Microsoft's side, so
treat this as a live signal, not an audit-complete one; the unified audit log
remains the record of truth.

## Files

| File | Purpose |
|------|---------|
| `o365_feeder.py` | Entry point: config, webhook server, queues, feeder loop |
| `o365_mgmt.py` | Management Activity API client: auth, subscriptions, content |
| `o365_events.py` | Audit record → Nodal `Event` mapping, buckets and weights |
| `selftest.py` | Offline end-to-end check against a fake Microsoft API |
| `samples/audit_records.json` | Example audit records for `--replay` / selftest |
| `deploy/nginx-o365-feeder.conf` | nginx server block |
| `deploy/o365-feeder.service` | systemd unit |

## Setup

### 1. Entra app registration

In the Entra portal, register an application and give it access to the audit log:

1. **App registrations → New registration**, single tenant.
2. **Certificates & secrets → New client secret**, keep the value.
3. **API permissions → Add a permission → Office 365 Management APIs →
   Application permissions → `ActivityFeed.Read`**, then **Grant admin consent**.
4. Note the **Directory (tenant) ID** and **Application (client) ID**.

Unified audit logging must be turned on for the tenant (it is on by default in
current tenants; `Get-AdminAuditLogConfig` in Exchange Online PowerShell will
tell you).

### 2. Install

```bash
git clone <this repo> /opt/o365-feeder && cd /opt/o365-feeder
python3 -m venv venv
./venv/bin/pip install -e ../..        # the nodal-sdk itself
./venv/bin/pip install -r requirements.txt
```

### 3. Configure

Running the feeder once with no config writes a commented template and exits:

```bash
./venv/bin/python o365_feeder.py
```

Fill in `o365_feeder.yaml` (see `o365_feeder.yaml.example`). The keys that matter
most:

| Key | Notes |
|-----|-------|
| `COMPONENT_NAME` / `COMPONENT_TOKEN` | Must match the component configured in your ghost |
| `COMPONENT_IP` / `LISTEN_PORT` | Where Brain connects *in* to this feeder |
| `GHOST_URL` | `https://<ghost fqdn>/api/components/handshake` |
| `TENANT_ID` / `CLIENT_ID` / `CLIENT_SECRET` | From step 1 |
| `WEBHOOK_URL` | The **public HTTPS** URL nginx serves, e.g. `https://o365-feed.example.com/webhook/o365` |
| `WEBHOOK_PATH` / `WEBHOOK_HOST` / `WEBHOOK_PORT` | Local bind, keep on loopback behind nginx |
| `WEBHOOK_AUTH_ID` | Random secret. Microsoft returns it in the `Authorization` header of every notification; the feeder rejects anything else |
| `INTERNAL_CIDRS` | Which client IPs count as internal (see *Device keying*) |

The config file holds two secrets — keep it `chmod 600` and owned by the service
user. It is in `.gitignore` for that reason.

### 4. nginx

Copy `deploy/nginx-o365-feeder.conf`, adjust `server_name`, certificate paths and
the upstream port, then reload. Microsoft requires a publicly trusted
certificate: a self-signed cert makes the validation handshake fail with no
useful error on the Microsoft side.

```bash
sudo cp deploy/nginx-o365-feeder.conf /etc/nginx/sites-available/o365-feeder
sudo ln -s /etc/nginx/sites-available/o365-feeder /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Microsoft publishes no stable source IP range for these notifications, so the
`WEBHOOK_AUTH_ID` check is the authentication — not an nginx allowlist.

### 5. Run

```bash
sudo cp deploy/o365-feeder.service /etc/systemd/system/
sudo systemctl enable --now o365-feeder
journalctl -u o365-feeder -f
```

On startup you should see the handshake with ghost, then one
`subscription <content type>: start` line per content type, each followed by
`answered webhook validation handshake` — that pair means the round trip through
nginx worked. Events start flowing once Microsoft seals its first content blob,
which typically lags the activity itself by a few minutes (occasionally up to
30 for `Audit.SharePoint`).

`GET /healthz` reports queue depths and running counts of notifications, blobs,
records and events sent. nginx denies it by default.

## Event mapping

Every event carries the user principal name as its identity
(`set_identity(upn, "office365")`), which is what lets Brain line these up with
the rest of the fabric and request identity mitigations.

| Operation | Description | Default weight | Hash bucket |
|-----------|-------------|----------------|-------------|
| `UserLoggedIn` | `Entra ID sign-in succeeded` | 0.05 | description + user |
| `UserLoginFailed` | `Entra ID sign-in failed` | 0.35 | description + device + user |
| `FileDownloaded` | `OneDrive file downloaded` | 0.25 | description + user + file |
| `FileSyncDownloadedFull` | `OneDrive file sync download` | 0.15 | description + user + file |

Metadata carries the useful record fields as strings — result status, logon
error, user agent, device compliance, file name/path/size, site URL — plus
`audit_id`, so any event can be traced back to the original audit record.

Timestamps come from the record's `CreationTime`, not ingestion time: webhook
delivery lags by minutes, and using ingestion time would bunch unrelated
activity together at the wrong moment.

### Buckets and weights

Bucket choices follow the SDK's rule — the more you hash, the more buckets, and
the more influence the events have on case triggering:

* **Successful sign-ins** are constant background noise, so every sign-in for a
  user shares one bucket and carries a very low weight.
* **Failed sign-ins** get a bucket per (user, source IP), so a spray against one
  account, or one IP working through many accounts, accumulates quickly.
* **Downloads** get a bucket per (user, file). One file fetched repeatedly stays
  quiet, while a user pulling many distinct files piles up buckets fast — which
  is the exfiltration shape worth catching.

Tune the weights in `WEIGHTS` if your tenant is noisier or quieter than average;
they are the first thing to turn down if this feed starts driving cases on its
own.

Buckets come from the SDK's `hash_bucket`, which uses Python's string hash — that
is salted per process, so bucket values change on restart unless the seed is
pinned. The systemd unit sets `PYTHONHASHSEED=0` to keep them stable.

### Device keying

Office 365 audit records have no MAC address, so the device key comes from the
client IP:

* inside `INTERNAL_CIDRS` → `{"RoutedInternal": ip}` — internal, but reached
  Microsoft through a router, so no MAC is knowable
* anything else → `{"External": ip}`

Classification uses only the configured CIDRs. If your users egress through
corporate NAT, add those public egress addresses to `INTERNAL_CIDRS` so their
sign-ins land on the internal side of the fabric. Records with no usable client
IP (some service principal sign-ins) are skipped, since there is no device to
attach them to.

### Adding another source

Both extension points live in `o365_events.py`: add the operation to `SIGNIN_OPS`
or `DOWNLOAD_OPS` (or write a sibling `_map_*` method and dispatch to it from
`map_record`), and add a default weight. If the new operation lives in a content
type that is not subscribed yet — `Audit.Exchange`, `Audit.General`,
`DLP.All` — add it to `CONTENT_TYPES` and the maintenance thread will subscribe
on its next pass.

## Testing without a tenant

`selftest.py` stands up a fake Management Activity API on loopback and walks the
whole path — token, subscription start, validation handshake, notification,
content fetch, mapping, dedup and subscription repair:

```bash
./venv/bin/python selftest.py
```

`--replay` maps a JSON file of audit records to events and prints them, which is
the quickest way to check a mapping change or to see what a real record from your
tenant will turn into:

```bash
./venv/bin/python o365_feeder.py --replay samples/audit_records.json
```

`--dry-run` runs the real thing against your tenant — webhook, subscriptions and
all — but logs events instead of sending them to Brain. Useful for confirming
volume and content before wiring it up.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `subscription ...: start` repeats every cycle | The validation POST is not reaching the feeder. Check `WEBHOOK_URL` against nginx's `server_name`/location, and the certificate chain |
| `rejected notification with bad Authorization header` | `WEBHOOK_AUTH_ID` changed after the subscription was created. Microsoft echoes the value recorded at subscription start; the feeder restarts the subscription when it notices the address or authId drifting, so this should clear itself within one `SUBSCRIBE_INTERVAL_SECS` |
| `token request failed 401` | Wrong client secret, or admin consent for `ActivityFeed.Read` was never granted |
| Subscriptions fine, no events | Normal for the first few minutes. If it persists, check `/healthz`: `records` climbing with `events` flat means the operations are being filtered — most often `ONEDRIVE_ONLY` dropping SharePoint downloads |
| `giving up on content ...` | The content blob could not be fetched after retries and its records are gone from this feed. Look for the Microsoft-side error just above it; the records are still in the unified audit log |
| `Feeder 'office365' not connected to brain...` | The SDK could not reach Brain; check `COMPONENT_IP`/`LISTEN_PORT` are what ghost has and that Brain can dial in |
