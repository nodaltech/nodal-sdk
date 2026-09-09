# Office 365 Feeder

A Nodal SDK **feeder** that turns OneDrive and SharePoint file changes into
Cyberbrain events. It is a small Flask webserver, meant to run behind nginx,
that receives **Microsoft Graph change notifications**, fetches what changed,
and pushes it into Brain over the SDK's encrypted ZMQ channel.

The whole service is one path:

```
notification -> delta (what changed) -> map -> feeder.send -> 200
```

No queue, no seen-set. Each drive's delta link is the only cursor, and it is
what makes that path safe: Graph retries an undelivered notification for up to
four hours, and a retry after the cursor has advanced returns nothing to feed.
Duplicate delivery is free.

| Action | Description | Default weight |
|--------|-------------|----------------|
| created | `<drive> file created` | 0.15 |
| edited | `<drive> file edited` | 0.10 |
| deleted | `<drive> file deleted` | 0.30 |

`<drive>` is `OneDrive` or `SharePoint`.

## What this feed cannot see

**Reads.** Downloading or opening a file does not change it, so it fires no
change notification and appears in no delta. There is no way to get reads on
this transport — not by configuration, and not by adding code.

If read visibility is what you need, the only complete source is the unified
audit log via the Office 365 Management Activity API (`FileAccessed`,
`FileDownloaded`), at roughly 30 minutes behind. Graph's `itemActivity` feed
nominally has an `access` action, but it is poll-only, its latency is
undocumented, and in testing it did not surface downloads at all.

**Sign-ins.** Graph has no change notification subscription for sign-in logs —
[`auditLogs/signIns` is not a subscribable resource][resources] and
[supports neither delta nor notifications][signins].

[resources]: https://learn.microsoft.com/en-us/graph/change-notifications-overview#supported-resources
[signins]: https://learn.microsoft.com/en-us/graph/api/resources/signin

## Latency

Microsoft documents driveItem change notification delivery as **averaging under
one minute, with a maximum of six hours** ([latency table][latency]). That is an
average, not a bound. Delta itself — the fetch that follows each notification —
has no published latency figure at all.

So measure your own tenant rather than trusting either number:

```bash
./venv/bin/python diagnose.py you@yourtenant.com --latency
```

That creates one small probe file, times how long `delta` takes to report it,
and deletes it. The result is the floor; notification delivery sits on top.

[latency]: https://learn.microsoft.com/en-us/graph/change-notifications-overview#latency

## Device attribution

Brain requires every event to name a device, and Graph never tells us one — a
`driveItem` notification carries [no change detail at all][webhooks], and delta
names the user who touched an item but never where from. So every emitted event
carries the address in `DEVICE_IP`, defaulting to `10.0.1.11`. It is a
placeholder, not an observation: **all** file activity in the tenant shares it.

This example needs **no changes to the SDK**: `Event["device"]` stays required
and `EventBuilder` is used exactly as it ships.

Two consequences worth being deliberate about:

* **Point `DEVICE_IP` at an address that is not a real host.** Brain may request
  an IP-targeted mitigation against the device it sees on these events.
* **Per-device correlation is meaningless on this feed.** Every user's activity
  lands on one fabric node, so that node will look permanently busy. The useful
  correlation is the identity, which is per-user and accurate.

An internal address (RFC1918, CGNAT, loopback, link-local, and the v6
equivalents) keys as `RoutedInternal` — there is no MAC to key on for a cloud
feed and never will be. Anything else keys as `External`. `DEVICE_IP` is
required, and a missing, empty or malformed value stops the feeder at startup.

[webhooks]: https://learn.microsoft.com/en-us/onedrive/developer/rest-api/concepts/using-webhooks

## How it fits together

```
   Microsoft Graph ──POST notification──> nginx (TLS) ──> Flask webhook (loopback)
                                                                 │
                                     GET /drives/{id}/root/delta │ inline
                                                                 │ map -> EventBuilder
                                                                 ▼
                                                          feeder.send ──ZMQ (curve)──> Brain
   subscription thread ──> POST/PATCH /subscriptions
```

* **webhook** answers Graph's `validationToken` handshake, then does the real
  work inline and returns 200. Graph counts a notification delivered only on a
  2xx within 3 seconds, so the delta fetch is capped at `MAX_PAGES` pages;
  anything left over arrives on the next notification. A Graph failure returns
  503 so the notification is redelivered, with the cursor left where it was.
* **subscription thread** creates one subscription per watched drive and renews
  it a day before expiry, rebuilding any that Graph has dropped. At startup it
  first deletes any subscription pointing at our own `NOTIFICATION_URL`, so a
  restart inside a subscription's lifetime does not leave the old one live and
  get every change notified twice.
* **asyncio loop** sends nothing. It stays running because the SDK's curve
  authenticator is an asyncio task on it, and without a live loop Brain cannot
  authenticate to the socket.

A drive is primed with `delta?token=latest` when first subscribed, so adopting
it does not replay its existing contents into Brain as a flood of "created"
events.

## Files

| File | Purpose |
|------|---------|
| `o365_feeder.py` | Entry point: config, webhook server, subscriptions, feeder |
| `o365_graph.py` | Graph client: auth, discovery, subscriptions, delta |
| `o365_events.py` | `driveItem` → Nodal `Event` mapping, buckets and weights |
| `selftest.py` | Offline end-to-end check against a fake Microsoft Graph |
| `diagnose.py` | Check a real tenant, and measure delta latency |
| `samples/drive_changes.json` | Example `delta` response for `--replay` / selftest |
| `deploy/nginx-o365-feeder.conf` | nginx server block |
| `deploy/o365-feeder.service` | systemd unit |

## Setup

### 1. Entra app registration

1. **App registrations → New registration**, single tenant.
2. **Certificates & secrets → New client secret**, keep the value.
3. **API permissions → Add a permission → Microsoft Graph → Application
   permissions** (not Delegated), add:
   * `Files.Read.All` — read drives and delta
   * `User.Read.All` — enumerate users, and resolve an actor's object id to a UPN
   * `Sites.Read.All` — only if you set `WATCH_SITES`

   Then **Grant admin consent** — a separate click, and without it every call
   returns 403 even though the permissions are listed.
4. Note the **Directory (tenant) ID** and **Application (client) ID**.

`Files.Read.All` is tenant-wide read access to every file in the organisation.
Treat the client secret accordingly.

Verify consent actually applied — `diagnose.py` prints the token's `roles` claim,
which is the only real proof:

```bash
./venv/bin/python diagnose.py you@yourtenant.com
```

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

Fill in `o365_feeder.yaml` (see `o365_feeder.yaml.example`):

| Key | Notes |
|-----|-------|
| `COMPONENT_NAME` / `COMPONENT_TOKEN` | Must match the component configured in your ghost |
| `COMPONENT_IP` / `LISTEN_PORT` | Where Brain connects *in* to this feeder |
| `GHOST_URL` | `https://<ghost fqdn>/api/components/handshake` |
| `TENANT_ID` / `CLIENT_ID` / `CLIENT_SECRET` | From step 1 |
| `NOTIFICATION_URL` | The **public HTTPS** URL nginx serves, e.g. `https://o365-feed.example.com/webhook/o365` |
| `WEBHOOK_PATH` / `WEBHOOK_HOST` / `WEBHOOK_PORT` | Local bind, keep on loopback behind nginx |
| `CLIENT_STATE` | Random secret. Graph echoes it on every notification and the feeder ignores anything else |
| `WATCH_USERS` | OneDrive: list of UPNs, or `["*"]` for every enabled user, or `[]` for none |
| `WATCH_SITES` | SharePoint: list of site ids/paths, or `["*"]`, or `[]` |
| `MAX_DRIVES` | One drive is one subscription, so `["*"]` on a 5,000-seat tenant means 5,000 of them — raise this deliberately |
| `DEVICE_IP` | Stand-in device on every event. Required. See *Device attribution* — do not point it at a real host |
| `MAX_PAGES` | Delta pages fetched per notification. Bounds how long the webhook holds Graph's 3-second budget |

Subscription lifetime (3 days), the renewal margin (1 day) and the maintenance
interval (5 minutes) are constants in `o365_feeder.py` — there is no reason to
tune them.

The config file holds two secrets — keep it `chmod 600` and owned by the service
user. It is in `.gitignore` for that reason.

### 4. nginx

```bash
sudo cp deploy/nginx-o365-feeder.conf /etc/nginx/sites-available/o365-feeder
sudo ln -s /etc/nginx/sites-available/o365-feeder /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Adjust `server_name`, certificate paths and the upstream port. Microsoft
requires a publicly trusted certificate: a self-signed cert makes the validation
handshake fail with no useful error on the Microsoft side.

Microsoft publishes the [IP ranges Graph delivers from][ips] if you want to
narrow the firewall, but `CLIENT_STATE` is the actual authentication.

[ips]: https://learn.microsoft.com/en-us/office365/enterprise/additional-office365-ip-addresses-and-urls

### 5. Run

```bash
sudo cp deploy/o365-feeder.service /etc/systemd/system/
sudo systemctl enable --now o365-feeder
journalctl -u o365-feeder -f
```

On startup you should see the handshake with ghost, an
`events will be keyed on device ...` line confirming `DEVICE_IP`, then
`watching N drive(s)`, then a pair of `answered graph endpoint validation
handshake` / `subscribed drive ...` lines per drive — that pair means the round
trip through nginx worked. A status line lands every 60 seconds with drive,
subscription, notification, change and event counts.

## Event mapping

Every event carries the actor's user principal name as its identity
(`set_identity(upn, "office365")`) plus the configured `DEVICE_IP` as its device
and `device_ip`. Identity is the key that carries real information.

Identity comes from delta's `lastModifiedBy` (falling back to `createdBy`),
preferring `userPrincipalName`, then `email`, then a cached `/users/{id}` lookup
on the object id, then the display name. The display name is a poor key — not
unique, and not what other feeds report — so it is a last resort, and an item
with no identifiable actor is skipped rather than fed with nothing to correlate
on.

Timestamps come from `lastModifiedDateTime`, not ingestion time. Notifications
average under a minute but can lag far longer, and using ingestion time would
bunch unrelated activity together at the wrong moment.

### Inferring the action

`delta` reports each item's *latest state*, not each change — an item renamed
twice appears once, with its final name. So the action is inferred:

* a `deleted` facet → **deleted**
* `createdDateTime == lastModifiedDateTime` → **created**
* otherwise → **edited**

That is a heuristic, not a record: a rename or a move both read as an edit, and
a file created and then immediately edited reads as an edit. The drive root and
folder metadata churn are skipped; a folder *deletion* is kept, since that is
the interesting half.

Note that OneDrive for Business omits `name` on deleted items, so a deletion
event has an `item_id` and path but no `item_name`. That is Graph's behaviour,
not a mapping gap.

### Buckets and weights

Bucket choices follow the SDK's rule — the more you hash, the more buckets, and
the more influence the events have on case triggering. Every event buckets on
(description, user, item), so:

* One file touched repeatedly stays in one bucket and stays quiet.
* A user working through many distinct files piles up buckets fast.
* `delete` carries the most weight, because bulk deletion is the ransomware
  shape and it is the sharpest signal delta gives. `edit` carries least —
  ordinary work is mostly edits.

Tune the weights in `WEIGHTS` if your tenant is noisier or quieter than average;
they are the first thing to turn down if this feed starts driving cases on its
own.

Buckets come from the SDK's `hash_bucket`, which uses Python's string hash — that
is salted per process, so bucket values change on restart unless the seed is
pinned. The systemd unit sets `PYTHONHASHSEED=0`.

## Testing

`selftest.py` stands up a fake Microsoft Graph on loopback and walks the whole
path — token, discovery, stale-subscription cleanup, subscription create, the
`validationToken` handshake, notification, delta, mapping, redelivery,
authentication, subscription repair, device keying, and recovery after a Graph
failure:

```bash
./venv/bin/python selftest.py
```

`diagnose.py` runs against a **real** tenant: it prints the token's granted
roles, resolves the user's drive, and shows what delta reports. With `--latency`
it also measures how fast a change surfaces.

`--replay` maps a saved delta response to events:

```bash
./venv/bin/python o365_feeder.py --replay samples/drive_changes.json
```

`--dry-run` runs the real thing against your tenant — webhook, subscriptions and
all — but logs events instead of sending them to Brain.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `subscription for drive ... failed` mentioning validation | Graph's `validationToken` POST is not reaching the feeder. Check `NOTIFICATION_URL` against nginx's `server_name` and location, and the certificate chain. Self-signed will not work |
| Subscriptions created, but no notifications | Normal until something *changes* in a watched drive. A read fires nothing — see *What this feed cannot see*. Confirm with the status line that `subscribed` equals `drives` |
| No events after you downloaded files | Expected. Downloads are invisible to this transport. Edit or create a file to test it |
| `notification for unknown subscription` | A subscription outlived the process that made it. Startup deletes any pointing at our own `NOTIFICATION_URL`, so this clears itself unless `NOTIFICATION_URL` changed |
| `rejected notification ...: bad clientState` | `CLIENT_STATE` changed after the subscriptions were created. Graph echoes the value recorded at subscription time; restart to recreate them |
| `delta link for drive ... aged out, re-priming` | Graph returned 410. The feeder re-primes to "now" rather than re-enumerating, so changes in the gap are lost by design — re-enumerating would flood Brain with events for old files |
| `drive ... has more changes pending` | A burst bigger than `MAX_PAGES` pages. The rest arrives on the next notification; raise `MAX_PAGES` if constant, but watch the 3-second budget |
| `token request failed 401` | Wrong client secret, or admin consent was never granted |
| Identity is a display name instead of a UPN | Graph gave an actor with no UPN, no email and an id that would not resolve. Check `User.Read.All` is consented |
| Brain opened a case against `10.0.1.11` | Working as configured — every event shares that device, so it will look busy. See *Device attribution* |
| Feeder exits at startup with a `ValueError` about `DEVICE_IP` | It is missing, empty or not a valid IP. Deliberate: it is required |
| `Feeder 'office365' not connected to brain...` | The SDK could not reach Brain; check `COMPONENT_IP`/`LISTEN_PORT` are what ghost has and that Brain can dial in |
