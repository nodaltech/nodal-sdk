# Office 365 Feeder

A Nodal SDK **feeder** that turns Office 365 file activity into Cyberbrain
events. It polls the [itemActivity][activities] feed of every watched OneDrive
and SharePoint drive over Microsoft Graph, and pushes what it finds into Brain
over the SDK's encrypted ZMQ channel.

The whole service is one loop:

```
every POLL_INTERVAL_SECS, for each drive:
    GET /drives/{id}/activities -> keep what is newer than the cursor -> send
```

**No inbound endpoint.** No webhook, no nginx, no TLS certificate, no public
DNS name, no subscriptions to create or renew. The feeder makes outbound calls
only.

**No seen-set.** Each drive's cursor is a single float — the newest
`activityDateTime` already fed — and an activity is fed when it is strictly
newer than that. Re-reading the same page is harmless, which is exactly why no
set of seen ids is needed.

| Action | Description | Default weight |
|--------|-------------|----------------|
| `access` | `<drive> file accessed` | 0.25 |
| `create` | `<drive> file created` | 0.15 |
| `edit` | `<drive> file edited` | 0.10 |
| `delete` | `<drive> file deleted` | 0.30 |
| `move` | `<drive> file moved` | 0.15 |
| `rename` | `<drive> file renamed` | 0.15 |
| `share` | `<drive> file shared` | 0.40 |

`<drive>` is `OneDrive` or `SharePoint`. Everything else Graph reports —
`comment`, `mention`, `version`, `restore` — is dropped as noise.

## Why polling, and why Graph

**Reads are the point.** Reading a file does not change it, so a file access
fires no Graph change notification — asking is the only way to see one. The
activities feed is where Graph keeps them, and it is a poll by construction: the
endpoint [accepts no OData parameters][activities], so it cannot be filtered by
time, has no delta, and has no subscription. A 20 second sweep is the trade for
seeing reads at all.

**Graph rather than the audit log, for latency.** Office 365 Management Activity
API notifications trail the activity itself by roughly half an hour, because
they only fire once a content blob is sealed. That is fine for an audit trail
and useless to a realtime system.

Three things this costs, worth understanding before you deploy:

**1. Sign-ins are gone.** Graph has no subscription *or* usable low-latency read
for sign-in logs — [`auditLogs/signIns` is not a subscribable resource][resources]
and [supports neither delta nor change notifications][signins]. If you need
sign-in events they have to come from somewhere else.

**2. There is no real device.** Graph reports no client address for file activity
— `itemActivity` names the user who acted but never the machine or address they
did it from. The actor's identity is the only key that means anything here, and
it is what Brain correlates on. Brain needs a device regardless, so a configured
stand-in address is attached to every event — see *Device attribution* below.

**3. Read latency is undocumented.** Microsoft publishes latency figures for
`driveItem` change notifications but **nothing** for the activities feed. Your
end-to-end latency is `20s + whatever lag the feed itself has`, and only the
second term is unknown. Measure it in your tenant before you rely on it:

```bash
# touch a file in a watched drive, then watch how long it takes to appear
./venv/bin/python o365_feeder.py --once -v
```

If the feed turns out to lag like the audit log, this feeder gains you nothing
over the Management API and you should know that before wiring it to Brain.

**Also verify the feed returns anything at all.** The Graph activity APIs have a
[history of returning empty results in some tenants][empty]. `--once` is the
one-command check.

[activities]: https://learn.microsoft.com/en-us/graph/api/itemactivity-list
[resources]: https://learn.microsoft.com/en-us/graph/change-notifications-overview#supported-resources
[signins]: https://learn.microsoft.com/en-us/graph/api/resources/signin
[empty]: https://learn.microsoft.com/en-us/answers/questions/732985/onedrive-for-business-graph-api-getactivitiesbyint

## Device attribution

Brain requires every event to name a device, and Graph never tells us one. So
every emitted event carries the address in `DEVICE_IP`, defaulting to
`10.0.1.11`. It is a placeholder, not an observation — **all** file activity in
the tenant shares it, whoever acted and wherever they were, because Graph does
not report where they were.

This example needs **no changes to the SDK**: `Event["device"]` stays required
and `EventBuilder` is used exactly as it ships.

Two consequences worth being deliberate about:

* **Point `DEVICE_IP` at an address that is not a real host.** Brain may request
  an IP-targeted mitigation against the device it sees on these events, and it
  would be pointing at whatever is genuinely at that address.
* **Per-device correlation is meaningless on this feed.** Every user's activity
  lands on one fabric node, so that node will look permanently busy. The useful
  correlation is the identity, which is per-user and accurate.

An internal address (RFC1918, CGNAT, loopback, link-local, and the v6
equivalents) keys as `RoutedInternal` — there is no MAC to key on for a cloud
feed and never will be. Anything else keys as `External`.

`DEVICE_IP` is **required**, and a missing, empty or malformed value stops the
feeder at startup rather than at the first event.

## How it fits together

```
   poll thread ──┬─> GET /drives/{a}/activities ─┐
    every 20s    ├─> GET /drives/{b}/activities ─┤ cursor filter
   (POLL_WORKERS)└─> GET /drives/{c}/activities ─┘ map -> EventBuilder
                                                        │
                                                        ▼
                                              feeder.send ──ZMQ (curve)──> Brain

   discovery thread ──> GET /users, GET /users/{id}/drive   (hourly)
```

* **poll thread** sweeps every drive through a small thread pool, then sends
  everything the workers hand back. It is the only thread that sends, which is
  why there is no lock around the socket — the SDK's PUB socket is not thread
  safe, so workers return events rather than sending them.
* **discovery thread** refreshes the drive list hourly, so new users and new
  sites get picked up. `WATCH_USERS: ["*"]` costs one Graph call per user, which
  has no business happening on the poll interval.
* **asyncio loop** sends nothing. It stays running because the SDK's curve
  authenticator is an asyncio task on it, and without a live loop Brain cannot
  authenticate to the socket.

A drive joining the feed has its cursor primed to **now**, so adopting it does
not replay its retained activity history into Brain as a flood of events.

## Cost

This is the one number to think about before setting `WATCH_USERS: ["*"]`.

One sweep is **one Graph call per drive**, every `POLL_INTERVAL_SECS`, whether
or not anything happened. At the 20 second default:

| Drives | Calls/min | Calls/day |
|--------|-----------|-----------|
| 10 | 30 | 43,200 |
| 100 | 300 | 432,000 |
| 200 (default cap) | 600 | 864,000 |

SharePoint throttles on a [resource-unit budget per site collection][throttling]
rather than a flat request rate, so there is no single number to stay under —
but this is a sustained load that never goes quiet, and it scales linearly with
drive count. `MAX_DRIVES` defaults to 200 as a deliberate brake. If you need
wider coverage, raise `POLL_INTERVAL_SECS` before raising `MAX_DRIVES`.

One sweep must also *finish* inside one interval. With 200 drives on 8 workers
that is 25 sequential calls per worker in 20 seconds — tight. The feeder logs a
warning when a sweep overruns; raise `POLL_WORKERS` when you see it.

[throttling]: https://learn.microsoft.com/en-us/sharepoint/dev/general-development/how-to-avoid-getting-throttled-or-blocked-in-sharepoint-online

## Files

| File | Purpose |
|------|---------|
| `o365_feeder.py` | Entry point: config, poll loop, discovery, feeder |
| `o365_graph.py` | Graph client: auth, discovery, activities |
| `o365_events.py` | `itemActivity` → Nodal `Event` mapping, buckets and weights |
| `selftest.py` | Offline end-to-end check against a fake Microsoft Graph |
| `samples/drive_activities.json` | Example activities response for `--replay` / selftest |
| `deploy/o365-feeder.service` | systemd unit |

## Setup

### 1. Entra app registration

In the Entra portal, register an application and give it read access to files:

1. **App registrations → New registration**, single tenant.
2. **Certificates & secrets → New client secret**, keep the value.
3. **API permissions → Add a permission → Microsoft Graph → Application
   permissions**, add:
   * `Files.Read.All` — read drives and their activity feeds
   * `User.Read.All` — enumerate users, and resolve an actor's object id to a UPN
   * `Sites.Read.All` — only if you set `WATCH_SITES`

   Then **Grant admin consent**.
4. Note the **Directory (tenant) ID** and **Application (client) ID**.

These are read-only permissions, but `Files.Read.All` is tenant-wide read access
to every file in the organisation. Treat the client secret accordingly.

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
| `WATCH_USERS` | OneDrive: list of UPNs, or `["*"]` for every enabled user, or `[]` for none |
| `WATCH_SITES` | SharePoint: list of site ids/paths, or `["*"]`, or `[]` |
| `MAX_DRIVES` | Polling brake — see *Cost* above before raising it |
| `POLL_INTERVAL_SECS` | Sweep interval, 20s by default |
| `POLL_WORKERS` | Drives polled in parallel. One sweep must finish inside one interval |
| `DISCOVER_INTERVAL_SECS` | How often the drive list is refreshed, hourly by default |
| `DEVICE_IP` | Stand-in device on every event, `10.0.1.11` by default. Required. See *Device attribution* — do not point it at a real host |

The config file holds a client secret — keep it `chmod 600` and owned by the
service user. It is in `.gitignore` for that reason.

### 4. Run

```bash
sudo cp deploy/o365-feeder.service /etc/systemd/system/
sudo systemctl enable --now o365-feeder
journalctl -u o365-feeder -f
```

On startup you should see the handshake with ghost, a
`events will be keyed on device ...` line confirming `DEVICE_IP`, then
`discovered N new drive(s), watching N`, then a `sweep fed N event(s)` line
whenever activity turns up. A status line lands every 60 seconds with drive,
sweep, activity, event and error counts.

Nothing needs to be exposed. There is no listening port other than
`LISTEN_PORT`, which is Brain dialling in.

## Event mapping

Every event carries the actor's user principal name as its identity
(`set_identity(upn, "office365")`) plus the configured `DEVICE_IP` as its device
and `device_ip`. Identity is the key that carries real information — see *Device
attribution* above.

Identity comes from the activity's `actor`, preferring `userPrincipalName`, then
`email`, then a cached `/users/{id}` lookup on the object id, then the display
name. The display name is a poor key — not unique, and not what other feeds
report — so it is a last resort, and an actor with none of these is skipped
rather than fed with nothing to correlate on.

Metadata carries the useful fields as strings: item id, name, path, web URL,
size, MIME type, the action, the activity id, the drive and its owner, and the
actor's display name.

Timestamps come from Microsoft's `activityDateTime`, not ingestion time. The
feed lags by an unspecified amount, and using ingestion time would bunch
unrelated activity together at the wrong moment.

Both the v1.0 and beta activity shapes are accepted — v1.0 puts action keys at
the top level with `activityDateTime`, beta nests them under `action` with
`times.recordedTime`. Switching endpoints therefore cannot silently produce an
empty feed.

### Buckets and weights

Bucket choices follow the SDK's rule — the more you hash, the more buckets, and
the more influence the events have on case triggering. Events bucket on
(description, user, item), so:

* One file touched repeatedly stays in one bucket and stays quiet.
* A user working through many distinct files piles up buckets fast — which is
  the exfiltration shape worth catching.
* `share` carries the most weight: it is the only action that can hand data to
  someone outside the tenant. `delete` is next, because bulk deletion is the
  ransomware shape. `edit` carries least — ordinary work is mostly edits.

**When `driveItem` is not expanded**, the event buckets on the user alone
instead. Drive-wide activity listings do not always include the item, and there
is no `$expand` to ask with. Bucketing on the activity id instead would give
every single read its own bucket and drive cases on ordinary work, so this
deliberately under-counts — the safe direction.

Tune the weights in `WEIGHTS` if your tenant is noisier or quieter than average;
they are the first thing to turn down if this feed starts driving cases on its
own.

Buckets come from the SDK's `hash_bucket`, which uses Python's string hash — that
is salted per process, so bucket values change on restart unless the seed is
pinned. The systemd unit sets `PYTHONHASHSEED=0` to keep them stable.

### Adding another action

Add an entry to `ACTIONS` in `o365_events.py` with a label and weight key, and a
default in `DEFAULT_WEIGHTS`. Any [`itemActionSet`][actionset] key works with no
other change.

[actionset]: https://learn.microsoft.com/en-us/graph/api/resources/itemactionset

## Testing

`selftest.py` stands up a fake Microsoft Graph on loopback and walks the whole
path — token, drive discovery, cursor priming, polling, both activity shapes,
re-poll idempotency, bucketing, identity resolution, device keying and behaviour
when Graph is down:

```bash
./venv/bin/python selftest.py
```

`--once` runs against your **real** tenant: it discovers drives, takes whatever
the activity feed currently retains, prints the events and exits without
sending anything. This is the first thing to run on a new tenant — it answers
both "does the activity feed return anything here" and "what will this look
like":

```bash
./venv/bin/python o365_feeder.py --once
```

`--replay` maps a saved activities response to events, which is the quickest way
to check a mapping change:

```bash
./venv/bin/python o365_feeder.py --replay samples/drive_activities.json
```

`--dry-run` polls for real on the normal interval but logs events instead of
sending them to Brain. Useful for confirming volume before wiring it up.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `--once` prints 0 events | The activity feed is returning nothing for these drives. Confirm `Files.Read.All` is consented, then check whether the API returns data for your tenant at all — see *Why polling, and why Graph* |
| `discovered 0 new drive(s)` | No drive matched. `WATCH_USERS` UPNs must be exact; users who have never opened OneDrive have no drive provisioned (a 404, logged at debug — rerun with `-v`) |
| `sweep of N drive(s) took ...s, longer than the 20s interval` | Too many drives for `POLL_WORKERS`, or Graph is slow. Raise `POLL_WORKERS`, or raise `POLL_INTERVAL_SECS` |
| `could not poll drive ...` with 429 | Throttled. The client obeys `Retry-After`; if it is constant, you are sweeping too many drives too often — see *Cost* |
| `token request failed 401` | Wrong client secret, or admin consent was never granted |
| Events arrive with a display name instead of a UPN as the identity | Graph gave an actor with no UPN, no email and an id that would not resolve. Check `User.Read.All` is consented — without it every actor falls back to a display name, which correlates poorly |
| Events appear minutes after the activity | Expected, and the part that is out of the feeder's hands. `20s` is the sweep; the rest is the activity feed's own lag, which Microsoft does not document |
| A burst of events on restart | Should not happen — a drive's cursor is primed to now on discovery. If it does, the cursor is being reset; note the cursor is in memory only, so a restart begins from "now" and activity during the downtime is not backfilled |
| Brain opened a case against `10.0.1.11` | Working as configured — every event in this feed shares that device, so it will look busy. Read *Device attribution*; the per-user signal is the identity |
| Feeder exits at startup with a `ValueError` about `DEVICE_IP` | It is missing, empty or not a valid IP. Deliberate: it is required, and failing later would be worse |
| `Feeder 'office365' not connected to brain...` | The SDK could not reach Brain; check `COMPONENT_IP`/`LISTEN_PORT` are what ghost has and that Brain can dial in |
