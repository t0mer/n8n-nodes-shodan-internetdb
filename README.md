# n8n-nodes-shodan-internetdb

[![npm](https://img.shields.io/npm/v/@t0mer/n8n-nodes-shodan-internetdb)](https://www.npmjs.com/package/@t0mer/n8n-nodes-shodan-internetdb)
[![CI](https://github.com/t0mer/n8n-nodes-shodan-internetdb/actions/workflows/ci.yml/badge.svg)](https://github.com/t0mer/n8n-nodes-shodan-internetdb/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An [n8n](https://n8n.io) community node package for **[Shodan InternetDB](https://internetdb.shodan.io)**, Shodan's free, keyless IP lookup service.

For a public IP address, InternetDB returns:

| Field | Example |
|---|---|
| `ports` | Open ports: `[22, 80, 443]` |
| `cpes` | Detected software as CPE 2.2 URIs: `cpe:/a:openbsd:openssh:7.4` |
| `hostnames` | Hostnames seen for the IP: `www.example.com` |
| `tags` | Labels such as `vpn`, `cdn`, `cloud`, `self-signed`, `eol-product` |
| `vulns` | Known CVE IDs: `CVE-2017-15906` |

The package has two nodes:

- **Shodan InternetDB**: look up one IP per item, or many IPs and CIDR ranges in one run. The output is shaped for downstream nodes, and the node can be used as an **AI Agent tool**.
- **Shodan InternetDB Trigger**: watches your IPs and ranges and fires **only when something changes**: new or closed ports, new or resolved CVEs, and tag, hostname, or CPE changes. Use it for attack-surface monitoring.

### How InternetDB differs from the full Shodan API

InternetDB is a lightweight, pre-computed snapshot:

- It needs **no API key** and **no account**.
- Data is refreshed about **once a week**. It is not a live scan.
- It has **no banners**, geolocation, ASN, or organisation data. It has much less detail than a full Shodan host lookup.
- It supports IP lookups only. There is no search, scanning, or alerting.

If you need banners, search, or on-demand scans, use the full Shodan API with an API key. This package deliberately covers InternetDB only.

## Usage terms

InternetDB is **free for non-commercial use**. **Commercial use requires a Shodan enterprise license.** See [internetdb.shodan.io](https://internetdb.shodan.io) for the current terms. You are responsible for complying with them.

## Installation

In a self-hosted n8n:

1. Go to **Settings → Community Nodes**.
2. Select **Install**.
3. Enter `@t0mer/n8n-nodes-shodan-internetdb` and confirm.

See n8n's [community nodes installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) for details. The package has no runtime dependencies.

## Credentials

**None.** InternetDB is keyless, so there is nothing to configure.

## Shodan InternetDB node

Resource: **IP**.

### Operations

| Operation | What it does |
|---|---|
| **Lookup** | Looks up one IP address per input item. |
| **Lookup Many** | Looks up a list of IPs and CIDR ranges in one run, such as `1.1.1.1, 8.8.8.0/30`. Addresses are de-duplicated, and output keeps the input order. |

**Lookup Many parameters**

| Parameter | Default | Description |
|---|---|---|
| Targets | | IPs and CIDR ranges separated by commas, spaces, or new lines. Supports expressions, for example `{{ $json.ips.join(',') }}`. |
| Run Once | `true` | Reads Targets from the first input item only and runs once, with all output paired to item 0. Turn it off to run a separate batch for every input item. |

### Output modes

| Output Mode | Items emitted per IP |
|---|---|
| **Host** (default) | One item with the host data and summary fields. |
| **Ports** | One item per open port: `{ ip, port, serviceName? }`. |
| **Vulnerabilities** | One item per CVE: `{ ip, cve }`. IPs with no CVEs emit nothing. |
| **Raw** | One item with the exact API response and no derived fields. |

In Host mode, `ports` are sorted ascending and `vulns` are sorted by CVE year, then number, so output is stable and easy to diff. `cpes`, `hostnames`, and `tags` keep the API order.

Host mode always includes `found`. With **Include Summary** on (the default), it also adds these fields:

```json
{
  "portCount": 4,
  "vulnCount": 1,
  "hasVulns": true,
  "hasEolProduct": false,
  "lookedUpAt": "2026-09-24T08:00:00.000Z",
  "source": "shodan-internetdb"
}
```

### Options

| Option | Default | Description |
|---|---|---|
| No Data Behavior | Return Empty Result | InternetDB has no data for the IP (HTTP 404). **Return Empty Result** emits the IP with empty arrays and `found: false`. **Skip** emits nothing. **Throw Error** fails the node. |
| Non-Public IP Behavior | Skip | Private, loopback, link-local, CGNAT, multicast, documentation, and reserved addresses are never sent to the API. **Skip** emits `{ ip, found: false, skipped: "non_public" }` in Host mode and nothing in other modes. **Throw Error** fails the node. |
| Include Summary | `true` | Adds the summary fields in Host mode. |
| Include Port Names | `false` | Adds IANA service names for about 90 well-known ports, as `services: [{ port, name }]` in Host mode and `serviceName` in Ports mode. Unknown ports get `null`. |
| Timeout (Ms) | `10000` | Timeout for each request. |
| Max Retries | `3` | Number of retries for HTTP 429, 5xx, and network errors. The node uses exponential backoff with jitter and honours `Retry-After`. |
| Max Addresses *(Lookup Many)* | `256` | Maximum number of unique addresses the targets may expand to. The hard maximum is **4096**. Larger inputs fail before any request is sent, with a message giving the expanded count. |
| Concurrency *(Lookup Many)* | `1` | Number of parallel lookups, from 1 to 5. |
| Delay Between Requests (Ms) *(Lookup Many)* | `250` | Pause between requests of each worker. InternetDB does not document its rate limits, so the defaults are deliberately polite. |

### Input formats

- **IPv4**: `1.1.1.1`. Leading zeros such as `01.2.3.4` are rejected because they are ambiguous (they could be read as octal).
- **IPv4 CIDR**: `/0` to `/32`, in Lookup Many and the trigger. Network and broadcast addresses are skipped, except for `/31` and `/32`.
- **IPv6**: single addresses are passed through. InternetDB's coverage is mostly IPv4, so most IPv6 lookups return no data. IPv6 ranges are not supported. IPv4-mapped addresses (`::ffff:1.2.3.4`) are looked up as IPv4.
- **Hostnames and URLs are not accepted.** Resolve them first, for example with a DNS or HTTP Request node, and pass the IP.
- `ip:port` values such as `1.2.3.4:443` are rejected with a clear message.

### Errors

- **Invalid input** fails with a message that names the value. In Lookup Many, it also gives the value's position.
- **API failures** (after retries) fail with the HTTP status.
- **Continue On Fail**: the node emits `{ ip, error, statusCode? }` for a failed IP and continues. In Lookup Many, one failed IP does not stop the rest of the batch.

### Use as an AI Agent tool

The node is marked `usableAsTool`. Connect it to an **AI Agent** node's *Tool* input to answer questions such as "what's exposed on 203.0.113.10?". Lookups are read-only.

## Trigger

**Shodan InternetDB Trigger** is a polling trigger. On every poll it looks up all target addresses, compares them with the previous snapshot, and emits only the changes.

### Events

| Event | Fires when |
|---|---|
| Port Opened / Port Closed | A port appears in or disappears from the list. There is one event per port. |
| Vulnerability Added / Vulnerability Resolved | A CVE appears or disappears. There is one event per CVE. |
| Tags Changed, Hostnames Changed, CPEs Changed | The set changed. The event carries `added[]` and `removed[]`. |
| Data Appeared | An IP with no data (404) now has data. |
| Data Disappeared | An IP with data now returns 404. |

Only the selected events are emitted, but state is always tracked for every field.

**Emit Mode**

- **Per Change** (default): one item per change, `{ ip, event, value?, added?, removed?, previousSeenAt, detectedAt }`.
- **Per Host**: one item per changed IP, `{ ip, found, current: {…}, changes: { portsOpened, portsClosed, vulnsAdded, vulnsResolved, tags: { added, removed }, … }, previousSeenAt, detectedAt }`.

### Behaviour

- **First activation** records the current state and emits **nothing**. Turn on **Emit Current State on First Run** to get the current state as Per Host items instead.
- **Editing targets**: IPs you remove are dropped from state. New IPs are recorded silently on their first poll, so adding a range doesn't flood you with "new port" events.
- **Failures**: if a lookup fails after retries, that IP keeps its previous snapshot and the other IPs are processed normally. If **every** lookup fails, the trigger reports an error and state is left untouched.
- **Non-public addresses** in the targets are ignored. The hard maximum is **1024** addresses, lower than the action node's because the trigger runs unattended.
- **Fetch Test Event** (manual mode) looks up at most the first 5 targets and returns them as Per Host samples. It never reads or changes the saved state.
- State is kept in the workflow's static data, in n8n's own database. Nothing else is stored.

### Recommended poll interval: every 12–24 hours

InternetDB refreshes its data about once a week. Polling more than once a day wastes requests and finds nothing new. A 12–24 hour interval still catches changes within a day of Shodan seeing them.

## Example workflows

Import any of these from [`examples/`](examples/) with **Workflows → Import from File**. The IP addresses are documentation placeholders; replace them with your own.

| File | What it does |
|---|---|
| [`weekly-exposure-report.json`](examples/weekly-exposure-report.json) | Every Monday, looks up your public IPs and appends the results to Google Sheets. It also emails a summary. |
| [`alert-on-new-port-or-cve.json`](examples/alert-on-new-port-or-cve.json) | Trigger: sends a Telegram alert when a new port opens or a new CVE appears on your IPs. A WhatsApp node works the same way. |
| [`enrich-siem-alerts.json`](examples/enrich-siem-alerts.json) | Enriches the source IP of a firewall or SIEM alert with InternetDB before triage. |
| [`ai-agent-exposure-tool.json`](examples/ai-agent-exposure-tool.json) | An AI Agent that uses the node as a tool to answer "what's exposed on this IP?" |

## Responsible use

This package is intended for **your own assets** and for **defensive triage**, such as checking what the internet sees on your IPs or enriching alerts about addresses that contacted you. Respect InternetDB's usage terms and don't use it to profile systems you have no legitimate reason to investigate.

## Compatibility

- Recent n8n 1.x and 2.x releases with community nodes enabled (self-hosted).
- Node.js 24 or later.

## Development

```bash
npm ci
npm run dev        # n8n with the nodes loaded, at http://localhost:5678
npm run lint
npm test           # vitest, no network access
npm run build
npm pack && npm run scan:package -- ./t0mer-n8n-nodes-shodan-internetdb-*.tgz
```

Releases use the `YYYY.M.PATCH` versioning scheme and are published from GitHub Actions with npm provenance (see `.github/workflows/publish.yml`). When bumping the version, also update `PACKAGE_VERSION` in `shared/constants.ts`. A test enforces that they match.

## Disclaimer

This is an **unofficial** community package. It is **not affiliated with, endorsed by, or sponsored by Shodan**. "Shodan" is used only to describe the service the package talks to.

## License

[MIT](LICENSE)
