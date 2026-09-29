# n8n-nodes-shodan-internetdb

[![npm](https://img.shields.io/npm/v/@t0mer/n8n-nodes-shodan-internetdb)](https://www.npmjs.com/package/@t0mer/n8n-nodes-shodan-internetdb)
[![CI](https://github.com/t0mer/n8n-nodes-shodan-internetdb/actions/workflows/ci.yml/badge.svg)](https://github.com/t0mer/n8n-nodes-shodan-internetdb/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/t0mer/n8n-nodes-shodan-internetdb/blob/main/LICENSE)

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

## Contents

- [How InternetDB differs from the full Shodan API](#how-internetdb-differs-from-the-full-shodan-api)
- [Usage terms](#usage-terms)
- [Installation](#installation)
- [Credentials](#credentials)
- [Shodan InternetDB node](#shodan-internetdb-node)
- [Trigger](#trigger)
- [Example workflows](#example-workflows)
- [Responsible use](#responsible-use)
- [Security and privacy notes](#security-and-privacy-notes)
- [Troubleshooting](#troubleshooting)
- [Compatibility](#compatibility)
- [Development](#development)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

## How InternetDB differs from the full Shodan API

InternetDB is a lightweight, pre-computed snapshot:

- It needs **no API key** and **no account**.
- Data is refreshed about **once a week**. It is not a live scan.
- It has **no banners**, geolocation, ASN, or organization data. It has much less detail than a full Shodan host lookup.
- It supports IP lookups only. There is no search, scanning, or alerting.

If you need banners, search, or on-demand scans, use the full Shodan API with an API key. This package deliberately covers InternetDB only.

## Usage terms

InternetDB is **free for non-commercial use**. If you use it to make money, for example to build a product you charge for, **you need a Shodan enterprise license**. Using it internally at a company is allowed. See [internetdb.shodan.io](https://internetdb.shodan.io) and Shodan's [announcement of the InternetDB API](https://blog.shodan.io/introducing-the-internetdb-api/) for the current terms. You are responsible for complying with them.

InternetDB does not document its rate limits, so the package's defaults are deliberately polite (one request at a time, 250 ms apart) and it backs off on HTTP 429.

## Installation

### Community Nodes UI (recommended)

In a self-hosted n8n:

1. Go to **Settings → Community Nodes**.
2. Select **Install**.
3. Enter `@t0mer/n8n-nodes-shodan-internetdb` and confirm.

See n8n's [community nodes installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) for details. The package has no runtime dependencies.

### Manual install

If you can't use the UI (for example, in queue mode), install the package into n8n's custom nodes folder and restart n8n:

```bash
mkdir -p ~/.n8n/nodes
cd ~/.n8n/nodes
npm install @t0mer/n8n-nodes-shodan-internetdb
# then restart n8n
```

See n8n's [manual installation guide](https://docs.n8n.io/integrations/community-nodes/installation/manual-install/) for Docker and queue-mode specifics.

## Credentials

**None.** InternetDB is keyless, so there is nothing to configure.

## Shodan InternetDB node

Resource: **IP**.

### Operations

| Operation | What it does |
|---|---|
| **Lookup** | Looks up one IP address per input item. |
| **Lookup Many** | Looks up a list of IPs and CIDR ranges in one run, such as `1.1.1.1, 8.8.8.0/30`. Addresses are de-duplicated, and output keeps the input order. |

**Lookup parameters**

| Parameter | Default | Description |
|---|---|---|
| IP Address | | Required. One public IPv4 or IPv6 address. Hostnames, URLs, ports, and ranges are rejected. |
| Output Mode | Host | See [Output modes](#output-modes). |

**Lookup Many parameters**

| Parameter | Default | Description |
|---|---|---|
| Targets | | Required. IPv4 addresses, IPv4 CIDR ranges, and single IPv6 addresses separated by commas, spaces, or new lines. Supports expressions, for example `{{ $json.ips.join(',') }}`. |
| Run Once | `true` | Reads Targets from the first input item only and runs once, with all output paired to item 0. Turn it off to run a separate batch for every input item. |
| Output Mode | Host | See [Output modes](#output-modes). |

### Output modes

| Output Mode | Items emitted per IP |
|---|---|
| **Host** (default) | One item with the host data and summary fields. |
| **Ports** | One item per open port: `{ ip, port, serviceName? }`. IPs with no open ports emit nothing. |
| **Vulnerabilities** | One item per CVE: `{ ip, cve }`. IPs with no CVEs emit nothing. |
| **Raw** | One item with the API response fields (`ip`, `ports`, `cpes`, `hostnames`, `tags`, `vulns`) and no derived fields. When InternetDB has no data and No Data Behavior is **Return Empty Result**, the item has empty arrays and `found: false`. |

In Host mode, `ports` are sorted ascending and `vulns` are sorted by CVE year, then number, so output is stable and easy to diff. `cpes`, `hostnames`, and `tags` keep the API order. Ports and Vulnerabilities modes use the same sort order.

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

`hasEolProduct` is `true` when the `tags` include `eol-product`. `lookedUpAt` is the time the request for that IP completed.

### Options

| Option | Default | Description |
|---|---|---|
| No Data Behavior | Return Empty Result | InternetDB has no data for the IP (HTTP 404). **Return Empty Result** emits the IP with empty arrays and `found: false` in Host and Raw modes; Ports and Vulnerabilities modes emit nothing for it. **Skip** emits nothing. **Throw Error** fails the node. |
| Non-Public IP Behavior | Skip | Private, loopback, link-local, CGNAT, multicast, documentation, and reserved addresses are never sent to the API. **Skip** emits `{ ip, found: false, skipped: "non_public" }` in Host mode and nothing in other modes. **Throw Error** fails the node. In Lookup Many with Continue On Fail off, it fails before any request is sent; with Continue On Fail on, each non-public IP is emitted as `{ ip, error }` and the other IPs are still looked up. |
| Include Summary | `true` | Adds the summary fields in Host mode. |
| Include Port Names | `false` | Adds IANA service names for about 90 well-known ports, as `services: [{ port, name }]` in Host mode and `serviceName` in Ports mode. Unknown ports get `null`. |
| Timeout (Ms) | `10000` | Timeout for each request. Minimum `1000`. |
| Max Retries | `3` | Number of retries (0 to 10) for HTTP 429, 5xx, and network errors. The node uses exponential backoff with jitter (500 ms doubling, capped at 10 s) and honors `Retry-After` in seconds (capped at 60 s). |
| Max Addresses *(Lookup Many)* | `256` | Maximum number of unique addresses the targets may expand to. The hard maximum is **4096**. Larger inputs fail before any request is sent, with a message giving the expanded count. |
| Concurrency *(Lookup Many)* | `1` | Number of parallel lookups, from 1 to 5. |
| Delay Between Requests (Ms) *(Lookup Many)* | `250` | Pause between requests of each worker. InternetDB does not document its rate limits, so the defaults are deliberately polite. |

### Input formats

- **IPv4**: `1.1.1.1`. Leading zeros such as `01.2.3.4` are rejected because they are ambiguous (they could be read as octal).
- **IPv4 CIDR**: `/0` to `/32`, in Lookup Many and the trigger. Network and broadcast addresses are skipped, except for `/31` and `/32`. Lookup (single IP) rejects ranges and points you to Lookup Many.
- **IPv6**: single addresses are passed through. InternetDB's coverage is mostly IPv4, so most IPv6 lookups return no data. IPv6 ranges are not supported. IPv4-mapped addresses (`::ffff:1.2.3.4`) are looked up as IPv4.
- **Hostnames and URLs are not accepted.** Resolve them first, for example with a DNS or HTTP Request node, and pass the IP.
- `ip:port` values such as `1.2.3.4:443` or `[2001:db8::1]:443` are rejected with a clear message.

### Errors

- **Invalid input** fails with a message that usually names the value, for example `"01.2.3.4" has a leading zero in an octet …`. Hostnames, URLs, and empty values get fixed messages that don't name the value, such as `InternetDB only accepts IP addresses. Resolve the hostname first …`. In Lookup Many, every message is prefixed with the value's position, for example `Target 2 ("example.com"): InternetDB only accepts IP addresses. …`.
- **HTTP 422** (InternetDB rejected the address) fails immediately with `InternetDB rejected "<ip>": <reason>`. It is not retried.
- **Other API failures** fail with the HTTP status, for example `InternetDB request for <ip> failed with HTTP 503 after 3 retries`. A batch that fails stops the remaining lookups and cancels in-flight requests.
- **Continue On Fail**: the node emits `{ ip, error, statusCode? }` for a failed IP and continues. In Lookup Many, one failed IP does not stop the rest of the batch. If the whole Targets value is invalid, Lookup Many emits `{ targets, error }` for that input item.

### Use as an AI Agent tool

The node is marked `usableAsTool`. Connect it to an **AI Agent** node's *Tool* input to answer questions such as "what's exposed on my server's IP?". Lookups are read-only.

## Trigger

**Shodan InternetDB Trigger** is a polling trigger. On every poll it looks up all target addresses, compares them with the previous snapshot, and emits only the changes.

### Parameters

| Parameter | Default | Description |
|---|---|---|
| Targets | | Required. Your public IPv4 addresses, IPv4 CIDR ranges, and single IPv6 addresses, separated by commas, spaces, or new lines. Same formats as [Lookup Many](#input-formats). |
| Events | All | Which changes trigger the workflow. See [Events](#events). |
| Emit Mode | Per Change | **Per Change** or **Per Host**. See below. |
| Max Addresses | `256` | Maximum number of unique addresses the targets may expand to. The hard maximum is **1024**, lower than the action node's because the trigger runs unattended. |
| Options → Concurrency | `1` | Parallel lookups, from 1 to 5. |
| Options → Delay Between Requests (Ms) | `250` | Pause between requests of each worker. |
| Options → Emit Current State on First Run | `false` | See [Behavior](#behavior). |
| Options → Max Retries | `3` | Retries for HTTP 429, 5xx, and network errors (0 to 10). |
| Options → Timeout (Ms) | `10000` | Timeout for each request. |

### Events

| Event | Fires when |
|---|---|
| Port Opened / Port Closed | A port appears in or disappears from the list. There is one event per port. |
| Vulnerability Added / Vulnerability Resolved | A CVE appears or disappears. There is one event per CVE. |
| Tags Changed, Hostnames Changed, CPEs Changed | The set changed. The event carries `added[]` and `removed[]`. |
| Data Appeared | An IP with no data (404) now has data. |
| Data Disappeared | An IP with data now returns 404. |

Changes are set differences: only additions and removals count, not reordering. Only the selected events are emitted, but state is always tracked for every field.

**Emit Mode**

- **Per Change** (default): one item per change, `{ ip, event, value?, added?, removed?, previousSeenAt, detectedAt }`.
- **Per Host**: one item per changed IP, `{ ip, found, current: {…}, changes: { dataAppeared, dataDisappeared, portsOpened, portsClosed, vulnsAdded, vulnsResolved, tags: { added, removed }, hostnames: { … }, cpes: { … } }, previousSeenAt, detectedAt }`.

`previousSeenAt` is the start time of the previous poll in which that IP was looked up successfully, and `detectedAt` is the time of the current poll.

### Behavior

- **First activation** records the current state and emits **nothing**. Turn on **Emit Current State on First Run** to get the current state as Per Host items instead.
- **Editing targets**: IPs you remove are dropped from state. New IPs are recorded silently on their first poll, so adding a range doesn't flood you with "new port" events.
- **Failures**: if a lookup fails after retries, that IP keeps its previous snapshot and the other IPs are processed normally. If **every** lookup fails, the trigger reports an error and state is left untouched.
- **Non-public addresses** in the targets are ignored. If every target is non-public, the trigger fails with an error.
- **Fetch Test Event** (manual mode) looks up at most the first 5 public addresses (after range expansion) and returns them as Per Host samples with empty `changes`. Sample lookups that fail are dropped; if all of them fail, the node throws an error. It never reads or changes the saved state.
- State is kept in the workflow's static data, in n8n's own database. Nothing else is stored.

### Recommended poll interval: every 12–24 hours

InternetDB refreshes its data about once a week. Polling more than once a day wastes requests and finds nothing new. A 12–24 hour interval still catches changes within a day of Shodan seeing them.

## Example workflows

Import any of these from [`examples/`](https://github.com/t0mer/n8n-nodes-shodan-internetdb/tree/main/examples) with **Workflows → Import from File**. The IP addresses are documentation placeholders; replace them with your own.

| File | What it does |
|---|---|
| [`weekly-exposure-report.json`](https://github.com/t0mer/n8n-nodes-shodan-internetdb/blob/main/examples/weekly-exposure-report.json) | Every Monday, looks up your public IPs and appends the results to Google Sheets. It also emails a summary. |
| [`alert-on-new-port-or-cve.json`](https://github.com/t0mer/n8n-nodes-shodan-internetdb/blob/main/examples/alert-on-new-port-or-cve.json) | Trigger: sends a Telegram alert when a new port opens or a new CVE appears on your IPs. A WhatsApp node works the same way. |
| [`enrich-siem-alerts.json`](https://github.com/t0mer/n8n-nodes-shodan-internetdb/blob/main/examples/enrich-siem-alerts.json) | Enriches the source IP of a firewall or SIEM alert with InternetDB before triage. |
| [`ai-agent-exposure-tool.json`](https://github.com/t0mer/n8n-nodes-shodan-internetdb/blob/main/examples/ai-agent-exposure-tool.json) | An AI Agent that uses the node as a tool to answer "what's exposed on this IP?" |

The examples need their own credentials for Google Sheets, SMTP, Telegram, or OpenAI. Replace placeholders such as `YOUR_SPREADSHEET_ID` and `YOUR_CHAT_ID`.

## Responsible use

This package is intended for **your own assets** and for **defensive triage**, such as checking what the internet sees on your IPs or enriching alerts about addresses that contacted you. Only look up IP addresses you are authorized to assess or have a legitimate reason to investigate. Respect InternetDB's usage terms and don't use it to profile systems you have no legitimate reason to investigate.

## Security and privacy notes

- The only data sent to InternetDB is the IP address, over HTTPS, in a `GET https://internetdb.shodan.io/<ip>` request with the User-Agent `n8n-nodes-shodan-internetdb/<version>`. There are no credentials to leak.
- Non-public addresses (private, loopback, reserved, and similar) are never sent.
- Lookup results can reveal known vulnerabilities on your infrastructure. Treat workflow output, execution logs, and alert destinations as sensitive.
- The package has no runtime dependencies, and each release is published from GitHub Actions with an npm provenance attestation.

## Troubleshooting

- **Every result has `found: false`**: InternetDB has no data for the IP (HTTP 404), or the address is non-public and was skipped (`skipped: "non_public"`). IPv6 coverage is limited.
- **"InternetDB only accepts IP addresses"**: you passed a hostname or URL. Resolve it to an IP first.
- **"The targets expand to N addresses, more than the Max Addresses limit"**: narrow the ranges or raise **Max Addresses** (up to 4096 for the action node, 1024 for the trigger).
- **The trigger never fires after activation**: the first poll only records a baseline, and later polls fire only when something changes. InternetDB data changes about once a week.
- **HTTP 429 errors**: lower **Concurrency** and raise **Delay Between Requests**.

## Compatibility

- Self-hosted n8n with community nodes enabled. The package uses n8n nodes API version 1 (`n8nNodesApiVersion: 1`). <!-- TODO: verify which n8n versions it has been tested with -->
- Development and CI use Node.js 24.

## Development

```bash
npm ci
npm run dev        # n8n with the nodes loaded, at http://localhost:5678
npm run lint
npm test           # vitest, no network access
npm run build
npm pack && npm install --no-save @n8n/scan-community-package@0.37.0 \
  && npm run scan:package -- ./t0mer-n8n-nodes-shodan-internetdb-*.tgz
```

Project layout:

| Path | Contents |
|---|---|
| `nodes/ShodanInternetDb/` | Action node and its IP resource description |
| `nodes/ShodanInternetDbTrigger/` | Polling trigger |
| `shared/` | HTTP client with retries and the worker pool, IP/CIDR parsing, output shaping, trigger diffing, port names, and the generated version constant |
| `tests/` | Vitest tests with recorded InternetDB fixtures and the OpenAPI spec |
| `examples/` | Importable example workflows |
| `scripts/` | `next-version.sh`, `sync-version.mjs`, and `scan-package.mjs` |

CI (`.github/workflows/ci.yml`) runs lint, build, tests, a no-runtime-dependencies check, the n8n package scanner on the packed tarball, and a Trivy filesystem scan. Optional Snyk and SonarQube jobs run only when the `SNYK_TOKEN` or `SONAR_TOKEN` secret is set.

### Releasing

Versions are `YYYY.M.PATCH`, and the pushed git tag sets the published version:

```bash
VERSION="$(./scripts/next-version.sh)"   # next patch for the current month, e.g. 2026.9.1
git tag "$VERSION" && git push origin "$VERSION"
```

Pushing the tag runs the Publish workflow (`.github/workflows/publish.yml`):

1. The workflow writes the tag's version into `package.json`.
2. `npm run release` lints, builds, and publishes to npm with provenance, using trusted publishing (OIDC) or the optional `NPM_TOKEN` secret.
3. A separate job runs the n8n Creator Portal scan on the published package.

The scanner exits with status 0 even when the scan fails, so a green job is not proof of a pass. Check the job log for `passed all security checks`, or run the scan yourself once the version is on npm:

```bash
npx @n8n/scan-community-package@beta @t0mer/n8n-nodes-shodan-internetdb
```

The `version` in `package.json` on `main` is not bumped. The User-Agent version in `shared/version.ts` is generated from `package.json` by `npm run build`, so it never needs a manual edit. See the [changelog](https://github.com/t0mer/n8n-nodes-shodan-internetdb/blob/main/CHANGELOG.md) for release notes.

## Contributing

Issues and pull requests are welcome on [GitHub](https://github.com/t0mer/n8n-nodes-shodan-internetdb/issues). Please run `npm run lint`, `npm test`, and `npm run build` before opening a pull request. Tests must not call the live InternetDB API.

## Disclaimer

This is an **unofficial** community package. It is **not affiliated with, endorsed by, or sponsored by Shodan**. "Shodan" is used only to describe the service the package talks to.

## License

[MIT](https://github.com/t0mer/n8n-nodes-shodan-internetdb/blob/main/LICENSE) © 2026 Tomer Klein
