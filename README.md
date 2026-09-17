# vulnscope2

A scoped vulnerability assessment tool with **async discovery, real nmap service detection, and bounded active validation**. V1 mostly recorded what a service volunteered. V2 negotiates exact TLS versions and ciphers, probes HTTP methods, confirms CORS reflection with independent requests, and correlates product versions with curated CVE records.

Python **3.11+**, standard library only. An optional `nmap` executable enables `--nmap`; discovery falls back to asyncio TCP connections when it is absent. No third-party runtime dependency is needed: asyncio supplies streams, sockets and subprocesses; `ssl` supplies TLS. The Python requirement increased from v1 for structured timeout/cancellation support.

## Run

```bash
# Running from the checkout needs no installation.
python3 -m vulnscope2 --help

# Or install a console entry point into a virtual environment.
python3 -m venv .venv
.venv/bin/python -m pip install -e .

# Create scope.txt containing an explicit allow rule for your authorized host.
python3 -m vulnscope2 --scope scope.txt --authorized-by "Infrastructure owner / ticket SEC-123" \
  --nmap --ports 22,80,443,8000-8005 --json report.json --html report.html host.example

# Async TCP discovery, with no nmap requirement.
python3 -m vulnscope2 --scope scope.txt --authorized-by "Infrastructure owner / ticket SEC-123" host.example
```

Targets are individual ASCII hostnames (use punycode for international names) or IP addresses, not URLs or CIDRs. CIDRs belong in **scope rules**. Default discovery checks 23 common service ports. `--ports` accepts 1–4096 selected ports. Neither discovery mode implies all 65,535 ports were checked.

Scope uses the same v1 syntax:

```text
allow .example.com
allow 192.0.2.0/24
deny admin.example.com
```

An allow rule is required; deny overrides allow. Every target goes through the original `scope.guard()` before discovery, DNS policy checking, or imported-service assessment. Every returned address is vetted, then one is pinned for this run (IPv4 preferred, deterministic ordering). **Other vetted addresses are not scanned.** Connections use numeric sockets; the hostname is used only for HTTP Host and TLS SNI. Redirects are never followed, and environment proxies are not used.

The permanent-deny list keeps all v1 entries: loopback, link-local including `169.254.169.254`, IPv4 multicast, and limited broadcast. V2 additionally blocks IPv6 multicast, IPv4-mapped IPv6, and unspecified destinations. The `guard()` function itself is unchanged; its module documentation now accurately describes the engine's call-once/pin flow. There is no scope bypass or “scan everything” mode. `authorized_by` is mandatory in both the CLI and Python API.

## What the checkers do

| Component | V2 capability | Boundary / interpretation |
|---|---|---|
| Ports | Async TCP discovery or real `nmap -sT -sV --version-light`; ingest XML service names, products, versions, tunnels and CPEs | Fixed arguments, no shell, numeric vetted target only, `-n -Pn`, no user-supplied scripts or nmap flags |
| TLS | Certificate verification/expiry, exact TLS 1.0–1.3 handshakes, one TLS 1.2 handshake per locally available cipher, weak-suite findings | Successful handshakes confirm support; failed attempts are inconclusive. No SSLv2/3, STARTTLS or malformed-handshake probing |
| HTTP | Security headers, parsed cookie attributes, headers/markup fingerprints, OPTIONS method advertisement | GET/OPTIONS only; advertised PUT/DELETE/TRACE are never exercised |
| CORS | Two independent random `.invalid` origins must both reflect on successful responses | Confirmation means reflection was reproduced; no authenticated session or data exposure is tested |
| Redirects | Repeat the original request and compare status/Location; flag HTTPS-to-HTTP downgrade | The destination is never contacted. A stable destination does not prove an open redirect |
| Exposure | V1's five fixed paths, now requiring file-format signatures and a response different from the baseline | No wordlist, traversal, content enumeration, or secret values in reports |
| Banners | Bounded SSH/FTP/SMTP/POP3/IMAP greeting reads; nmap service names also select nonstandard ports | No authentication commands or brute force |
| DNS | Async SPF/DMARC/DNSKEY/CAA queries; duplicate/invalid policies; transaction/question validation | Fixed public recursive resolvers (1.1.1.1, 8.8.8.8), no zone transfer. Errors are not interpreted as absent records |
| CVEs | Curated Apache, OpenSSH and vsftpd upstream version correlations from nmap, headers and greetings | **Candidates**, never confirmed exploitability; platform, configuration, backports and artifact provenance matter |

Nmap service probes use its installed probe database. `--version-light` limits general probe intensity, although port-specific probes still run. Nmap's own excluded ports remain excluded from version detection. See [nmap service detection](https://nmap.org/book/man-version-detection.html). An installed nmap that fails produces a report error; only an **absent** binary triggers fallback. The executable is searched on PATH, then `/opt/homebrew/bin/nmap`.

No exploitation, state-changing payloads, fuzzing wordlists, brute force, credential testing, or access attempts are implemented. HTTP uses a 32 KiB body prefix and bounded headers. Discovery runs first for each target; follow-up checkers and different targets run concurrently. DNS policy checks still run if no target ports are open.

## Ingest existing recon

`--ingest` replaces discovery, is mutually exclusive with `--nmap`, and never grants scope. An explicit empty port list means **no open ports**, not “scan again.” If positional targets accompany ingest, each must exist in that input.

V1 formats are supported:

```json
{"host.example": [22, 443], "empty.example": []}
```

```json
{"findings": [{"target": "host.example", "port": 22}]}
```

Service metadata can also be supplied:

```json
{"host.example": [{"port": 8081, "service": "http", "product": "Apache httpd", "version": "2.4.49"}]}
```

`name`, `tunnel`, `extra`, and `cpes` are optional service fields. Explicitly non-open or non-TCP entries are excluded. External data remains untrusted; it is not evidence that a currently running package is vulnerable.

```bash
python3 -m vulnscope2 --scope scope.txt --authorized-by "Infrastructure owner" --ingest recon.json
```

## Python API

```python
import asyncio
from vulnscope2 import Scope, run_scan
from vulnscope2.ingest import parse_ingest

scope = Scope.from_lines(["allow host.example"])
report = asyncio.run(run_scan(
    ["host.example"], scope, authorized_by="Infrastructure owner / SEC-123",
    nmap=True, ports=[22, 80, 443],
))
print(report.counts(), report.exit_code)
```

`run_scan` is async; `run_scan_sync` serves synchronous callers. Internal checker and adapter functions accept already-vetted contexts; they are not independent public scanning interfaces. The optional web UI below calls this same engine.

## Web UI

Launch the optional assessment workspace from this checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-web.txt
.venv/bin/python -m vulnscope2.web
# Open http://127.0.0.1:8765

# Choose another port:
.venv/bin/python -m vulnscope2.web --port 9000
```

FastAPI and uvicorn are optional web dependencies; the CLI and Python engine remain dependency-free. All frontend assets are included locally, with no CDN or build step. The launcher binds **127.0.0.1 by default**. Listening beyond localhost requires an explicit `--host` option. This is a single-operator tool without user authentication; only expose it to trusted operators, behind access control if needed. The local browser boundary rejects foreign origins and requires a per-process CSRF token for writes; this is not a remote authentication system.

Enter individual targets (one per line or comma-separated), paste the same `allow` / `deny` rules used in a scope file, and supply **Authorized by** with the owner or approval reference. Both authorization and a non-empty scope containing an allow rule are mandatory; invalid requests are rejected before a job is scheduled. The unchanged engine still runs `scope.guard()` on every target. Even an explicit allow rule cannot permit loopback or another permanently denied address.

Choose **Native** async TCP discovery or **Nmap** service/version discovery. Both use the core's 23 common service ports and existing timeout/concurrency defaults. Nmap falls back to native only when the executable is absent. The web UI accepts at most 64 targets per run, with two simultaneous runs to bound total work.

Live activity streams the engine's target-level progress over Server-Sent Events; it does not estimate a percentage or imply per-probe coverage. On completion, the dashboard shows severity counts, targets, authorization, worst severity, and coverage status. Click a severity card, select a checker, or search the findings. Open a finding for its evidence, remediation, primary references, CVEs, validation status, and pinned IP. Version matches remain **candidates**. Review the expanded errors/refusals when a run is **incomplete**, including runs that returned no findings. Completion means no recorded operational errors, not exhaustive coverage; JSON `complete` remains the coverage indicator.

**↓ JSON** and **↓ HTML** download the exact `reporting.to_json()` / `reporting.to_html()` output used by the CLI. Notes and service inventory are also available in the dashboard. Theme selection supports system, light, and dark. Reports live only in server memory: the oldest finished runs are evicted as new runs arrive (20 retained runs maximum), and restarting the server clears them. Download reports to keep them; local saved reports belong under ignored `artifacts/`.

Closing a tab does not stop a scan. Refreshing its run URL reconnects and replays progress. **Stop scan** cancels the engine task and its async network/subprocess work; cancellation has incomplete coverage and no final engine report, so downloads remain unavailable. Server shutdown also cancels active runs. Use the supplied launcher with one worker; multiple workers or reload would split or discard the in-memory scan store.

The HTTP interface is `GET /api/config` (defaults and CSRF token), `POST /api/scans` with JSON fields `targets` (array), `scope` (text), `authorized_by` (text), and `nmap` (boolean), plus `GET /api/scans/{id}`, `GET /api/scans/{id}/events`, `POST /api/scans/{id}/cancel`, and `GET /api/scans/{id}/report.json` / `report.html`. Writes need `X-Vulnscope-Token` from `/api/config`; browser requests must use the server's own origin. SSE supports `Last-Event-ID` replay and idle heartbeats. Missing authorization or scope returns HTTP 422; a target refused by the engine produces an incomplete report with the refusal preserved.

## Reports and CI

Console, JSON and standalone HTML retain evidence, remediation and references. Each finding includes `ip`, `cves` and `validation` (`observed`, `confirmed`, or `candidate`). JSON also contains service inventory, discovery provenance, notes, errors and `complete`. HTML escapes target-controlled text; console output strips terminal control sequences. Findings use the named **info / low / medium / high / critical** scale, never invented CVSS scores.

The v1 exit-code contract is unchanged:

| Exit | Worst finding |
|---|---|
| 0 | No finding above info |
| 1 | Low or medium |
| 2 | High |
| 3 | Critical |

Invalid CLI/API inputs and report-writing failures return CLI status 2; Ctrl-C returns 130. **Report errors/refusals do not change the finding-based exit code.** Consequently a refused scan with no findings still returns 0, as in v1. For CI that also requires coverage, check JSON `complete == true`, and require the expected target/service inventory. `complete` means no recorded operational error, not exhaustive vulnerability coverage.

Defaults: `--timeout 6` seconds per network operation, `--concurrency 32` native network operations, `--target-concurrency 4` target pipelines, `--nmap-timeout 180` per nmap process, `--checker-timeout 180` per follow-up checker. Nmap has its own internal concurrency (`--max-parallelism 16`); target concurrency bounds simultaneous nmap processes. TLS enumeration can hit its checker budget; partial findings survive and the report becomes incomplete. Cancellation closes sockets and kills/reaps an active nmap child. The blocking system resolver runs in asyncio's bounded thread pool; port/checker operations do not use a thread per port.

## Limits that affect interpretation

- The CVE table is deliberately small, offline and auditable, not a current comprehensive vulnerability feed. Sources are embedded per rule: [Apache advisories](https://httpd.apache.org/security/vulnerabilities_24.html), [OpenSSH 9.8 notes](https://www.openssh.com/txt/release-9.8), and [vsftpd CVE record](https://nvd.nist.gov/vuln/detail/CVE-2011-2523). Version strings may be misleading or hide backported fixes.
- TLS enumeration is limited by the local OpenSSL build. Python cannot restrict TLS 1.3 suites individually; the negotiated TLS 1.3 suite is reported. Certificate dates are available only after a verifying handshake; verification failures are reported without guessing certificate fields.
- Only direct TLS is implemented, not STARTTLS. HTTP is HTTP/1.1, without JavaScript, authentication, proxying, HTTP/2 or HTTP/3. GET can have application-specific side effects on poorly designed services; only scan systems whose owners authorize these probes.
- DNS checks use the exact requested hostname. No public suffix inference, inherited CAA/DMARC evaluation, alias following, or DNSSEC chain validation. DNSKEY absence at a non-apex name does not imply an unsigned zone. Truncated DNS responses are reported as errors rather than silently treated as missing records.
- Listening database ports establish reachability from the scanner, not public exposure or absent authentication. V2 avoids v1's critical “Redis exposed” inference based only on an open port.

## Verification

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q vulnscope2 tests
```

Web tests run with the optional dependencies and the HTTP test client installed (`python3 -m pip install -r requirements-web.txt httpx`). Otherwise only the web tests are skipped. They cover request refusals before engine scheduling, the real permanent-deny path, async streaming/replay, report byte equivalence, cancellation, capacity, browser request boundaries, and localhost defaults, without live target scans.

With the web server running, `python3 tests/web_smoke.py --port 8765` verifies actual HTTP requests, missing authorization/scope refusals, SSE progress, and downloads. Its only assessment target is permanently denied loopback, so it exercises the real engine refusal without scanning infrastructure.

The suite exercises permanent denials, mixed DNS answers, scope precedence, authorization before I/O, empty ingest, nmap XML boundaries, child cleanup, async ordering/concurrency, numeric socket pinning and SNI, CORS confirmation, redirect non-following, HTTP parsing, TLS negotiation evidence, CVE boundaries, report escaping and CI codes. A synthetic full-CLI test covers nmap XML → nonstandard HTTP port → active validation/CVE candidate → JSON/HTML. Its transports are fixtures, not a claim of a live network scan.

See [VALIDATION.md](VALIDATION.md) for the actual execution results and environment limitation. To independently repeat the deny-path check:

```bash
printf 'allow 127.0.0.1\n' > /tmp/vulnscope2-deny.scope
python3 -m vulnscope2 --scope /tmp/vulnscope2-deny.scope \
  --authorized-by "Local permanent-deny verification" 127.0.0.1
```

Loopback is always refused, even when explicitly allowed. Never weaken that rule to make a demonstration pass.
