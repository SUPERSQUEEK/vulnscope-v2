# Validation record

Executed in `/Users/amiral-rabadi/vulnscope-v2` on 2026-09-17 with Python 3.11.0.

## Passed

- `python3 -m unittest discover -s tests -q`: **40 tests passed**.
- `python3 -m compileall -q vulnscope2 tests`: passed.
- Package import and `python3 -m vulnscope2 --help`: passed.
- `python3 -m pip wheel --no-deps --no-build-isolation --no-cache-dir --disable-pip-version-check --wheel-dir artifacts .`: built `vulnscope2-2.0.0-py3-none-any.whl` without runtime dependencies or dependency downloads.
- Compared the `guard()` function AST with `../vulnscope/vulnscope/scope.py`: identical. Permanent-deny additions and module documentation are outside that function.
- `/opt/homebrew/bin/nmap --version`: executable present, version **7.991**.
- Full synthetic CLI test: fixed nmap invocation → XML parsing → Apache HTTP on port 8081 → two-origin CORS confirmation and a CVE candidate → deduplicated findings → JSON/HTML → expected high-finding exit status 2.

The synthetic integration test uses mocked subprocess output and network transports. It is not a successful live scan. Scope enforcement remains real in that test, using an explicitly allowed documentation-range IP; no production guard bypass is installed.

## Actual CLI runs

Explicit scope file `artifacts/loopback.scope`:

```text
allow 127.0.0.1
```

```bash
python3 -m vulnscope2 --scope artifacts/loopback.scope \
  --authorized-by 'User-requested permanent-deny verification' \
  --json artifacts/loopback.json 127.0.0.1
```

Result: **REFUSED**, `127.0.0.1 is in a permanently denied range.` No discovery or checker connection was made. This is the required behavior even with an explicit allow rule. The v1 finding-based exit contract returns 0 here because there are no findings; JSON reports `complete: false` and the refusal in `errors`.

Explicit scope file `artifacts/scanme.scope`:

```text
allow scanme.nmap.org
```

```bash
python3 -m vulnscope2 --scope artifacts/scanme.scope \
  --authorized-by 'User-requested assessment; scanme.nmap.org public Nmap authorization' \
  --nmap --ports 22,80 --nmap-timeout 90 --timeout 4 \
  --json artifacts/scanme-nmap.json --html artifacts/scanme-nmap.html scanme.nmap.org
```

Result: **REFUSED**, `scanme.nmap.org did not resolve; refusing to scan an unknown target.` The environment has restricted networking. The observed failure occurred in system hostname resolution, before nmap could start; external connectivity and live nmap XML ingestion could not be established. No hardcoded IP, alternate resolver bypass, loopback exception, or scope relaxation was used to force a pass.

**A successful live end-to-end nmap scan remains unverified.** Run the documented command on authorized infrastructure from a network-enabled environment to complete that check. The public scanme authorization is limited to Nmap scanning and excludes exploitation/DoS; see [Nmap's authorization statement](https://nmap.org/book/legal-issues.html). For the complete native HTTP/TLS validation suite, prefer infrastructure you own or have explicitly authorized for those checks.

The CLI reports and wheel are retained under ignored `artifacts/`. This record and the deterministic tests are committable. No GitHub remote or commit was created.

## Optional Web UI validation

Executed on 2026-09-17 with Python 3.11.0, FastAPI 0.141.1, uvicorn 0.53.0, and httpx installed.

- `python3 -m unittest discover -s tests -v`: **50 tests passed**, including 10 web tests. No live target scans are used.
- Python compile checks and `node --check vulnscope2/web/static/app.js`: passed.
- Web and core CLI `--help`: passed; the web launcher defaults to `127.0.0.1:8765` and one worker.
- Wheel build: passed. Inspected the archive: all seven web Python/static files are present, and the core package metadata still has no runtime dependencies.
- Real FastAPI HTTP handlers exercised through `httpx.ASGITransport`: missing `authorized_by` and missing `scope` each returned **HTTP 422** with an explicit error. The same requests with blank/invalid values and deny-only scopes are covered by tests before engine scheduling.
- A web request with explicit loopback scope reached the **real engine**, which returned `REFUSED 127.0.0.1: 127.0.0.1 is in a permanently denied range.` Status preserved `complete: false`; SSE returned status, progress/refusal, and done events. JSON and HTML downloads returned HTTP 200 and were compared byte-for-byte with the CLI serializers.
- Synthetic successful web pipeline: real scope guard → real native discovery/checkers over fixture transport → OpenSSH greeting → CVE candidate → sorted JSON/HTML reports. This establishes adapter integration, not a live vulnerability finding.
- Streaming before task completion, multiple subscribers/replay, cancellation cleanup, operational failure status, bounded job retention, origin/CSRF checks, and static asset delivery passed.

**Live listener and browser verification remain blocked by this environment.** Actually starting `python3 -m vulnscope2.web --port 8765` reached application startup, then failed to bind `127.0.0.1:8765` with `[Errno 1] operation not permitted`. A uvicorn Unix-socket listener under `/private/tmp` was also denied. Thus in-process HTTP verification must not be represented as a successful live uvicorn server test. No server is left running.

The browser integration reported no available browsers. A separate headless Chromium launch also failed in the sandbox, so visual rendering and browser interaction checks are not claimed as passed.

To finish the live HTTP check in a host environment that permits listeners, launch the web server as documented in README, then run:

```bash
python3 tests/web_smoke.py --port 8765
```

The standalone smoke check uses the standard library HTTP client and only the permanently denied loopback assessment target. It checks authorization/scope refusals, SSE, incomplete status, and downloads without target discovery. Review the web UI in light/dark themes and at desktop/mobile widths in that environment. No engine, guard, checker, finding, or report implementation was changed to accommodate the web UI or these environment limitations.
