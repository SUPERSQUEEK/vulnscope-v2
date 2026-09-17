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
