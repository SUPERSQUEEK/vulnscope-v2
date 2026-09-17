# Working on vulnscope2

This is a governed vulnerability assessment tool, evolved from v1 at `../vulnscope`.
V2 intentionally permits bounded active validation. Preserve the boundary between
confirming a weakness and exploiting it.

## Invariants

1. Every externally supplied target goes through `scope.guard()` before any
   discovery or checker activity. Empty scopes and blank `authorized_by` fail
   before I/O. No scope bypass, automatic allow generation, or scan-everything flag.
2. Keep the original guard's allow/deny behavior and every permanent-deny entry.
   V2's additional IPv6 multicast, mapped IPv4 and unspecified-address denials
   also stay. Validate targets as individual hosts before guard; CIDRs are scope
   rules, not target expansion instructions.
3. Guard checks every DNS answer. Every later target socket uses the selected
   vetted numeric IP; never resolve the target again. HTTP Host and TLS SNI
   retain the hostname. Nmap gets only the numeric IP and disables DNS. Never
   trust an imported target/IP, nmap hostname, redirect, CPE or banner as authority.
4. No exploitation, mutation payloads, brute force, fuzzing wordlists, login
   attempts, or access-gaining steps. HTTP probes are GET/OPTIONS only; advertised
   methods are observations. The five fixed v1 exposure paths are not expandable
   through a wordlist. Redirect destinations are never contacted.
5. A version match is a CVE **candidate**, not confirmation. Preserve explicit
   applicability caveats and primary advisory references. A confirmed finding
   requires reproducible protocol behavior and evidence. Never fabricate CVSS.
6. PortChecker runs first per target. Later checkers get its open-service map.
   DNS runs for guarded hostnames even with zero open ports. Empty imported
   discovery is authoritative; never accidentally trigger a fresh sweep.
7. Async sockets/subprocesses, bounded concurrency, per-operation timeouts, and
   checker budgets. Only the blocking system resolver belongs in the executor.
   Cancellation must close sockets and reap nmap. Never use shell execution for
   nmap, expose arbitrary nmap flags/scripts, or scan additional XML addresses.
8. A checker failure cannot abort other checkers or targets. Preserve partial
   findings, put operational failures in `report.errors`, and expose incomplete
   coverage. Failed probes must not imply a clean target or absent DNS records.
9. Every finding retains evidence, pinned IP, named severity and validation
   status. Do not persist retrieved credentials/cookie values in reports. Escape
   HTML and neutralize terminal controls from remote input.
10. CI finding exits remain `0` info/none, `1` low/medium, `2` high, `3` critical.
    Errors/refusals remain separate; document checking JSON `complete` for coverage.
11. CLI and Python API are the public interfaces. New UIs must call the engine,
    enforce the same scope/authorization requirements and bind localhost by default.

## Layout and conventions

- `scope.py`: v1 guard and permanent denials; security-critical.
- `engine.py`: authorization, ordering, async orchestration, failure isolation.
- `models.py`, `ingest.py`, `nmap.py`: input validation and discovery provenance.
- `checkers/`: bounded native protocol checks over vetted target contexts.
- `dnsclient.py`: fixed-recursive-resolver DNS transport and strict parsing.
- `cves.py`: curated offline version ranges with applicability and sources.
- `findings.py`, `reporting.py`: data and console/JSON/HTML outputs.
- `tests/`: stdlib unittest tests; no live scans in the automated suite.

Use Python 3.11+, standard library first, `from __future__ import annotations`,
dataclasses for data and plain behavioral functions. Explain non-obvious safety
and correctness decisions in docstrings. Generated reports and local scope files
belong under ignored `artifacts/`; never commit secrets. No GitHub remote is
configured by this build.

Run `python3 -m unittest discover -s tests -v` and compile checks after relevant
changes. Scope changes need literal, multi-address DNS, suffix, deny-precedence,
permanent-range and malformed-input coverage. Integration fixtures must not
weaken production guard logic. A blocked live scan is a validation limitation,
not a reason to bypass scope or permanently allow loopback.
