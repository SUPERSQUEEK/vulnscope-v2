# What's new in v2

- **Real nmap integration.** `--nmap` runs TCP service/version detection and feeds
  XML product, version, tunnel and CPE metadata into the checker pipeline.
  Missing nmap falls back to native async discovery; external JSON ingest stays.
- **Async engine.** Targets, network operations and follow-up checkers overlap
  within concurrency limits. Port discovery still precedes deeper checks.
  Timeouts, cancellation cleanup and partial failure reporting are explicit.
- **Active validation.** Exact TLS protocol/cipher handshakes, two-origin CORS
  confirmation, repeated redirect observations and HTTP OPTIONS provide evidence
  v1's mostly observational checks could not establish.
- **More reliable findings.** Nonstandard ports use service metadata; header and
  markup fingerprints supplement greetings. Sensitive-path findings require
  format markers. DNS errors no longer masquerade as missing policy records.
- **CVE references with honest confidence.** Upstream version rules produce
  candidates with applicability caveats. Reproduced behaviors are separately
  marked confirmed. Version disclosure never proves exploitability.
- **Scope retained and tightened.** The original guard function is preserved.
  Every interface requires authorization. Numeric IP pinning extends through
  nmap, TLS and HTTP; redirects never expand scope. The permanent deny table also
  covers IPv6 multicast, mapped IPv4 and unspecified destinations.
- **Auditable outputs.** Console/JSON/HTML include CVEs, validation status, pinned
  IPs, inventory/provenance and incomplete-run status. Named severities and v1's
  finding-based CI exit codes remain unchanged.
- **A clean Python package.** `vulnscope2` targets Python 3.11+, has no third-party
  runtime dependencies, and includes a deterministic unittest suite. This release
  provides CLI and async/sync Python APIs.
- **Optional web workspace.** FastAPI/uvicorn drives the same async engine with
  live SSE progress, severity/checker/search filters, evidence drawers, light and
  dark themes, and identical JSON/HTML exports. Explicit scope and authorization
  remain mandatory; the launcher binds localhost by default.

V2 probes more deeply while stopping at validation: no exploitation,
state-changing payloads, credential attacks, fuzzing wordlists or access attempts.
