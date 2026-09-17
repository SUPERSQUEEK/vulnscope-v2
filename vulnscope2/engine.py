"""The only public scanning entry point owns authorization and IP pinning."""
from __future__ import annotations

import asyncio
import math
from .scope import Scope, ScopeError, guard
from .models import Target, target_name, port_number, Service
from .findings import Report
from .checkers.base import Network, Checker
from .checkers.ports import PortChecker, COMMON_PORTS
from .checkers.http import HttpChecker
from .checkers.tls import TlsChecker
from .checkers.banners import BannerChecker
from .checkers.dns import DnsChecker
from .cves import correlate


async def run_scan(targets, scope: Scope, authorized_by: str, scope_summary=None, *,
                   ingest=None, timeout=6.0, concurrency=32, target_concurrency=4,
                   ports=None, nmap=False, nmap_timeout=180, checker_timeout=180,
                   on_event=None):
    if not isinstance(authorized_by, str) or not authorized_by.strip():
        raise ValueError('authorized_by is required')
    if not isinstance(scope, Scope) or scope.is_empty():
        raise ValueError('An explicit scope with at least one allow rule is required')
    for name, value in [('timeout',timeout), ('nmap_timeout',nmap_timeout), ('checker_timeout',checker_timeout)]:
        if not isinstance(value, (int,float)) or not math.isfinite(value) or value < 1 or value > 3600:
            raise ValueError(f'{name} must be finite and between 1 and 3600 seconds')
    for value in (concurrency, target_concurrency):
        if type(value) is not int or not 1 <= value <= 256:
            raise ValueError('Concurrency must be an integer between 1 and 256')
    targets = list(dict.fromkeys(target_name(t) for t in targets))
    if not targets:
        raise ValueError('At least one target is required')
    ports = sorted({port_number(p) for p in (COMMON_PORTS if ports is None else ports)})
    if not ports or len(ports) > 4096:
        raise ValueError('Select between 1 and 4096 ports')
    if ingest is not None:
        if not isinstance(ingest, dict):
            raise ValueError('Use parse_ingest() to construct imported services')
        if nmap:
            raise ValueError('ingest and nmap are mutually exclusive discovery modes')
        # The internal representation cannot smuggle new target names into the run.
        for host, services in ingest.items():
            if host != target_name(host) or not isinstance(services, dict):
                raise ValueError('Use parse_ingest() to construct imported services')
            if any(not isinstance(s, Service) or port_number(p) != s.port for p,s in services.items()):
                raise ValueError('Invalid imported service mapping')
        if any(host not in ingest for host in targets):
            raise ValueError('Every requested target must be present in ingest')
    report = Report(authorized_by=authorized_by.strip(), targets=targets,
                    scope_summary=scope_summary or f'{len(scope.allow_hosts)} host(s), '
                    f'{len(scope.allow_suffixes)} suffix(es), {len(scope.allow_nets)} net(s) allowed')
    network = Network(timeout, concurrency)
    target_limit = asyncio.Semaphore(target_concurrency)

    def emit(message):
        if on_event:
            on_event(message)

    async def one(host):
        async with target_limit:
            try:
                # Only blocking system DNS uses the bounded default executor.
                ips = await asyncio.to_thread(guard, scope, host)
            except ScopeError as exc:
                report.errors.append(f'REFUSED {host}: {exc}')
                emit(f'refused {host}: {exc}')
                return
            except Exception as exc:
                report.errors.append(f'REFUSED {host}: guard failed: {exc}')
                return
            ip = sorted(ips, key=lambda value: (':' in value, value))[0]
            target = Target(host, ip)
            emit(f'scanning {host} ({ip})')
            report.notes.append(f'{host}: vetted {ips}; scanning pinned {ip}')
            discovery = PortChecker(network, report)
            try:
                await discovery.run(target, ports, ingest[host] if ingest is not None else None, nmap, nmap_timeout)
            except Exception as exc:
                report.errors.append(f'{host}: ports: {type(exc).__name__}: {exc}')
            report.services[host] = {'ip':ip, 'services':[s.to_dict() for _,s in sorted(target.services.items())]}
            fingerprint = Checker(network, report)
            fingerprint.name = 'cves'
            for port, service in target.services.items():
                correlate(fingerprint, target, port, f'{service.product} {service.version} {service.extra}')
            async def check(cls):
                checker = cls(network, report)
                try:
                    async with asyncio.timeout(checker_timeout):
                        await checker.run(target)
                except Exception as exc:
                    report.errors.append(f'{host}: {checker.name}: {type(exc).__name__}: {exc}')
            await asyncio.gather(*(check(cls) for cls in (DnsChecker,TlsChecker,HttpChecker,BannerChecker)))
            emit(f'finished {host}: {len(target.ports)} open port(s)')

    await asyncio.gather(*(one(host) for host in targets))
    # The same version can arrive from nmap and a native banner probe.
    seen = set()
    unique = []
    for finding in report.findings:
        key = (finding.target, finding.ip, finding.port, finding.cves[0]) if finding.cves else None
        if key is not None and key in seen:
            continue
        if key is not None:
            seen.add(key)
        unique.append(finding)
    report.findings = unique
    return report


def run_scan_sync(*args, **kwargs):
    """Synchronous clients share the same mandatory authorization boundary."""
    return asyncio.run(run_scan(*args, **kwargs))
