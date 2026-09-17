"""CLI and library callers use the same fail-closed scanning engine."""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import sys
from .scope import Scope, ScopeError
from .engine import run_scan
from .models import port_number
from .ingest import load_ingest
from . import reporting


def parse_ports(text):
    ports = set()
    for item in text.split(','):
        if '-' in item:
            first, last = item.split('-', 1)
            start, end = port_number(first), port_number(last)
            if start > end or end - start >= 4096:
                raise ValueError('Invalid or oversized port range')
            ports.update(range(start, end + 1))
        else:
            ports.add(port_number(item))
    if len(ports) > 4096:
        raise ValueError('At most 4096 ports may be selected')
    return ports


def main(argv=None):
    parser = argparse.ArgumentParser(prog='vulnscope2', description='Scoped async vulnerability assessment and active validation')
    parser.add_argument('targets', nargs='*', help='Individual hosts, IPs or URLs; CIDRs belong in scope rules')
    parser.add_argument('--scope', required=True)
    parser.add_argument('--authorized-by', required=True)
    discovery = parser.add_mutually_exclusive_group()
    discovery.add_argument('--nmap', action='store_true', help='Real nmap TCP service/version scan; fallback if absent')
    discovery.add_argument('--ingest', help='External JSON discoveries; still subject to guard()')
    parser.add_argument('--ports', help='Comma-separated ports/ranges; default curated service ports')
    parser.add_argument('--timeout', type=float, default=6)
    parser.add_argument('--nmap-timeout', type=float, default=180)
    parser.add_argument('--checker-timeout', type=float, default=180)
    parser.add_argument('--concurrency', type=int, default=32)
    parser.add_argument('--target-concurrency', type=int, default=4)
    parser.add_argument('--json', metavar='PATH')
    parser.add_argument('--html', metavar='PATH')
    parser.add_argument('--quiet', action='store_true')
    args = parser.parse_args(argv)
    try:
        scope = Scope.from_lines(Path(args.scope).read_text(encoding='utf-8').splitlines())
        ingest = load_ingest(args.ingest) if args.ingest else None
        if ingest is not None and args.ports:
            raise ValueError('--ports cannot be combined with --ingest')
        targets = args.targets or list(ingest or {})
        report = asyncio.run(run_scan(targets, scope, args.authorized_by, ingest=ingest,
                            ports=parse_ports(args.ports) if args.ports else None,
                            nmap=args.nmap, timeout=args.timeout, concurrency=args.concurrency,
                            target_concurrency=args.target_concurrency, nmap_timeout=args.nmap_timeout,
                            checker_timeout=args.checker_timeout,
                            on_event=None if args.quiet else lambda msg: print(msg, file=sys.stderr)))
        print(reporting.console(report))
        if args.json:
            Path(args.json).write_text(reporting.to_json(report), encoding='utf-8')
        if args.html:
            Path(args.html).write_text(reporting.to_html(report), encoding='utf-8')
        return report.exit_code
    except (OSError, ScopeError, ValueError, KeyError, TypeError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('Scan cancelled.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
