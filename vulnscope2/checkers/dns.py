"""Review records at the exact scoped name without guessing a registrable apex."""
from __future__ import annotations

import asyncio
import ipaddress
from .base import Checker
from ..dnsclient import query


class DnsChecker(Checker):
    name = 'dns'

    async def run(self, target):
        try:
            ipaddress.ip_address(target.host)
            return
        except ValueError:
            pass
        async def inspect(kind, name):
            try:
                records = await query(name, 'TXT' if kind in {'SPF','DMARC'} else kind, self.network)
                self.evaluate(target, name, kind, records)
            except Exception as exc:
                self.error(target, f'{kind} {name}: {exc}')
        await asyncio.gather(*(inspect(kind, name) for kind, name in (
            ('SPF',target.host), ('DMARC','_dmarc.'+target.host),
            ('DNSKEY',target.host), ('CAA',target.host))))

    def evaluate(self, target, name, kind, records):
        evidence = f'{kind} at {name}: {records}'
        if kind == 'SPF':
            policies = [r for r in records if r.lower().split()[:1] == ['v=spf1']]
            if not policies:
                self.finding(target, None, 'No SPF record at scanned name', 'medium',
                             'Mail policy may live at another name; this scan does not infer the mail domain.', evidence,
                             remediation='Publish SPF if this name sends mail.')
            elif len(policies) > 1:
                self.finding(target, None, 'Multiple SPF policies', 'medium',
                             'Multiple SPF records cause a policy evaluation error.', evidence,
                             remediation='Consolidate senders into a single SPF record.')
            elif any(term in {'all','+all'} for term in policies[0].lower().split()):
                self.finding(target, None, 'SPF permits any sender', 'high',
                             'The policy contains an unconditional pass mechanism.', evidence,
                             remediation='Replace permissive all with an appropriate restrictive policy.')
            elif '?all' in policies[0].lower().split():
                self.finding(target, None, 'SPF neutral catch-all', 'low',
                             'The policy makes no assertion about unlisted senders.', evidence)
        elif kind == 'DMARC':
            policies = [r for r in records if r.split(';', 1)[0].strip().lower() == 'v=dmarc1']
            if not policies:
                self.finding(target, None, 'No DMARC record at scanned name', 'medium',
                             'Organizational-domain inheritance is not evaluated.', evidence,
                             remediation='Review the effective DMARC policy for your mail domain.')
            else:
                tags = {key.strip().lower(): value.strip().lower()
                        for part in policies[0].split(';') if '=' in part
                        for key, value in [part.split('=', 1)]}
                if len(policies) > 1 or tags.get('p') not in {'none','quarantine','reject'}:
                    self.finding(target, None, 'Invalid DMARC policy', 'medium',
                                 'Multiple records or missing/invalid p= policy.', evidence)
                elif tags['p'] == 'none':
                    self.finding(target, None, 'DMARC monitoring only', 'low',
                                 'The published policy requests reporting without enforcement.', evidence,
                                 remediation='Move to quarantine or reject after validating legitimate senders.')
        elif kind == 'DNSKEY':
            self.finding(target, None, 'DNSKEY observation', 'info',
                         'Key presence does not validate DNSSEC. Absence at a non-apex name does not establish an unsigned zone.', evidence)
        elif kind == 'CAA' and not records:
            self.finding(target, None, 'No CAA record at scanned name', 'info',
                         'CAA may be inherited from a parent; effective issuance policy is not established.', evidence)
