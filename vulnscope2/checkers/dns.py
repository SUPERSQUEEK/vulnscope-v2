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
                             remediation='Publish one SPF TXT record listing every host and service authorized to send mail '
                             'for this name, ending in "-all" to hard-fail all others (e.g. '
                             '"v=spf1 include:_spf.google.com ip4:198.51.100.0/24 -all"). If this name never sends mail, '
                             'publish "v=spf1 -all" so spoofed mail from it is rejected outright.',
                             reference='https://datatracker.ietf.org/doc/html/rfc7208')
            elif len(policies) > 1:
                self.finding(target, None, 'Multiple SPF policies', 'medium',
                             'Multiple SPF records cause a policy evaluation error.', evidence,
                             remediation='Merge every sending source into a single SPF TXT record. RFC 7208 permits only one '
                             'SPF record per name; more than one causes a PermError that voids SPF entirely, so combine the '
                             'include:/ip4:/ip6: mechanisms into one string ending in "-all".',
                             reference='https://datatracker.ietf.org/doc/html/rfc7208')
            elif any(term in {'all','+all'} for term in policies[0].lower().split()):
                self.finding(target, None, 'SPF permits any sender', 'high',
                             'The policy contains an unconditional pass mechanism.', evidence,
                             remediation='Remove the "+all"/"all" mechanism, which authorizes the entire internet to send as '
                             'this domain. After enumerating legitimate senders with include:/ip4:/ip6:, end the record with '
                             '"-all" (hard fail), or "~all" (soft fail) only during a staged rollout.',
                             reference='https://datatracker.ietf.org/doc/html/rfc7208')
            elif '?all' in policies[0].lower().split():
                self.finding(target, None, 'SPF neutral catch-all', 'low',
                             'The policy makes no assertion about unlisted senders.', evidence)
        elif kind == 'DMARC':
            policies = [r for r in records if r.split(';', 1)[0].strip().lower() == 'v=dmarc1']
            if not policies:
                self.finding(target, None, 'No DMARC record at scanned name', 'medium',
                             'Organizational-domain inheritance is not evaluated.', evidence,
                             remediation='Publish a DMARC record as a TXT record at "_dmarc.<domain>", e.g. '
                             '"v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain; adkim=s; aspf=s". Begin at "p=none" '
                             'with rua reporting to observe legitimate mail, then raise to quarantine and reject. DMARC is '
                             'evaluated at the organizational domain, so a subdomain may inherit a parent policy.',
                             reference='https://datatracker.ietf.org/doc/html/rfc7489')
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
                                 remediation='Once your aggregate (rua) reports confirm that legitimate mail passes SPF or '
                                 'DKIM with alignment, raise the policy from "p=none" to "p=quarantine" and then "p=reject" '
                                 'so spoofed mail is actually blocked rather than only reported. Use "pct=" to roll '
                                 'enforcement out in stages if the sending estate is large.',
                                 reference='https://datatracker.ietf.org/doc/html/rfc7489')
        elif kind == 'DNSKEY':
            self.finding(target, None, 'DNSKEY observation', 'info',
                         'Key presence does not validate DNSSEC. Absence at a non-apex name does not establish an unsigned zone.', evidence)
        elif kind == 'CAA' and not records:
            self.finding(target, None, 'No CAA record at scanned name', 'info',
                         'CAA may be inherited from a parent; effective issuance policy is not established.', evidence)
