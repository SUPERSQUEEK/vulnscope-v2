"""Curated upstream ranges are candidates, never proof of exploitable code.

Vendor patch backports, platform, and configuration affect applicability.
Rules are offline and intentionally small; references identify their source.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    product: str
    minimum: tuple
    maximum: tuple  # inclusive
    cve: str
    severity: str
    condition: str
    reference: str


RULES = (
    Rule('apache', (2,4,49), (2,4,49), 'CVE-2021-41773', 'high',
         'Requires affected path access configuration; CGI affects impact.',
         'https://httpd.apache.org/security/vulnerabilities_24.html'),
    Rule('apache', (2,4,50), (2,4,50), 'CVE-2021-42013', 'high',
         'Incomplete traversal fix; applicability depends on access configuration.',
         'https://httpd.apache.org/security/vulnerabilities_24.html'),
    Rule('openssh', (8,5,0), (9,7,99), 'CVE-2024-6387', 'high',
         'Portable sshd on affected platforms; OpenBSD is excluded. Distribution backports may fix this.',
         'https://www.openssh.com/txt/release-9.8'),
    Rule('vsftpd', (2,3,4), (2,3,4), 'CVE-2011-2523', 'high',
         'Only compromised distribution artifacts were backdoored; version alone cannot establish provenance.',
         'https://nvd.nist.gov/vuln/detail/CVE-2011-2523'),
)
PATTERNS = (
    ('apache', re.compile(r'\bApache(?: httpd)?[/ _-]+(\d+\.\d+(?:\.\d+)?)(?![\d.])', re.I)),
    ('openssh', re.compile(r'\bOpenSSH[/ _-]+(\d+\.\d+(?:\.\d+)?)(?:p\d+)?(?![\d.])', re.I)),
    ('vsftpd', re.compile(r'\bvsftpd[/ _-]+(\d+\.\d+(?:\.\d+)?)(?![\d.])', re.I)),
)


def identify(text):
    for product, pattern in PATTERNS:
        match = pattern.search(text)
        if match:
            yield product, match.group(1)


def correlate(checker, target, port, text):
    for product, version in identify(text):
        numeric = tuple(int(p) for p in version.split('.'))
        numeric += (0,) * (3 - len(numeric))
        for rule in RULES:
            if product == rule.product and rule.minimum <= numeric <= rule.maximum:
                checker.finding(target, port, f'{rule.cve}: {product} version candidate', rule.severity,
                                f'Detected {version} matches an upstream affected range. {rule.condition} '
                                'Exploitability has not been tested.', text,
                                cves=[rule.cve], validation='candidate', reference=rule.reference,
                                remediation='Verify the installed package and vendor advisory; apply the supported security update.')
