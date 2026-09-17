"""Actual handshakes enumerate protocols and locally available TLS 1.2 ciphers.

A failed handshake is inconclusive, not proof a server rejects a protocol.
Python exposes no TLS 1.3 cipher restriction API, so only its negotiated suite
is reported. No STARTTLS downgrade or malformed handshake probes are used.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import ssl
import warnings
from .base import Checker

TLS_PORTS = {443,8443,465,993,995}


def context_for(version=None, cipher=None, verify=False):
    context = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if version is not None:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
    if not verify:
        context.set_ciphers((cipher or 'ALL') + ':@SECLEVEL=0')
    return context


class TlsChecker(Checker):
    name = 'tls'

    async def run(self, target):
        ports = {p for p, s in target.services.items()
                 if p in TLS_PORTS or s.tunnel == 'ssl' or s.name in {'https','https-alt','imaps','pop3s','smtps'}}
        await self.each(target, ports, self.inspect)

    async def handshake(self, target, port, context):
        async with self.network.connect(target, port, context) as (_, writer):
            obj = writer.get_extra_info('ssl_object')
            return obj.version(), obj.cipher()[0], obj.getpeercert()

    async def inspect(self, target, port):
        try:
            protocol, cipher, cert = await self.handshake(target, port, context_for(verify=True))
            self.finding(target, port, 'Verified TLS certificate', 'info',
                         'The local trust store accepted the certificate chain and hostname.',
                         f'{protocol}; {cipher}; notAfter={cert.get("notAfter")}')
            if cert.get('notAfter'):
                expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), timezone.utc)
                days = (expiry - datetime.now(timezone.utc)).days
                if days < 14:
                    self.finding(target, port, 'Certificate expiring soon', 'medium',
                                 f'Certificate expires in {days} day(s).', f'notAfter={expiry.isoformat()}',
                                 remediation='Renew the certificate before expiration.')
        except ssl.SSLCertVerificationError as exc:
            self.finding(target, port, 'Certificate did not verify', 'high',
                         'The certificate failed local trust or hostname validation.', str(exc),
                         remediation='Install a valid certificate and full chain matching the hostname.', validation='confirmed')
        except (OSError, TimeoutError) as exc:
            self.report.notes.append(f'{target.host}:{port}: default TLS handshake: {exc or type(exc).__name__}')

        accepted = {}
        failures = {}
        for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            try:
                protocol, cipher, _ = await self.handshake(target, port, context_for(version))
                accepted[protocol] = cipher
                if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                    self.finding(target, port, f'Confirmed deprecated {protocol}', 'high',
                                 'An exact-version handshake succeeded.', f'{protocol}; cipher={cipher}',
                                 validation='confirmed', remediation='Disable TLS 1.0 and TLS 1.1.',
                                 reference='https://datatracker.ietf.org/doc/rfc8996/')
            except (OSError, TimeoutError, ValueError) as exc:
                failures[version.name] = str(exc) or type(exc).__name__
        self.finding(target, port, 'TLS protocol enumeration', 'info',
                     'Successful handshakes prove support. Other attempts are inconclusive and may be limited by local OpenSSL.',
                     f'accepted={accepted}; unsuccessful={failures}')
        if not accepted:
            self.error(target, f'port {port}: no TLS protocol handshake succeeded')
            return
        if 'TLSv1.2' not in accepted:
            return
        context = context_for(ssl.TLSVersion.TLSv1_2)
        ciphers = sorted({c['name'] for c in context.get_ciphers() if c['protocol'] != 'TLSv1.3'})
        supported = []
        inconclusive = []
        # Serial within a port bounds TLS load; different ports and targets still overlap.
        attempted = 0
        try:
            for cipher in ciphers:
                attempted += 1
                try:
                    _, negotiated, _ = await self.handshake(target, port, context_for(ssl.TLSVersion.TLSv1_2, cipher))
                    supported.append(negotiated)
                except (OSError, TimeoutError, ValueError):
                    inconclusive.append(cipher)
        finally:
            # A checker deadline must not discard successful cipher observations.
            self.finding(target, port, 'TLS 1.2 cipher enumeration', 'info',
                         'One handshake per locally available suite. TLS 1.3 suite enumeration is not exposed by Python ssl.',
                         f'attempted={attempted}/{len(ciphers)}; accepted={supported}; unsuccessful={len(inconclusive)}')
            self.cipher_findings(target, port, supported)

    def cipher_findings(self, target, port, supported):
        weak = [c for c in supported if any(x in c for x in ('RC4','DES','NULL','EXPORT','MD5')) or c.startswith('ADH-') or c.startswith('AECDH-')]
        if weak:
            self.finding(target, port, 'Confirmed weak TLS cipher support', 'high',
                         'Individual handshakes negotiated weak suites.', ', '.join(weak),
                         validation='confirmed', remediation='Disable anonymous, null, export, RC4 and DES cipher suites.')
        legacy = [c for c in supported if c not in weak and ('GCM' not in c and 'CHACHA20' not in c)]
        if legacy:
            self.finding(target, port, 'Legacy non-AEAD TLS ciphers accepted', 'low',
                         'These suites lack modern AEAD; this observation does not prove a specific cryptographic attack.',
                         ', '.join(legacy), validation='confirmed', remediation='Prefer ECDHE with AES-GCM or ChaCha20-Poly1305.')
