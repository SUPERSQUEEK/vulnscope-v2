"""Bounded GET/OPTIONS probes validate behavior without following redirects.

No cookie jar, proxy environment, authorization headers, or state-changing
methods are used. CORS needs two independent observations to earn confirmation.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from http.cookies import SimpleCookie, CookieError
import re
import secrets
import ssl
from urllib.parse import urljoin, urlsplit
from .base import Checker
from ..cves import correlate

HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 9200, 11434}
TLS_PORTS = {443, 8443}
BODY_LIMIT = 32768


@dataclass
class Response:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def values(self, name):
        return [v for k, v in self.headers if k == name]

    def get(self, name, default=''):
        values = self.values(name)
        return values[0] if len(values) == 1 else default


def is_https(service):
    return service.tunnel == 'ssl' or service.name in {'https', 'https-alt'} or service.port in TLS_PORTS


async def read_response(reader):
    block = await reader.readuntil(b'\r\n\r\n')
    if len(block) > 32768:
        raise ValueError('HTTP headers exceed 32 KiB')
    lines = block.decode('iso-8859-1').split('\r\n')
    match = re.fullmatch(r'HTTP/1\.[01] ([0-9]{3})(?: .*)?', lines[0])
    if not match:
        raise ValueError('Invalid HTTP status line')
    headers = []
    for line in lines[1:-2]:
        name, sep, value = line.partition(':')
        if not sep or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError('Invalid HTTP header')
        headers.append((name.lower(), value.strip()))
    response = Response(int(match.group(1)), headers, b'')
    if response.status < 200 or response.status in {204, 304}:
        return response
    if response.get('transfer-encoding').lower() == 'chunked':
        body = bytearray()
        for _ in range(4096):
            line = await reader.readline()
            size = int(line.split(b';', 1)[0].strip(), 16)
            if size < 0:
                raise ValueError('Invalid chunk size')
            if not size:
                break
            count = min(size, BODY_LIMIT - len(body))
            body.extend(await reader.readexactly(count))
            if len(body) == BODY_LIMIT:
                break
            if await reader.readexactly(2) != b'\r\n':
                raise ValueError('Invalid chunk delimiter')
        response.body = bytes(body)
    elif response.get('content-length'):
        size = int(response.get('content-length'))
        if size < 0:
            raise ValueError('Invalid Content-Length')
        response.body = await reader.readexactly(min(size, BODY_LIMIT))
    else:
        chunks = bytearray()
        while len(chunks) < BODY_LIMIT:
            chunk = await reader.read(BODY_LIMIT - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        response.body = bytes(chunks)
    return response


class HttpChecker(Checker):
    name = 'http'

    async def run(self, target):
        ports = {p for p, s in target.services.items() if p in HTTP_PORTS | TLS_PORTS
                 or s.name in {'http', 'http-alt', 'http-proxy', 'https', 'https-alt'}}
        await self.each(target, ports, self.inspect)

    async def request(self, target, port, path='/', method='GET', headers=None):
        if method not in {'GET', 'OPTIONS'}:
            raise ValueError('Only read-only HTTP probes are permitted')
        if not path.startswith('/') or any(ord(c) < 33 or ord(c) > 126 for c in path):
            raise ValueError('Invalid request path')
        tls = is_https(target.services[port])
        context = None
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # TlsChecker reports trust separately.
        host = f'[{target.host}]' if ':' in target.host else target.host
        if port != (443 if tls else 80):
            host += f':{port}'
        hdrs = {'Host': host, 'User-Agent': 'vulnscope2/2.0 authorized-assessment',
                'Accept-Encoding': 'identity', 'Connection': 'close'}
        hdrs.update(headers or {})
        if any('\r' in v or '\n' in v for v in hdrs.values()):
            raise ValueError('Invalid request header')
        wire = f'{method} {path} HTTP/1.1\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in hdrs.items()) + '\r\n'
        async with self.network.connect(target, port, context) as (reader, writer):
            writer.write(wire.encode('ascii'))
            await writer.drain()
            return await read_response(reader)

    async def inspect(self, target, port):
        baseline = await self.request(target, port)
        tls = is_https(target.services[port])
        self.finding(target, port, 'HTTP response fingerprint', 'info',
                     'Status and technology indicators from a bounded unauthenticated response.',
                     f'GET / -> {baseline.status}; ' + '; '.join(
                         f'{k}: {v}' for k, v in baseline.headers
                         if k in {'server','x-powered-by','via','x-generator','content-type'}))
        server = baseline.get('server')
        if any(char.isdigit() for char in server):
            self.finding(target, port, 'Server version disclosure', 'low',
                         'The Server header discloses a version-like identifier.',
                         f'Server: {server}', remediation='Suppress unnecessary version details.')
        correlate(self, target, port, f'Server: {server}')
        signatures = {b'wp-content': 'WordPress', b'__NEXT_DATA__': 'Next.js',
                      b'/_next/': 'Next.js', b'drupalSettings': 'Drupal',
                      b'laravel_session': 'Laravel', b'ng-version=': 'Angular',
                      b'data-reactroot': 'React', b'Shopify.theme': 'Shopify'}
        seen = set()
        for marker, technology in signatures.items():
            if marker in baseline.body and technology not in seen:
                seen.add(technology)
                self.finding(target, port, f'{technology} fingerprint', 'info',
                             'A markup signature suggests this technology; it is not authoritative.',
                             f'GET / body contains {marker!r}')
        if 200 <= baseline.status < 300:
            expected = {'content-security-policy':'medium', 'x-content-type-options':'low',
                        'x-frame-options':'low'}
            if tls:
                expected['strict-transport-security'] = 'medium'
            for header, severity in expected.items():
                if header == 'x-frame-options' and 'frame-ancestors' in baseline.get('content-security-policy').lower():
                    continue
                if not baseline.values(header):
                    self.finding(target, port, f'Missing {header}', severity,
                                 'This response lacks a browser hardening header; impact depends on the application.',
                                 f'GET / -> {baseline.status}; {header} absent',
                                 remediation=f'Configure an appropriate {header} policy.')
        for raw in baseline.values('set-cookie'):
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except CookieError:
                continue
            for name, value in cookie.items():
                for attribute in ('secure','httponly','samesite'):
                    if not value[attribute]:
                        self.finding(target, port, f'Cookie {name} missing {attribute}', 'low',
                                     'Cookie hardening depends on its purpose; review this attribute.',
                                     f'Set-Cookie: {name}=<redacted>; missing {attribute}',
                                     remediation=f'Consider setting {attribute} for this cookie.')
        # Independent probes retain baseline findings even when one probe fails.
        for probe in (self.cors, self.options, self.redirect, self.exposures):
            try:
                await probe(target, port, baseline)
            except Exception as exc:
                self.error(target, f'port {port}, {probe.__name__}: {type(exc).__name__}: {exc}')

    async def cors(self, target, port, baseline):
        origins = [f'https://{secrets.token_hex(8)}.vulnscope.invalid' for _ in range(2)]
        replies = [await self.request(target, port, headers={'Origin': origin}) for origin in origins]
        if all(200 <= reply.status < 300 and reply.get('access-control-allow-origin') == origin
               for origin, reply in zip(origins, replies)):
            credentials = all(reply.get('access-control-allow-credentials') == 'true' for reply in replies)
            evidence = '; '.join(f'Origin {origin} -> {reply.status}, ACAO={reply.get("access-control-allow-origin")}, '
                                 f'ACAC={reply.get("access-control-allow-credentials")}'
                                 for origin, reply in zip(origins, replies))
            self.finding(target, port, 'Confirmed arbitrary-origin CORS reflection',
                         'high' if credentials else 'medium',
                         'Two unique origins were reflected' + (' with credentials enabled.' if credentials else '.') +
                         ' Authenticated data exposure was not tested.', evidence, validation='confirmed',
                         remediation='Use an explicit trusted-origin allowlist.')

    async def options(self, target, port, baseline):
        reply = await self.request(target, port, method='OPTIONS')
        allow = reply.get('allow')
        self.finding(target, port, 'HTTP method advertisement', 'info',
                     'OPTIONS advertises methods; support and authorization for mutating methods are not tested.',
                     f'OPTIONS / -> {reply.status}; Allow: {allow or "(absent)"}')
        methods = {value.strip().upper() for value in allow.split(',')}
        if methods & {'TRACE', 'PUT', 'DELETE', 'CONNECT'}:
            self.finding(target, port, 'Review advertised HTTP methods', 'low',
                         'Potentially sensitive methods are advertised. This alone does not prove they are usable.',
                         f'OPTIONS / -> {reply.status}; Allow: {allow}',
                         remediation='Restrict unnecessary methods and verify application authorization.')

    async def redirect(self, target, port, baseline):
        if baseline.status not in {301,302,303,307,308} or not baseline.get('location'):
            return
        repeat = await self.request(target, port)
        if repeat.status != baseline.status or repeat.get('location') != baseline.get('location'):
            return
        scheme = 'https' if is_https(target.services[port]) else 'http'
        host = f'[{target.host}]' if ':' in target.host else target.host
        destination = urlsplit(urljoin(f'{scheme}://{host}:{port}/', repeat.get('location')))
        downgrade = scheme == 'https' and destination.scheme == 'http'
        self.finding(target, port, 'Confirmed HTTPS downgrade redirect' if downgrade else 'Confirmed redirect destination',
                     'medium' if downgrade else 'info',
                     'Two requests returned the same Location. The destination was not contacted; this does not establish an open redirect.',
                     f'GET / twice -> {repeat.status}; Location: {repeat.get("location")}', validation='confirmed',
                     remediation='Redirect HTTPS clients only to HTTPS destinations.' if downgrade else '')

    async def exposures(self, target, port, baseline):
        # The same five fixed paths as v1; format signatures avoid catch-all 200s.
        signatures = {
            '/.git/config': (rb'(?m)^\[core\]\s*$', 'Git configuration', 'high'),
            '/.env': (rb'(?m)^(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY)\s*=\s*[^\s]+', 'Environment configuration', 'high'),
            '/server-status': (rb'Apache Server Status|Total Accesses:', 'Apache status', 'medium'),
            '/.aws/credentials': (rb'(?m)^aws_secret_access_key\s*=\s*[^\s]+', 'AWS credential configuration', 'critical'),
            '/config.php.bak': (rb'<\?php[\s\S]*(?:\$[A-Za-z_]+\s*=|define\s*\()', 'PHP source backup', 'high'),
        }
        for path, (pattern, label, severity) in signatures.items():
            try:
                reply = await self.request(target, port, path)
                if reply.status == 200 and reply.body != baseline.body and re.search(pattern, reply.body):
                    self.finding(target, port, f'{label} exposed', severity,
                                 'The public response matches the expected file format. Secret values are not retained in the report.',
                                 f'GET {path} -> 200; format marker {pattern!r}; {len(reply.body)} bytes inspected',
                                 validation='confirmed', remediation='Remove this resource from the public web root and review exposed credentials.')
            except Exception as exc:
                self.error(target, f'port {port}, {path}: {type(exc).__name__}: {exc}')
