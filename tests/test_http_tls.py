from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import ssl
import unittest
from unittest.mock import patch
from vulnscope2.checkers.base import Network
from vulnscope2.checkers.http import HttpChecker, Response, read_response
from vulnscope2.checkers.tls import TlsChecker, context_for
from vulnscope2.findings import Report
from vulnscope2.models import Target, Service


class HttpTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.target = Target('example.test','192.0.2.10', {8081:Service(8081,name='http')})
        self.report = Report(authorized_by='test')
        self.checker = HttpChecker(Network(), self.report)

    async def test_cors_requires_two_unique_reflections(self):
        origins = []
        async def request(target, port, **kwargs):
            origin = kwargs['headers']['Origin']
            origins.append(origin)
            return Response(200,[('access-control-allow-origin',origin), ('access-control-allow-credentials','true')],b'ok')
        self.checker.request = request
        await self.checker.cors(self.target,8081,Response(200,[],b''))
        self.assertEqual(len(set(origins)),2)
        self.assertEqual(self.report.findings[0].validation,'confirmed')
        self.assertEqual(self.report.findings[0].severity,'high')

    async def test_static_or_duplicate_cors_does_not_confirm(self):
        async def request(*args, **kwargs):
            return Response(200,[('access-control-allow-origin','https://fixed.test')],b'ok')
        self.checker.request = request
        await self.checker.cors(self.target,8081,None)
        self.assertFalse(self.report.findings)

    async def test_redirect_is_repeated_but_never_followed(self):
        calls = []
        async def request(target,port,path='/',**kwargs):
            calls.append((target.ip,path))
            return Response(302,[('location','http://169.254.169.254/latest/meta-data')],b'')
        self.checker.request = request
        self.target.services[8081].tunnel = 'ssl'
        await self.checker.redirect(self.target,8081,await request(self.target,8081))
        self.assertEqual(calls,[('192.0.2.10','/'),('192.0.2.10','/')])
        self.assertEqual(self.report.findings[0].title,'Confirmed HTTPS downgrade redirect')

    async def test_options_advertisement_never_sends_mutating_method(self):
        methods = []
        async def request(*args,**kwargs):
            methods.append(kwargs.get('method','GET'))
            return Response(200,[('allow','GET, PUT, DELETE')],b'')
        self.checker.request = request
        await self.checker.options(self.target,8081,None)
        self.assertEqual(methods,['OPTIONS'])
        self.assertTrue(all(f.validation == 'observed' for f in self.report.findings))

    async def test_wire_host_header_nonstandard_port_and_no_proxy(self):
        wire = []
        reader = asyncio.StreamReader()
        reader.feed_data(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
        reader.feed_eof()
        class Writer:
            def write(self, data):
                wire.append(data)
            async def drain(self):
                pass
        @asynccontextmanager
        async def connect(target,port,context):
            self.assertEqual(target.ip,'192.0.2.10')
            self.assertEqual(port,8081)
            yield reader, Writer()
        self.checker.network.connect = connect
        response = await self.checker.request(self.target,8081)
        self.assertIn(b'Host: example.test:8081\r\n',wire[0])
        self.assertEqual(response.body,b'ok')

    async def test_chunked_and_duplicate_cookie_parsing(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n2\r\nok\r\n0\r\n\r\n')
        reader.feed_eof()
        response = await read_response(reader)
        self.assertEqual(response.body,b'ok')
        self.assertEqual(len(response.values('set-cookie')),2)

    async def test_false_exposure_catchall_is_not_confirmed(self):
        async def request(*args,**kwargs):
            return Response(200,[],b'<html>Welcome</html>')
        self.checker.request = request
        await self.checker.exposures(self.target,8081,await request())
        self.assertFalse(self.report.findings)

    async def test_exposure_signature_retains_no_secret(self):
        async def request(target,port,path):
            return Response(200,[],b'API_KEY=supersecret' if path == '/.env' else b'<html>Not found</html>')
        self.checker.request = request
        await self.checker.exposures(self.target,8081,Response(200,[],b'home'))
        self.assertEqual(len(self.report.findings),1)
        self.assertNotIn('supersecret',self.report.findings[0].evidence)


class TlsTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_protocol_and_cipher_context(self):
        context = context_for(ssl.TLSVersion.TLSv1_2,'AES128-SHA')
        self.assertEqual(context.minimum_version,ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.maximum_version,ssl.TLSVersion.TLSv1_2)
        self.assertEqual([c['name'] for c in context.get_ciphers() if c['protocol'] != 'TLSv1.3'], ['AES128-SHA'])

    async def test_deprecated_protocol_confirmed_and_failures_inconclusive(self):
        report = Report()
        checker = TlsChecker(Network(),report)
        async def handshake(target,port,context):
            if context.verify_mode == ssl.CERT_REQUIRED:
                raise ssl.SSLCertVerificationError('certificate expired')
            if context.maximum_version == ssl.TLSVersion.TLSv1:
                return 'TLSv1','AES128-SHA',{}
            raise ssl.SSLError('unsupported here')
        checker.handshake = handshake
        await checker.inspect(Target('example.test','192.0.2.10'),443)
        self.assertTrue(any(f.title == 'Confirmed deprecated TLSv1' for f in report.findings))
        summary = next(f for f in report.findings if f.title == 'TLS protocol enumeration')
        self.assertIn('inconclusive',summary.detail)
        self.assertNotIn('no 1.3',str(report.findings))

    async def test_cipher_evidence_survives_cancellation(self):
        report = Report()
        checker = TlsChecker(Network(),report)
        attempts = 0
        async def handshake(target,port,context):
            nonlocal attempts
            attempts += 1
            if attempts == 7:
                raise asyncio.CancelledError()
            if attempts == 1:
                return 'TLSv1.2','AES128-SHA',{}
            version = {ssl.TLSVersion.TLSv1:'TLSv1',ssl.TLSVersion.TLSv1_1:'TLSv1.1',
                       ssl.TLSVersion.TLSv1_2:'TLSv1.2',ssl.TLSVersion.TLSv1_3:'TLSv1.3'}[context.maximum_version]
            return version,'AES128-SHA',{}
        checker.handshake = handshake
        with self.assertRaises(asyncio.CancelledError):
            await checker.inspect(Target('example.test','192.0.2.10'),443)
        summary = next(f for f in report.findings if f.title == 'TLS 1.2 cipher enumeration')
        self.assertIn("accepted=['AES128-SHA']",summary.evidence)
