"""Full CLI wiring with synthetic transports, without weakening the guard."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, AsyncMock

from vulnscope2.__main__ import main
from vulnscope2.checkers.base import Network
from vulnscope2.models import Target
from test_nmap_ingest import XML


class PipelineTests(unittest.TestCase):
    def test_nmap_to_nonstandard_http_to_cve_and_reports(self):
        requests = []
        @asynccontextmanager
        async def connect(network,target,port,context=None,**kwargs):
            self.assertEqual(target.ip,'192.0.2.10')
            self.assertEqual(port,8081)
            reader = asyncio.StreamReader()
            class Writer:
                def write(self, data):
                    requests.append(data)
                    head = b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\nContent-Length: 2\r\n'
                    origin = next((line[8:] for line in data.split(b'\r\n') if line.startswith(b'Origin: ')),None)
                    if origin:
                        head += b'Access-Control-Allow-Origin: ' + origin + b'\r\nAccess-Control-Allow-Credentials: true\r\n'
                    if data.startswith(b'OPTIONS'):
                        head += b'Allow: GET, OPTIONS\r\n'
                    reader.feed_data(head + b'\r\nok')
                    reader.feed_eof()
                async def drain(self):
                    pass
            yield reader,Writer()
        async def create(*args,**kwargs):
            self.assertEqual(args[-1],'192.0.2.10')
            kwargs['stdout'].write(XML)
            kwargs['stdout'].flush()
            process = AsyncMock()
            process.returncode = 0
            return process
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'scope').write_text('allow 192.0.2.10\n')
            with patch('vulnscope2.nmap.find_nmap',return_value='/fixture/nmap'), \
                 patch('vulnscope2.nmap.asyncio.create_subprocess_exec',side_effect=create), \
                 patch.object(Network,'connect',connect), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = main(['--scope',str(root/'scope'),'--authorized-by','synthetic fixture',
                             '--nmap','--ports','8081','--json',str(root/'report.json'),
                             '--html',str(root/'report.html'),'192.0.2.10'])
            report = json.loads((root/'report.json').read_text())
            self.assertEqual(code,2)
            self.assertTrue(report['complete'])
            self.assertEqual(report['services']['192.0.2.10']['services'][0]['version'],'2.4.49')
            self.assertEqual(len([f for f in report['findings'] if f['cves']]),1)
            self.assertTrue(any(f['validation'] == 'confirmed' for f in report['findings']))
            self.assertIn('CVE-2021-41773',(root/'report.html').read_text())
            self.assertTrue(any(req.startswith(b'OPTIONS') for req in requests))
            self.assertTrue(all(req.startswith((b'GET ',b'OPTIONS ')) for req in requests))

    def test_cli_authorization_and_scope_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'scope'
            path.write_text('allow 192.0.2.10')
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(['--scope',str(path),'--authorized-by',' ','192.0.2.10']),2)
                with self.assertRaises(SystemExit):
                    main(['--scope',str(path),'192.0.2.10'])


class PinningTests(unittest.IsolatedAsyncioTestCase):
    async def test_numeric_socket_and_hostname_sni(self):
        import ssl
        from unittest.mock import MagicMock
        raw = MagicMock()
        reader, writer = MagicMock(), MagicMock()
        loop = asyncio.get_running_loop()
        with patch('vulnscope2.checkers.base.socket.socket',return_value=raw), \
             patch.object(loop,'sock_connect',new_callable=AsyncMock) as connect, \
             patch('vulnscope2.checkers.base.asyncio.open_connection',new_callable=AsyncMock,return_value=(reader,writer)) as opened:
            async with Network().connect(Target('example.test','192.0.2.10'),443,ssl.create_default_context()):
                pass
        connect.assert_awaited_once_with(raw,('192.0.2.10',443))
        self.assertEqual(opened.call_args.kwargs['server_hostname'],'example.test')
        self.assertNotIn('host',opened.call_args.kwargs)
        self.assertEqual(opened.call_args.kwargs['sock'],raw)
        writer.transport.abort.assert_called_once()
