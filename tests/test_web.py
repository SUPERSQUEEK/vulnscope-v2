"""Optional HTTP adapter tests; all successful discovery uses fixtures, never sockets."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import importlib.util
import ipaddress
import unittest
from unittest.mock import AsyncMock, patch

from vulnscope2.findings import Finding, Report
from vulnscope2 import reporting

WEB_AVAILABLE = all(importlib.util.find_spec(name) for name in ('fastapi', 'uvicorn', 'httpx'))
if WEB_AVAILABLE:
    import httpx
    from vulnscope2.web.app import create_app
    from vulnscope2.web.store import ScanStore
    from vulnscope2.scope import Scope


@unittest.skipUnless(WEB_AVAILABLE, 'Install requirements-web.txt and httpx for web tests')
class WebTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.app = create_app()
        self.lifespan = self.app.router.lifespan_context(self.app)
        await self.lifespan.__aenter__()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                                        base_url='http://127.0.0.1')
        config = (await self.client.get('/api/config')).json()
        self.headers = {'X-Vulnscope-Token': config['token']}
        self.valid = {'targets': ['127.0.0.1'], 'scope': 'allow 127.0.0.1',
                      'authorized_by': 'Web test / no target I/O', 'nmap': False}

    async def asyncTearDown(self):
        await self.client.aclose()
        await self.lifespan.__aexit__(None, None, None)

    async def start(self, data=None):
        response = await self.client.post('/api/scans', json=self.valid if data is None else data,
                                          headers=self.headers)
        self.assertEqual(response.status_code, 202, response.text)
        scan = self.app.state.store.runs[response.json()['id']]
        return scan

    async def test_missing_blank_and_invalid_governance_rejected_before_engine(self):
        with patch('vulnscope2.engine.run_scan', new_callable=AsyncMock) as run:
            for key in ('authorized_by', 'scope'):
                for value in (None, '', ' \n\t ', 123, [], {}):
                    with self.subTest(key=key, value=value):
                        data = dict(self.valid, **{key: value})
                        response = await self.client.post('/api/scans', json=data, headers=self.headers)
                        self.assertEqual(response.status_code, 422, response.text)
                data = dict(self.valid)
                del data[key]
                response = await self.client.post('/api/scans', json=data, headers=self.headers)
                self.assertEqual(response.status_code, 422)
            for scope in ('# comment only', 'deny 127.0.0.1', 'permit example.com', 'allow'):
                response = await self.client.post('/api/scans', json=dict(self.valid, scope=scope), headers=self.headers)
                self.assertEqual(response.status_code, 422)
            run.assert_not_awaited()
        self.assertFalse(self.app.state.store.runs)

    async def test_invalid_targets_and_options_never_schedule(self):
        invalid = [{'targets': []}, {'targets': 'example.com'}, {'targets': ['https://']},
                   {'targets': ['192.0.2.0/24']}, {'targets': [None]}, {'targets': ['']},
                   {'targets': ['a.example'] * 65}, {'nmap': 'true'}, {'nmap': 1},
                   {'skip_scope': True}, {'scope': 'a' * 65537}, {'authorized_by': 'a' * 1025}]
        with patch('vulnscope2.engine.run_scan', new_callable=AsyncMock) as run:
            for fields in invalid:
                with self.subTest(fields=list(fields)):
                    response = await self.client.post('/api/scans', json=dict(self.valid, **fields), headers=self.headers)
                    self.assertEqual(response.status_code, 422)
            run.assert_not_awaited()

    async def test_url_targets_and_bare_scope_accepted_with_real_guard(self):
        data = dict(self.valid, targets=['https://amirslm.com/', 'amirslm.com:443/foo'],
                    scope='amirslm.com')
        with patch('vulnscope2.scope._resolve', return_value={ipaddress.ip_address('192.0.2.8')}), \
             patch('vulnscope2.engine.PortChecker.run', new_callable=AsyncMock) as ports, \
             patch('vulnscope2.engine.DnsChecker.run', new_callable=AsyncMock):
            scan = await self.start(data)
            await scan.task
            self.assertEqual(scan.targets, ['amirslm.com'])
            self.assertTrue(scan.report.to_dict()['complete'])
            self.assertEqual(ports.call_args.args[0].ip, '192.0.2.8')
        response = await self.client.post('/api/scans', json=dict(data, scope=''), headers=self.headers)
        self.assertEqual(response.status_code, 422)

    async def test_normalization_affordance_never_schedules_or_resolves(self):
        with patch('vulnscope2.scope._resolve') as resolve, \
             patch('vulnscope2.engine.run_scan', new_callable=AsyncMock) as run:
            response = await self.client.post('/api/targets/normalize',
                json={'targets': ['https://amirslm.com/', 'amirslm.com:443/foo', 'http://[2001:db8::1]/']},
                headers=self.headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['targets'], ['amirslm.com', '2001:db8::1'])
            for data in ({'targets': []}, {'targets': ['192.0.2.0/24']}, None, {'targets': ['https://']},
                         {'targets': ['example.com'], 'scope': 'example.com'}):
                response = await self.client.post('/api/targets/normalize', json=data, headers=self.headers)
                self.assertIn(response.status_code, (415, 422))
            resolve.assert_not_called()
            run.assert_not_awaited()
        self.assertFalse(self.app.state.store.runs)

    async def test_bad_bodies_and_browser_boundary(self):
        response = await self.client.post('/api/scans', json=self.valid)
        self.assertEqual(response.status_code, 403)
        for headers in ({'Origin': 'https://foreign.example'}, {'Sec-Fetch-Site': 'cross-site'}):
            response = await self.client.post('/api/scans', json=self.valid, headers=self.headers | headers)
            self.assertEqual(response.status_code, 403)
        response = await self.client.get('/api/config', headers={'Host': 'rebinding.example'})
        self.assertEqual(response.status_code, 400)
        response = await self.client.post('/api/scans', content='{}', headers=self.headers)
        self.assertEqual(response.status_code, 415)
        for body in ('{', 'null', '[]'):
            response = await self.client.post('/api/scans', content=body, headers=self.headers | {'Content-Type': 'application/json'})
            self.assertEqual(response.status_code, 422)
        response = await self.client.post('/api/scans', content=b'x' * (128 * 1024 + 1),
                                          headers=self.headers | {'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 413)

    async def test_real_engine_permanent_refusal_sse_and_exact_downloads(self):
        with patch('vulnscope2.engine.PortChecker.run', new_callable=AsyncMock) as ports:
            scan = await self.start()
            await scan.task
            ports.assert_not_awaited()
        status = (await self.client.get(f'/api/scans/{scan.id}')).json()
        self.assertEqual(status['state'], 'completed')
        self.assertFalse(status['report']['complete'])
        self.assertIn('permanently denied', status['report']['errors'][0])
        self.assertEqual(status['report']['exit_code'], 0)
        events = await self.client.get(f'/api/scans/{scan.id}/events')
        self.assertIn('text/event-stream', events.headers['content-type'])
        self.assertIn('event: progress', events.text)
        self.assertIn('refused 127.0.0.1', events.text)
        self.assertIn('event: done', events.text)
        resumed = await self.client.get(f'/api/scans/{scan.id}/events', headers={'Last-Event-ID': '2'})
        self.assertNotIn('id: 1\n', resumed.text)
        for format, serialize in [('json', reporting.to_json), ('html', reporting.to_html)]:
            response = await self.client.get(f'/api/scans/{scan.id}/report.{format}')
            self.assertEqual(response.content, serialize(scan.report).encode())
            self.assertIn('attachment;', response.headers['content-disposition'])

    async def test_real_engine_native_discovery_to_candidate_report_with_fixture_transport(self):
        @asynccontextmanager
        async def connection(network, target, port, **kwargs):
            self.assertEqual(target.ip, '192.0.2.8')
            if port != 22:
                raise ConnectionRefusedError
            reader = asyncio.StreamReader()
            reader.feed_data(b'SSH-2.0-OpenSSH_9.0\r\n')
            reader.feed_eof()
            yield reader, None

        # The real guard authorizes a documentation IP; only transport is a fixture.
        with patch('vulnscope2.checkers.base.Network.connect', connection):
            scan = await self.start({'targets': ['192.0.2.8'], 'scope': 'allow 192.0.2.8',
                                     'authorized_by': 'Synthetic transport fixture', 'nmap': False})
            await scan.task
        data = (await self.client.get(f'/api/scans/{scan.id}')).json()['report']
        self.assertTrue(data['complete'])
        self.assertEqual(data['worst'], 'high')
        self.assertEqual(data['findings'][0]['validation'], 'candidate')
        self.assertEqual(data['findings'][0]['cves'], ['CVE-2024-6387'])
        self.assertTrue(all(finding['ip'] == '192.0.2.8' for finding in data['findings']))
        self.assertEqual(data['services']['192.0.2.8']['services'][0]['source'], 'tcp-connect')
        for format, serialize in [('json', reporting.to_json), ('html', reporting.to_html)]:
            response = await self.client.get(f'/api/scans/{scan.id}/report.{format}')
            self.assertEqual(response.content, serialize(scan.report).encode())

    async def test_task_streams_before_completion_and_forwards_core_options(self):
        release = asyncio.Event()
        started = asyncio.Event()
        report = Report(authorized_by='fixture', targets=['example.com'])
        report.add(Finding('example.com', 22, 'banners', '<script>remote</script>', 'high',
                           'Review applicability', 'SSH fixture', ip='192.0.2.8',
                           validation='candidate', cves=['CVE-2024-6387']))

        async def run(targets, scope, *, authorized_by, nmap, on_event):
            self.assertEqual(targets, ['example.com'])
            self.assertEqual(authorized_by, 'fixture')
            self.assertTrue(nmap)
            self.assertTrue(scope._host_allowed('example.com'))
            on_event('scanning example.com (192.0.2.8)\nnext line')
            started.set()
            await release.wait()
            return report

        with patch('vulnscope2.engine.run_scan', run):
            scan = await self.start({'targets': ['EXAMPLE.COM.', 'example.com'],
                                     'scope': 'allow example.com', 'authorized_by': ' fixture ', 'nmap': True})
            await asyncio.wait_for(started.wait(), 1)
            self.assertFalse(scan.task.done())
            streams = [scan.stream(after=2), scan.stream(after=2)]
            for stream in streams:
                progress = await anext(stream)
                self.assertIn('event: progress', progress)
                self.assertIn('\\nnext line', progress)  # Never inject an SSE frame.
                await stream.aclose()
            pending = await self.client.get(f'/api/scans/{scan.id}/report.json')
            self.assertEqual(pending.status_code, 409)
            release.set()
            await scan.task
        response = await self.client.get(f'/api/scans/{scan.id}/report.json')
        self.assertEqual(response.text, reporting.to_json(report))
        html = await self.client.get(f'/api/scans/{scan.id}/report.html')
        self.assertIn('&lt;script&gt;', html.text)
        self.assertNotIn('<script>remote', html.text)

    async def test_failure_and_cancellation_do_not_look_complete(self):
        with patch('vulnscope2.engine.run_scan', side_effect=RuntimeError('fixture failure')):
            scan = await self.start()
            await scan.task
        self.assertEqual(scan.state, 'failed')
        self.assertIsNone(scan.report)
        self.assertIn('fixture failure', scan.error)
        cleaned = asyncio.Event()
        async def blocked(*args, **kwargs):
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()
        with patch('vulnscope2.engine.run_scan', blocked):
            scan = await self.start()
            await asyncio.sleep(0)
            response = await self.client.post(f'/api/scans/{scan.id}/cancel', json={}, headers=self.headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['state'], 'cancelled')
            self.assertIsNone(response.json()['report'])
            self.assertTrue(cleaned.is_set())
            self.assertTrue(scan.task.done())

    async def test_capacity_eviction_and_shutdown(self):
        store = ScanStore(max_runs=2, max_active=1)
        scope = Scope.from_lines(['allow 127.0.0.1'])
        first = store.start(['127.0.0.1'], scope, 'fixture', False)
        with self.assertRaises(ValueError):
            store.start(['127.0.0.1'], scope, 'fixture', False)
        await first.task
        second = store.start(['127.0.0.1'], scope, 'fixture', False)
        await second.task
        third = store.start(['127.0.0.1'], scope, 'fixture', False)
        self.assertNotIn(first.id, store.runs)
        await store.close()
        self.assertTrue(third.done)
        self.assertTrue(third.task.done())

    async def test_unknown_runs_invalid_cursors_and_static_assets(self):
        for suffix in ('', '/events', '/report.json'):
            response = await self.client.get('/api/scans/unknown' + suffix)
            self.assertEqual(response.status_code, 404)
        scan = await self.start()
        await scan.task
        for cursor in ('-1', '999', 'nonsense'):
            response = await self.client.get(f'/api/scans/{scan.id}/events', headers={'Last-Event-ID': cursor})
            self.assertEqual(response.status_code, 400)
        for path in ('/', '/static/app.js', '/static/styles.css'):
            response = await self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['cache-control'], 'no-store')
            self.assertIn("frame-ancestors 'none'", response.headers['content-security-policy'])

    def test_launcher_localhost_default(self):
        from vulnscope2.web.__main__ import main
        with patch('uvicorn.run') as run:
            main([])
            self.assertEqual(run.call_args.kwargs['host'], '127.0.0.1')
            self.assertEqual(run.call_args.kwargs['workers'], 1)
            main(['--host', '0.0.0.0', '--port', '9000'])
            self.assertEqual(run.call_args.kwargs['host'], '0.0.0.0')
            self.assertEqual(run.call_args.kwargs['port'], 9000)
