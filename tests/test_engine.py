from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import unittest
from unittest.mock import patch, AsyncMock
from vulnscope2.engine import run_scan
from vulnscope2.scope import Scope
from vulnscope2.ingest import parse_ingest
from vulnscope2.models import Service


class EngineTests(unittest.IsolatedAsyncioTestCase):
    async def test_auth_required_before_guard(self):
        with patch('vulnscope2.engine.guard') as guard:
            for auth in ('','   ',None):
                with self.assertRaises(ValueError):
                    await run_scan(['192.0.2.10'], Scope.from_lines(['allow 192.0.2.10']), auth)
            guard.assert_not_called()

    async def test_denial_precedes_any_checker(self):
        with patch('vulnscope2.engine.PortChecker.run', new_callable=AsyncMock) as ports:
            report = await run_scan(['127.0.0.1'], Scope.from_lines(['allow 127.0.0.1']), 'test')
            ports.assert_not_awaited()
        self.assertIn('REFUSED', report.errors[0])

    async def test_empty_ingest_does_not_trigger_sweep(self):
        with patch('vulnscope2.checkers.base.Network.connect') as connect:
            report = await run_scan(['192.0.2.10'], Scope.from_lines(['allow 192.0.2.10']), 'test',
                                    ingest=parse_ingest({'192.0.2.10':[]}))
            connect.assert_not_called()
        self.assertFalse(report.errors)
        self.assertEqual(report.services['192.0.2.10']['services'], [])

    async def test_port_first_concurrent_targets_followups_and_failure_isolation(self):
        discovered = set()
        active = set()
        overlap = asyncio.Event()
        async def ports(checker, target, *args):
            active.add(target.host)
            if len(active) == 2:
                overlap.set()
            await asyncio.wait_for(overlap.wait(), 1)
            target.services = {22: Service(22, name='ssh')}
            discovered.add(target.host)
        async def follow(checker, target):
            self.assertIn(target.host, discovered)
            self.assertEqual(target.ports, {22})
        async def failure(checker, target):
            raise RuntimeError('fixture failure')
        scope = Scope.from_lines(['allow 192.0.2.0/24'])
        with patch('vulnscope2.engine.PortChecker.run', ports), patch('vulnscope2.engine.HttpChecker.run', follow), \
             patch('vulnscope2.engine.TlsChecker.run', failure), patch('vulnscope2.engine.BannerChecker.run', follow), \
             patch('vulnscope2.engine.DnsChecker.run', follow):
            report = await run_scan(['192.0.2.10','192.0.2.11'], scope, 'test')
        self.assertEqual(len(report.errors), 2)
        self.assertEqual(len(report.services), 2)

    async def test_missing_nmap_falls_back(self):
        @asynccontextmanager
        async def connect(network, target, port, **kwargs):
            yield None, None
        with patch('vulnscope2.nmap.find_nmap', return_value=None), \
             patch('vulnscope2.checkers.base.Network.connect', connect):
            report = await run_scan(['192.0.2.10'], Scope.from_lines(['allow 192.0.2.10']), 'test', ports=[12345], nmap=True)
        self.assertEqual(report.services['192.0.2.10']['services'][0]['port'], 12345)
        self.assertIn('nmap absent', report.notes[-1])

    async def test_bad_runtime_options(self):
        for kwargs in ({'timeout':float('nan')},{'concurrency':0},{'ports':[0]},{'ports':[]}, {'target_concurrency':False}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                await run_scan(['192.0.2.10'], Scope.from_lines(['allow 192.0.2.10']), 'test', **kwargs)

    async def test_nmap_failure_does_not_silently_sweep(self):
        with patch('vulnscope2.nmap.find_nmap', return_value='/fixture/nmap'), \
             patch('vulnscope2.nmap.scan', side_effect=RuntimeError('broken nmap')), \
             patch('vulnscope2.checkers.base.Network.connect') as connect:
            report = await run_scan(['192.0.2.10'], Scope.from_lines(['allow 192.0.2.10']), 'test', ports=[80], nmap=True)
            connect.assert_not_called()
        self.assertFalse(report.to_dict()['complete'])
        self.assertIn('broken nmap',report.errors[0])

    async def test_ingest_never_grants_scope(self):
        with patch('vulnscope2.checkers.base.Network.connect') as connect:
            report = await run_scan(['192.0.2.10'], Scope.from_lines(['allow 192.0.2.11']), 'test',
                                    ingest=parse_ingest({'192.0.2.10':[80]}))
            connect.assert_not_called()
        self.assertIn('REFUSED',report.errors[0])
