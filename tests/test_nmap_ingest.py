from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch, AsyncMock
from vulnscope2.nmap import parse_xml, scan, NmapError
from vulnscope2.models import Target
from vulnscope2.ingest import parse_ingest

XML = b'''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>
<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8081"><state state="open"/>
<service name="http" product="Apache httpd" version="2.4.49"><cpe>cpe:/a:apache:http_server:2.4.49</cpe></service></port>
<port protocol="tcp" portid="22"><state state="filtered"/></port>
<port protocol="udp" portid="53"><state state="open"/></port></ports></host>
<runstats><finished exit="success"/></runstats></nmaprun>'''


class ParsingTests(unittest.TestCase):
    def test_open_tcp_only_and_metadata(self):
        result = parse_xml(XML, '192.0.2.10')
        self.assertEqual(set(result), {8081})
        self.assertEqual(result[8081].version, '2.4.49')
        self.assertIn('apache', result[8081].cpes[0])

    def test_xml_cannot_add_host(self):
        with self.assertRaises(NmapError):
            parse_xml(XML, '192.0.2.11')
        for data in (XML.replace(b'exit="success"', b'exit="error"'), b'<broken',
                     b'<!DOCTYPE a [<!ENTITY x "boom">]><a/>', b'<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'):
            with self.assertRaises(NmapError):
                parse_xml(data, '192.0.2.10')

    def test_ingest_formats_and_empty(self):
        result = parse_ingest({'example.test': [22, {'port':8081, 'service':'http','version':'2.4.49','product':'Apache httpd'}], 'empty.test': []})
        self.assertEqual(result['empty.test'], {})
        self.assertEqual(result['example.test'][8081].name, 'http')
        self.assertEqual(set(parse_ingest({'findings':[{'target':'example.test','port':22}]})['example.test']), {22})

    def test_ingest_rejects_bad_ports_and_shapes(self):
        for data in ([], {'a.test':[0]}, {'a.test':[65536]}, {'a.test':[True]},
                     {'a.test':['22;whoami']}, {'a.test':'22'}, {'findings':[None]}):
            with self.subTest(data=data), self.assertRaises((ValueError, KeyError)):
                parse_ingest(data)


class ProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_command_numeric_pin_no_shell_and_xml_ingestion(self):
        async def create(*args, **kwargs):
            self.assertEqual(args[-1], '192.0.2.10')
            self.assertNotIn('example.test', args)
            for required in ('-sT','-sV','-n','-Pn','-oX'):
                self.assertIn(required, args)
            self.assertNotIn('--script', args)
            kwargs['stdout'].write(XML)
            kwargs['stdout'].flush()
            process = AsyncMock()
            process.returncode = 0
            return process
        with patch('vulnscope2.nmap.asyncio.create_subprocess_exec', side_effect=create):
            result, _ = await scan(Target('example.test','192.0.2.10'), [8081], '/fake/nmap')
        self.assertEqual(result[8081].product, 'Apache httpd')

    async def test_cancellation_reaps_subprocess(self):
        class Process:
            returncode = None
            killed = False
            async def wait(self):
                if not self.killed:
                    await asyncio.Event().wait()
                self.returncode = -9
            def kill(self):
                self.killed = True
        process = Process()
        with patch('vulnscope2.nmap.asyncio.create_subprocess_exec', return_value=process):
            task = asyncio.create_task(scan(Target('example.test','192.0.2.10'), [80], '/fake/nmap'))
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(process.killed)
        self.assertEqual(process.returncode, -9)
