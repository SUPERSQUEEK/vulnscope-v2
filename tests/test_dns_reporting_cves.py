from __future__ import annotations

import struct
import unittest
from vulnscope2.dnsclient import parse_response, encode_name, DnsError
from vulnscope2.findings import Finding, Report
from vulnscope2.checkers.base import Checker, Network
from vulnscope2.models import Target
from vulnscope2.cves import correlate
from vulnscope2 import reporting


class DnsTests(unittest.TestCase):
    def packet(self, flags=0x8180, question='example.test'):
        return struct.pack('!6H',123,flags,1,0,0,0) + encode_name(question) + struct.pack('!HH',16,1)

    def test_nodata_and_nxdomain_are_not_servfail(self):
        self.assertEqual(parse_response(self.packet(),123,'example.test','TXT'),[])
        self.assertEqual(parse_response(self.packet(0x8183),123,'example.test','TXT'),[])
        for data in (self.packet(0x8182),self.packet(0x8380),self.packet(question='other.test'),b'bad'):
            with self.assertRaises(DnsError):
                parse_response(data,123,'example.test','TXT')
        with self.assertRaises(DnsError):
            parse_response(self.packet(),124,'example.test','TXT')


class CveReportTests(unittest.TestCase):
    def test_version_boundaries_and_candidates(self):
        for banner, expected in [('Apache/2.4.49','CVE-2021-41773'),('Apache httpd 2.4.50','CVE-2021-42013'),
                                 ('OpenSSH_9.7p1','CVE-2024-6387'),('vsFTPd 2.3.4','CVE-2011-2523'),
                                 ('Apache/2.4.51',None),('OpenSSH_9.8p1',None),('Apache/2.4.490',None),('OpenSSH_8.4p1',None)]:
            report = Report()
            correlate(Checker(Network(),report),Target('example.test','192.0.2.10'),80,banner)
            with self.subTest(banner=banner):
                self.assertEqual(report.findings[0].cves[0] if report.findings else None,expected)
                if expected:
                    self.assertEqual(report.findings[0].validation,'candidate')

    def test_ci_exit_scale_and_html_escaping(self):
        for severity, code in [('info',0),('low',1),('medium',1),('high',2),('critical',3)]:
            report = Report(authorized_by='<operator>')
            report.add(Finding('example.test',80,'http','<script>','%s'%severity,
                               'detail','raw\x1b[2J',cves=['CVE-2021-41773'],validation='candidate'))
            self.assertEqual(report.exit_code,code)
            self.assertNotIn('<script>',reporting.to_html(report))
            self.assertIn('&lt;operator&gt;',reporting.to_html(report))
            self.assertIn('CVE-2021-41773',reporting.to_json(report))
            self.assertNotIn('\x1b',reporting.console(report))
        report.errors.append('incomplete')
        self.assertFalse(report.to_dict()['complete'])
        self.assertEqual(report.exit_code,3)

class DnsWireTests(unittest.TestCase):
    def response(self, typ, data):
        return (struct.pack('!6H',123,0x8180,1,1,0,0) + encode_name('example.test') +
                struct.pack('!HH',typ,1) + b'\xc0\x0c' + struct.pack('!HHIH',typ,1,60,len(data)) + data)

    def test_compressed_owner_and_fragmented_txt(self):
        self.assertEqual(parse_response(self.response(16,b'\x06v=spf1\x05 -all'),123,'example.test','TXT'), ['v=spf1 -all'])

    def test_caa_and_dnskey(self):
        self.assertEqual(parse_response(self.response(257,b'\x00\x05issueca.test'),123,'example.test','CAA'), ['0 issue ca.test'])
        self.assertEqual(parse_response(self.response(48,b'\x01\x01\x03\x08'),123,'example.test','DNSKEY'), ['01010308'])

    def test_alias_does_not_report_missing_policy(self):
        packet = (struct.pack('!6H',123,0x8180,1,1,0,0) + encode_name('example.test') +
                  struct.pack('!HH',16,1) + b'\xc0\x0c' + struct.pack('!HHIH',5,1,60,2) + b'\xc0\x0c')
        with self.assertRaises(DnsError):
            parse_response(packet,123,'example.test','TXT')
