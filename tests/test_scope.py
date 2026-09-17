from __future__ import annotations

import unittest
from unittest.mock import patch
import ipaddress
from vulnscope2.scope import Scope, ScopeError, guard
from vulnscope2.models import target_name


class ScopeTests(unittest.TestCase):
    def test_permanent_denials_override_explicit_allows(self):
        for host in ('127.0.0.1','169.254.169.254','224.0.0.1','255.255.255.255',
                     '::1','fe80::1','ff02::1','::ffff:127.0.0.1','0.0.0.0','::'):
            with self.subTest(host=host), self.assertRaises(ScopeError):
                guard(Scope.from_lines([f'allow {host}']), host)

    def test_literal_allow_and_deny(self):
        self.assertEqual(guard(Scope.from_lines(['allow 192.0.2.0/24']), '192.0.2.10'), ['192.0.2.10'])
        with self.assertRaises(ScopeError):
            guard(Scope.from_lines(['allow 192.0.2.0/24','deny 192.0.2.10']), '192.0.2.10')
        with self.assertRaises(ScopeError):
            guard(Scope(), '192.0.2.10')

    def test_every_dns_address_is_checked(self):
        scope = Scope.from_lines(['allow example.test'])
        with patch('vulnscope2.scope._resolve', return_value={ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('127.0.0.1')}):
            with self.assertRaises(ScopeError):
                guard(scope, 'example.test')
        with patch('vulnscope2.scope._resolve', return_value={ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('192.0.2.2')}):
            self.assertEqual(set(guard(scope, 'example.test')), {'192.0.2.1','192.0.2.2'})
            with self.assertRaises(ScopeError):
                guard(Scope.from_lines(['allow 192.0.2.1']), 'example.test')

    def test_suffix_boundary_and_denial(self):
        scope = Scope.from_lines(['allow .example.test','deny .private.example.test'])
        with patch('vulnscope2.scope._resolve', return_value={ipaddress.ip_address('192.0.2.1')}):
            self.assertTrue(guard(scope, 'api.example.test'))
            for host in ('evilexample.test','x.private.example.test','private.example.test'):
                with self.assertRaises(ScopeError):
                    guard(scope, host)

    def test_malformed_scope_and_target_inputs(self):
        for line in ('permit example.test','allow','allow example.test extra'):
            with self.assertRaises(ScopeError):
                Scope.from_lines([line])
        for host in ('-sV','example.test\r\nHost: evil','https://','192.0.2.0/24','::1%lo0'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                target_name(host)

    def test_url_and_port_normalization(self):
        examples = {
            'https://amirslm.com/': 'amirslm.com',
            'http://amirslm.com': 'amirslm.com',
            'amirslm.com:443/foo': 'amirslm.com',
            'amirslm.com:443/123': 'amirslm.com',
            ' HTTPS://AMIRSLM.COM.:443/a%20b?q=1#part ': 'amirslm.com',
            '//amirslm.com/path': 'amirslm.com',
            'amirslm.com/?next=https://elsewhere.test/': 'amirslm.com',
            'http://192.0.2.10:8080/foo': '192.0.2.10',
            '192.0.2.10:443': '192.0.2.10',
            '2001:db8::443': '2001:db8::443',
            'https://[2001:db8::1]:443/foo': '2001:db8::1',
            '[2001:db8::1]:443/foo': '2001:db8::1',
            'https://[::ffff:127.0.0.1]/': '::ffff:7f00:1',
        }
        for value, expected in examples.items():
            with self.subTest(value=value):
                self.assertEqual(target_name(value), expected)
                self.assertEqual(target_name(expected), expected)

    def test_invalid_url_authorities_and_cidrs(self):
        for value in ('https:///path', 'https://a.test:bad/', 'a.test:65536',
                      'a.test:', 'https://user:secret@a.test/', 'https://a.test\\@b.test/',
                      'https://a.te\nst/', 'https://[::1]suffix/', 'http://[::1%25lo0]/',
                      '192.0.2.0/24', '192.0.2.0/33', '192.0.2.0/255.255.255.0',
                      '2001:db8::/32', '', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                target_name(value)

    def test_bare_and_url_scope_rules_preserve_enforcement(self):
        with patch('vulnscope2.scope._resolve', return_value={ipaddress.ip_address('192.0.2.1')}):
            for line in ('amirslm.com', 'allow https://amirslm.com/',
                         '  allow   amirslm.com:443/foo  ', '\ufeffamirslm.com # owner'):
                with self.subTest(line=line):
                    scope = Scope.from_lines([line])
                    self.assertEqual(guard(scope, 'amirslm.com'), ['192.0.2.1'])
                    with self.assertRaises(ScopeError):
                        guard(scope, 'unlisted.test')
            for lines in ([], [' ', '# comment'], ['deny amirslm.com', 'allow amirslm.com'],
                          ['amirslm.com', 'deny https://amirslm.com:443/path']):
                with self.subTest(lines=lines), self.assertRaises(ScopeError):
                    guard(Scope.from_lines(lines), 'amirslm.com')
        for rule, host in (('192.0.2.0/24', '192.0.2.10'), ('2001:db8::/32', '2001:db8::1'),
                           ('192.0.2.10', '192.0.2.10')):
            self.assertEqual(guard(Scope.from_lines([rule]), host), [host])
        for url in ('http://127.0.0.1:80/', 'https://[::1]/', 'https://[::ffff:127.0.0.1]/'):
            with self.subTest(url=url), self.assertRaises(ScopeError):
                guard(Scope.from_lines([url]), target_name(url))

    def test_actionable_scope_errors(self):
        line = 'alllow target https://amirslm.com/'
        with self.assertRaises(ScopeError) as caught:
            Scope.from_lines([line])
        self.assertIn(line, str(caught.exception))
        self.assertIn('allow amirslm.com', str(caught.exception))
        for line in ('allow https://', '192.0.2.0/33', 'allow *', 'deny', 'allow .'):
            with self.subTest(line=line), self.assertRaises(ScopeError):
                Scope.from_lines([line])

    def test_unresolvable_host_fails_closed(self):
        with patch('vulnscope2.scope._resolve', return_value=set()), self.assertRaises(ScopeError):
            guard(Scope.from_lines(['allow example.test']), 'example.test')
