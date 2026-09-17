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
        for host in ('-sV','example.test\r\nHost: evil','https://example.test','192.0.2.0/24','::1%lo0'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                target_name(host)

    def test_unresolvable_host_fails_closed(self):
        with patch('vulnscope2.scope._resolve', return_value=set()), self.assertRaises(ScopeError):
            guard(Scope.from_lines(['allow example.test']), 'example.test')
