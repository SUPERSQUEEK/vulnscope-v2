"""Numeric-only sockets keep DNS rebinding and ambient proxy settings out."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from contextlib import asynccontextmanager
from ..findings import Finding


class Network:
    def __init__(self, timeout=6.0, concurrency=32):
        self.timeout = timeout
        self.limit = asyncio.Semaphore(concurrency)

    @asynccontextmanager
    async def connect(self, target, port, context=None, timeout=None):
        ip = ipaddress.ip_address(target.ip)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        writer = None
        raw = None
        async with self.limit:
            async with asyncio.timeout(timeout or self.timeout):
                try:
                    raw = socket.socket(family, socket.SOCK_STREAM)
                    raw.setblocking(False)
                    await asyncio.get_running_loop().sock_connect(raw, (str(ip), port))
                    kwargs = {'sock': raw, 'limit': 65536}
                    if context is not None:
                        kwargs.update(ssl=context, server_hostname=target.host,
                                      ssl_handshake_timeout=timeout or self.timeout)
                    reader, writer = await asyncio.open_connection(**kwargs)
                    raw = None  # Transport now owns the socket.
                    yield reader, writer
                finally:
                    if raw is not None:
                        raw.close()
                    if writer is not None:
                        writer.close()
                        # Abort also bounds shutdown when a TLS peer never sends close_notify.
                        writer.transport.abort()


class Checker:
    name = 'base'

    def __init__(self, network, report):
        self.network = network
        self.report = report

    def finding(self, target, port, title, severity, detail, evidence, **kwargs):
        self.report.add(Finding(target.host, port, self.name, title, severity,
                                detail, evidence, ip=target.ip, **kwargs))

    def error(self, target, error):
        self.report.errors.append(f'{target.host}: {self.name}: {error}')

    async def each(self, target, ports, operation):
        async def one(port):
            try:
                await operation(target, port)
            except Exception as exc:
                self.error(target, f'port {port}: {type(exc).__name__}: {exc}')
        await asyncio.gather(*(one(port) for port in sorted(ports)))
