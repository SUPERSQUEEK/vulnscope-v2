"""Read greeting protocols without authentication or commands."""
from __future__ import annotations

from .base import Checker
from ..cves import correlate

BANNER_PORTS = {21,22,25,110,143}


class BannerChecker(Checker):
    name = 'banners'

    async def run(self, target):
        ports = {p for p, s in target.services.items()
                 if not s.tunnel and (p in BANNER_PORTS or s.name in {'ftp','ssh','smtp','pop3','imap'})}
        await self.each(target, ports, self.inspect)

    async def inspect(self, target, port):
        async with self.network.connect(target, port) as (reader, _):
            banner = (await reader.read(2048)).decode('utf-8', 'replace').strip()
        if banner:
            self.finding(target, port, 'Service greeting', 'info',
                         'Unauthenticated service identification.', banner)
            correlate(self, target, port, banner)
