"""Discovery completes before any checker decides which services to interrogate."""
from __future__ import annotations

import asyncio
from .base import Checker
from ..models import Service
from .. import nmap

COMMON_PORTS = {21:'ftp', 22:'ssh', 23:'telnet', 25:'smtp', 53:'domain', 80:'http',
                110:'pop3', 143:'imap', 443:'https', 445:'smb', 465:'smtps',
                993:'imaps', 995:'pop3s', 3306:'mysql', 3389:'rdp', 5432:'postgres',
                5900:'vnc', 6379:'redis', 8080:'http-alt', 8443:'https-alt',
                9200:'elasticsearch', 11434:'http', 27017:'mongodb'}
SENSITIVE = {23:'Telnet', 445:'SMB', 3306:'MySQL', 5432:'PostgreSQL', 6379:'Redis',
             9200:'Elasticsearch', 27017:'MongoDB', 3389:'RDP', 5900:'VNC'}


class PortChecker(Checker):
    name = 'ports'

    async def run(self, target, ports, preset=None, use_nmap=False, nmap_timeout=180):
        if preset is not None:
            target.services = dict(preset)
        elif use_nmap and (binary := nmap.find_nmap()):
            # An installed but failing nmap is an error, not a silent fallback.
            target.services, diagnostic = await nmap.scan(target, ports, binary, nmap_timeout)
            if diagnostic:
                self.report.notes.append(f'{target.host}: nmap: {diagnostic}')
        else:
            if use_nmap:
                self.report.notes.append(f'{target.host}: nmap absent; using asyncio TCP-connect discovery')
            async def probe(port):
                try:
                    async with self.network.connect(target, port, timeout=min(self.network.timeout, 2)):
                        target.services[port] = Service(port, COMMON_PORTS.get(port, 'unknown'))
                except (TimeoutError, ConnectionRefusedError, ConnectionResetError):
                    pass
                except OSError as exc:
                    self.error(target, f'discovery port {port}: {exc}')
            await asyncio.gather(*(probe(port) for port in ports))
        for port, service in sorted(target.services.items()):
            label = service.name if service.name != 'unknown' else COMMON_PORTS.get(port, 'unknown')
            evidence = f'{service.source}: TCP {port} open; {label} {service.product} {service.version}'.strip()
            if port in SENSITIVE:
                self.finding(target, port, f'{SENSITIVE[port]} reachable', 'high',
                             'A sensitive service is reachable from the scanner. Authentication and public exposure are not established.',
                             evidence, remediation=f'Do not expose {SENSITIVE[port]} to untrusted networks. Bind it to '
                             'localhost or a private interface, and place it behind a firewall or cloud security group that '
                             'permits only known management hosts (ideally over a VPN or bastion). If remote access is '
                             'genuinely required, require strong authentication and TLS, and replace legacy plaintext '
                             'protocols (Telnet, unencrypted VNC) with SSH or a tunnelled equivalent. Databases and '
                             'search/cache engines should never be directly internet-facing.',
                             reference='https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/')
            else:
                self.finding(target, port, f'Open port {port}/{label}', 'info',
                             'Service discovered; version strings are untrusted observations.', evidence)
