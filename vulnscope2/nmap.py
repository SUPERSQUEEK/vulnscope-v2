"""A fixed nmap invocation prevents options or XML from expanding target scope."""
from __future__ import annotations

import asyncio
import ipaddress
import shutil
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET
from .models import Service


class NmapError(Exception):
    pass


def find_nmap():
    return shutil.which('nmap') or (
        '/opt/homebrew/bin/nmap' if Path('/opt/homebrew/bin/nmap').is_file() else None)


def parse_xml(data, vetted_ip):
    if len(data) > 8 * 1024 * 1024 or b'<!ENTITY' in data.upper():
        raise NmapError('Oversized XML or entity declaration')
    try:
        root = ET.fromstring(data)
        if root.tag != 'nmaprun':
            raise NmapError('Not nmap XML')
        finished = root.find('runstats/finished')
        if finished is None or finished.get('exit') != 'success':
            raise NmapError('nmap did not finish successfully')
        services = {}
        expected = ipaddress.ip_address(vetted_ip)
        for host in root.findall('host'):
            addresses = [ipaddress.ip_address(a.get('addr')) for a in host.findall('address')
                         if a.get('addrtype') in ('ipv4', 'ipv6')]
            if not addresses or any(address != expected for address in addresses):
                raise NmapError('XML contains an address other than the vetted target')
            if host.find('status') is None or host.find('status').get('state') != 'up':
                continue
            if host.find('ports') is None:
                raise NmapError('nmap omitted port results for an up host (possibly timed out)')
            if host.find('times') is not None and host.find('times').get('timedout') == 'true':
                raise NmapError('nmap host timed out')
            for port in host.findall('ports/port'):
                state = port.find('state')
                if port.get('protocol') != 'tcp' or state is None or state.get('state') != 'open':
                    continue
                elem = port.find('service')
                attrs = elem.attrib if elem is not None else {}
                svc = Service(int(port.get('portid')), name=attrs.get('name', 'unknown'),
                              product=attrs.get('product', ''), version=attrs.get('version', ''),
                              extra=attrs.get('extrainfo', ''), tunnel=attrs.get('tunnel', ''),
                              cpes=[c.text or '' for c in elem.findall('cpe')] if elem is not None else [],
                              source='nmap')
                services[svc.port] = svc
        # A timed-out host may be omitted entirely even with a successful run exit.
        if not root.findall('host'):
            raise NmapError('nmap returned no host result (possibly timed out)')
        return services
    except (ET.ParseError, TypeError, ValueError) as exc:
        raise NmapError(f'Invalid nmap XML: {exc}') from exc


async def scan(target, ports, binary, timeout=180):
    ip = str(ipaddress.ip_address(target.ip))
    args = [binary, '-sT', '-sV', '--version-light', '-Pn', '-n',
            '--disable-arp-ping', '--max-retries', '1', '--max-parallelism', '16',
            '--host-timeout', f'{int(timeout)}s', '-p', ','.join(map(str, sorted(ports))),
            '-oX', '-']
    if ':' in ip:
        args.append('-6')
    args.append(ip)
    # Files bound memory use even if nmap emits large diagnostics or service banners.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = await asyncio.create_subprocess_exec(*args, stdout=output, stderr=errors)
        try:
            async with asyncio.timeout(timeout + 5):
                await process.wait()
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        errors.seek(0)
        diagnostic = errors.read(8192).decode('utf-8', 'replace').strip()
        if process.returncode:
            raise NmapError(f'nmap exited {process.returncode}: {diagnostic}')
        if 'timed out' in diagnostic.lower():
            raise NmapError(diagnostic)
        output.seek(0)
        services = parse_xml(output.read(8 * 1024 * 1024 + 1), ip)
        if not set(services) <= set(ports):
            raise NmapError('XML contains a port outside the requested set')
        return services, diagnostic
