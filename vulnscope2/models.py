"""Keep discoveries separate from conclusions and retain their provenance."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
import ipaddress
import re
from urllib.parse import urlsplit


def target_name(value):
    """Normalize human host/URL input without resolving or authorizing it.

    Bare IPv6 is parsed before looking for a port. Bare IP/prefix input stays
    scope-only; it must never turn into a scan of the network's first host.
    Reject ambiguous authorities rather than guessing which host was intended.
    """
    if not isinstance(value, str):
        raise ValueError('Target must be a hostname, URL or a single IP')
    value = value.strip()
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or '\\' in value:
        raise ValueError('Targets cannot contain whitespace, controls or backslashes')
    # urlsplit silently removes some controls; validate before calling it.
    explicit_url = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', value)) or value.startswith('//')
    if not explicit_url and '/' in value:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            pass
        else:
            raise ValueError('CIDRs belong in scope rules; enter a single IP or a URL as the target')
        address, prefix = value.split('/', 1)
        if prefix.isdecimal():
            try:
                ipaddress.ip_address(address)
            except ValueError:
                pass
            else:
                raise ValueError('CIDRs belong in scope rules; enter a single IP or a URL as the target')
    if '%' in value.split('/', 1)[0]:
        raise ValueError('IPv6 zone IDs are not accepted')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        parsed = urlsplit(value if explicit_url else '//' + value)
        if (not parsed.netloc or parsed.username is not None or parsed.password is not None
                or parsed.netloc.endswith(':')):
            raise ValueError('Use a URL with a host and no embedded credentials')
        if parsed.netloc.startswith('[') and not re.fullmatch(r'\[[^\]]+\](?::[0-9]+)?', parsed.netloc):
            raise ValueError('Use [IPv6] or [IPv6]:port')
        if parsed.port is not None:
            port_number(parsed.port)
        value = (parsed.hostname or '').lower().rstrip('.')
    except ValueError as exc:
        raise ValueError(f'Invalid target {value!r}; enter a host or URL (e.g. https://example.com/)') from exc
    if '%' in value:
        raise ValueError('IPv6 zone IDs are not accepted')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not value or len(value) > 253 or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in value.split('.')
    ):
        raise ValueError(f'Invalid target {value!r}; enter a hostname, URL or single IP; CIDRs belong in scope')
    return value


def port_number(value):
    if isinstance(value, bool) or not re.fullmatch(r'[0-9]+', str(value)):
        raise ValueError(f'Invalid port: {value!r}')
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError(f'Port out of range: {port}')
    return port


@dataclass
class Service:
    port: int
    name: str = 'unknown'
    product: str = ''
    version: str = ''
    extra: str = ''
    tunnel: str = ''
    cpes: list[str] = field(default_factory=list)
    source: str = 'tcp-connect'

    def __post_init__(self):
        self.port = port_number(self.port)

    def to_dict(self):
        return asdict(self)


@dataclass
class Target:
    host: str
    ip: str
    services: dict[int, Service] = field(default_factory=dict)

    @property
    def ports(self):
        return set(self.services)
