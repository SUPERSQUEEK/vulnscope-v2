"""Keep discoveries separate from conclusions and retain their provenance."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
import ipaddress
import re


def target_name(value):
    if not isinstance(value, str):
        raise ValueError('Target must be a hostname or a single IP')
    value = value.strip().lower().rstrip('.')
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
        raise ValueError(f'Invalid target {value!r}; URLs, CIDRs and zone IDs are not targets')
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
