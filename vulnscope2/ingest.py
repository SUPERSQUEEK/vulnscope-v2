"""Imported discoveries are hints; importing never grants network authority."""
from __future__ import annotations

import json
from pathlib import Path
from .models import Service, target_name, port_number


def parse_ingest(data):
    if not isinstance(data, dict):
        raise ValueError('Ingest must be an object')
    out = {}

    def add(host, item):
        host = target_name(host)
        out.setdefault(host, {})
        if isinstance(item, dict):
            if item.get('state', 'open') != 'open' or item.get('protocol', 'tcp') != 'tcp':
                return
            port = port_number(item['port'])
            fields = {k: item[k] for k in ('product', 'version', 'extra', 'tunnel', 'cpes') if k in item}
            if any(not isinstance(v, str) for k, v in fields.items() if k != 'cpes'):
                raise ValueError('Service metadata must be strings')
            if 'cpes' in fields and (not isinstance(fields['cpes'], list) or
                                    not all(isinstance(v, str) for v in fields['cpes'])):
                raise ValueError('cpes must be a list of strings')
            name = item.get('name', item.get('service', 'unknown'))
            if not isinstance(name, str):
                raise ValueError('Service name must be a string')
            service = Service(port, name=name, source='ingest', **fields)
        else:
            service = Service(port_number(item), source='ingest')
        out[host][service.port] = service

    if 'findings' in data:
        if not isinstance(data['findings'], list):
            raise ValueError('findings must be a list')
        for item in data['findings']:
            if not isinstance(item, dict):
                raise ValueError('Each finding must be an object')
            if item.get('port') is not None:
                add(item.get('target') or item.get('host'), item)
    else:
        for host, items in data.items():
            host = target_name(host)
            out.setdefault(host, {})
            if not isinstance(items, (list, tuple, set)):
                raise ValueError('Host values must be lists of ports or service objects')
            for item in items:
                add(host, item)
    return out


def load_ingest(path):
    if Path(path).stat().st_size > 8 * 1024 * 1024:
        raise ValueError('Ingest exceeds 8 MiB')
    return parse_ingest(json.loads(Path(path).read_text(encoding='utf-8')))
