"""Bounded async DNS queries go only to fixed public recursive resolvers.

A response must echo its random transaction ID and question. SERVFAIL and
truncation are errors, never evidence that a policy record is absent.
"""
from __future__ import annotations

import asyncio
import secrets
import socket
import struct

RESOLVERS = ('1.1.1.1', '8.8.8.8')
TYPES = {'TXT':16, 'DNSKEY':48, 'CAA':257}


class DnsError(Exception):
    pass


def encode_name(name):
    labels = name.rstrip('.').encode('ascii').split(b'.')
    if any(not label or len(label) > 63 for label in labels):
        raise DnsError('Invalid DNS name')
    return b''.join(bytes([len(label)]) + label for label in labels) + b'\x00'


def decode_name(msg, offset):
    labels, seen = [], set()
    end = None
    while True:
        if offset in seen or offset >= len(msg):
            raise DnsError('Invalid compressed DNS name')
        seen.add(offset)
        if len(seen) > 128:
            raise DnsError('DNS name too long')
        size = msg[offset]
        if size & 0xc0 == 0xc0:
            if offset + 1 >= len(msg):
                raise DnsError('Truncated pointer')
            if end is None:
                end = offset + 2
            offset = ((size & 63) << 8) | msg[offset + 1]
            continue
        offset += 1
        if not size:
            return '.'.join(labels), end if end is not None else offset
        if size > 63 or offset + size > len(msg):
            raise DnsError('Truncated label')
        labels.append(msg[offset:offset+size].decode('ascii'))
        offset += size


def parse_response(msg, qid, name, qtype):
    try:
        rid, flags, qd, an, _, _ = struct.unpack('!6H', msg[:12])
        if rid != qid or not flags & 0x8000 or flags & 0x7800 or qd != 1:
            raise DnsError('DNS identity/flags mismatch')
        question, pos = decode_name(msg, 12)
        typ, cls = struct.unpack('!HH', msg[pos:pos+4])
        pos += 4
        if question.lower() != name.rstrip('.').lower() or typ != TYPES[qtype] or cls != 1:
            raise DnsError('DNS question mismatch')
        if flags & 0x0200:
            raise DnsError('Truncated DNS response')
        rcode = flags & 15
        if rcode not in {0, 3}:
            raise DnsError(f'DNS resolver error {rcode}')
        if rcode == 3:
            return []
        out = []
        for _ in range(an):
            owner, pos = decode_name(msg, pos)
            typ, cls, _, size = struct.unpack('!HHIH', msg[pos:pos+10])
            pos += 10
            if pos + size > len(msg):
                raise DnsError('Truncated RDATA')
            data = msg[pos:pos+size]
            pos += size
            if typ == 5 and cls == 1 and owner.lower() == name.rstrip('.').lower():
                raise DnsError('Aliased DNS policy name; alias following is not implemented')
            if typ != TYPES[qtype] or cls != 1 or owner.lower() != name.rstrip('.').lower():
                continue
            if qtype == 'TXT':
                parts, i = [], 0
                while i < len(data):
                    length = data[i]
                    i += 1
                    if i + length > len(data):
                        raise DnsError('Truncated TXT')
                    parts.append(data[i:i+length].decode('utf-8', 'replace'))
                    i += length
                out.append(''.join(parts))
            elif qtype == 'DNSKEY':
                if len(data) < 4:
                    raise DnsError('Invalid DNSKEY')
                out.append(data.hex())
            else:
                if len(data) < 2 or 2 + data[1] > len(data):
                    raise DnsError('Invalid CAA')
                out.append(f'{data[0]} ' + data[2:2+data[1]].decode('ascii') + ' ' +
                           data[2+data[1]:].decode('utf-8', 'replace'))
        return out
    except (struct.error, IndexError, UnicodeError) as exc:
        raise DnsError(f'Malformed DNS response: {exc}') from exc


async def query(name, qtype, network):
    qid = secrets.randbelow(65536)
    packet = struct.pack('!6H', qid, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack('!HH', TYPES[qtype], 1)
    errors = []
    for resolver in RESOLVERS:
        try:
            async with network.limit:
                async with asyncio.timeout(network.timeout):
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.setblocking(False)
                        loop = asyncio.get_running_loop()
                        await loop.sock_connect(sock, (resolver, 53))
                        await loop.sock_sendall(sock, packet)
                        data = await loop.sock_recv(sock, 4096)
                        return parse_response(data, qid, name, qtype)
        except (OSError, TimeoutError, DnsError) as exc:
            errors.append(str(exc) or type(exc).__name__)
    raise DnsError('; '.join(errors))
