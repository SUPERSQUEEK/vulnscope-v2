"""Verify a running localhost web server using only a permanently denied target.

Start `python3 -m vulnscope2.web` separately, then run this script. This is
deliberately outside unittest discovery: the automated suite never needs a
listener, and this smoke check never contacts assessment targets.
"""
from __future__ import annotations

import argparse
import json
import time
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    base = f'http://127.0.0.1:{args.port}'
    opener = build_opener(ProxyHandler({}))

    def request(path, data=None, token=''):
        headers = {'X-Vulnscope-Token': token}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        req = Request(base + path, data=json.dumps(data).encode() if data is not None else None,
                      headers=headers)
        try:
            response = opener.open(req, timeout=10)
        except HTTPError as error:
            response = error
        with response:
            return response.status, response.read(), response.headers

    status, body, _ = request('/')
    assert status == 200 and b'Assessment workspace' in body
    status, body, _ = request('/api/config')
    assert status == 200
    token = json.loads(body)['token']
    valid = {'targets': ['127.0.0.1'], 'scope': 'allow 127.0.0.1',
             'authorized_by': 'Local web smoke check / permanent-deny verification', 'nmap': False}
    for field in ('authorized_by', 'scope'):
        data = dict(valid)
        del data[field]
        status, body, _ = request('/api/scans', data, token)
        assert status == 422, (status, body)
        print(f'PASS: missing {field}: HTTP 422, {json.loads(body)["detail"]}')
    status, body, _ = request('/api/scans', valid, token)
    assert status == 202, (status, body)
    scan_id = json.loads(body)['id']
    deadline = time.monotonic() + 10
    while True:
        status, body, _ = request(f'/api/scans/{scan_id}')
        assert status == 200
        scan = json.loads(body)
        if scan['state'] == 'completed':
            break
        if time.monotonic() > deadline:
            raise RuntimeError('Permanent-deny run did not complete in 10 seconds')
        time.sleep(.05)
    report = scan['report']
    assert report['complete'] is False and not report['findings']
    assert any('permanently denied' in error for error in report['errors'])
    print('PASS: real engine refused loopback; report.complete is false')
    status, events, headers = request(f'/api/scans/{scan_id}/events')
    assert status == 200 and 'text/event-stream' in headers['Content-Type']
    assert b'event: progress' in events and b'event: done' in events
    print('PASS: SSE progress and completion frames received')
    for format in ('json', 'html'):
        status, body, headers = request(f'/api/scans/{scan_id}/report.{format}')
        assert status == 200 and 'attachment;' in headers['Content-Disposition']
        if format == 'json':
            assert json.loads(body) == report
            assert body == json.dumps(report, indent=2).encode()
        else:
            assert b'INCOMPLETE' in body and b'permanently denied' in body
        print(f'PASS: {format.upper()} download')


if __name__ == '__main__':
    main()
