"""Process-local async jobs and replayable progress; scanning stays in engine."""
from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import secrets

from .. import engine
from ..findings import Report
from ..scope import Scope


@dataclass
class Scan:
    id: str
    targets: list[str]
    state: str = 'queued'
    report: Report | None = None
    error: str = ''
    events: deque = field(default_factory=lambda: deque(maxlen=512))
    sequence: int = 0
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task | None = None

    @property
    def done(self):
        return self.state in {'completed', 'failed', 'cancelled'}

    def publish(self, kind, **data):
        self.sequence += 1
        data['time'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
        self.events.append((self.sequence, kind, data))
        self.changed.set()
        self.changed = asyncio.Event()

    def snapshot(self):
        return {'id': self.id, 'targets': self.targets, 'state': self.state,
                'error': self.error,
                'report': self.report.to_dict() if self.report is not None else None}

    async def stream(self, after=0):
        """Replay on reconnect without tying the scan lifetime to any browser.

        Each subscriber owns its cursor. Swapping the wakeup event on publish
        avoids lost wakeups between subscribers; heartbeats keep proxies alive.
        """
        while True:
            changed = self.changed
            for sequence, kind, data in list(self.events):
                if sequence > after:
                    yield f'id: {sequence}\nevent: {kind}\ndata: {json.dumps(data)}\n\n'
                    after = sequence
            if self.done:
                return
            try:
                await asyncio.wait_for(changed.wait(), timeout=15)
            except TimeoutError:
                yield ': keep-alive\n\n'


class ScanStore:
    """Bound aggregate work and retain at most 20 runs, without writing reports.

    A single uvicorn worker owns these tasks. Finished runs are evicted oldest
    first; active runs are never evicted. The engine retains its own budgets.
    """

    def __init__(self, max_runs=20, max_active=2):
        self.runs: dict[str, Scan] = {}
        self.max_runs = max_runs
        self.max_active = max_active
        self.token = secrets.token_urlsafe(32)

    def start(self, targets: list[str], scope: Scope, authorized_by: str, nmap: bool):
        if sum(not scan.done for scan in self.runs.values()) >= self.max_active:
            raise ValueError('Two assessments are already running. Wait for one to finish.')
        while len(self.runs) >= self.max_runs:
            oldest = next((key for key, scan in self.runs.items() if scan.done), None)
            if oldest is None:
                raise ValueError('Assessment capacity reached. Wait for a run to finish.')
            del self.runs[oldest]
        scan = Scan(secrets.token_urlsafe(18), targets)
        self.runs[scan.id] = scan
        scan.publish('status', state='queued', message='Assessment queued.')
        scan.task = asyncio.create_task(self._run(scan, scope, authorized_by, nmap))
        return scan

    async def _run(self, scan, scope, authorized_by, nmap):
        scan.state = 'running'
        scan.publish('status', state=scan.state, message='Checking scope and starting assessment.')
        try:
            scan.report = await engine.run_scan(
                scan.targets, scope, authorized_by=authorized_by, nmap=nmap,
                on_event=lambda message: scan.publish('progress', message=message))
            scan.state = 'completed'
        except asyncio.CancelledError:
            scan.state = 'cancelled'
            scan.error = 'Assessment stopped. Coverage is incomplete; no final engine report is available.'
            raise
        except Exception as exc:
            scan.state = 'failed'
            scan.error = f'Assessment failed: {type(exc).__name__}: {exc}'
        finally:
            scan.publish('done', state=scan.state, error=scan.error)

    async def cancel(self, scan):
        if scan.task is not None and not scan.task.done():
            scan.task.cancel()
            await asyncio.gather(scan.task, return_exceptions=True)
            # A task cancelled before its first turn cannot run its finally block.
            if not scan.done:
                scan.state = 'cancelled'
                scan.error = 'Assessment stopped before it started. No targets were assessed.'
                scan.publish('done', state=scan.state, error=scan.error)

    async def close(self):
        await asyncio.gather(*(self.cancel(scan) for scan in self.runs.values()))
