"""Thin HTTP adapter for the governed engine and unchanged CLI serializers."""
from __future__ import annotations

from contextlib import asynccontextmanager
import json
from pathlib import Path
import secrets

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import reporting
from ..checkers.ports import COMMON_PORTS
from ..models import target_name
from ..scope import Scope, ScopeError
from .store import ScanStore

STATIC = Path(__file__).parent / 'static'
MAX_BODY = 128 * 1024


def validate_scan(data):
    """Use the core parsers before scheduling; the engine still enforces guard.

    Web-only size limits bound process-local storage and aggregate workloads.
    No scope is inferred from targets, and no target DNS lookup happens here.
    """
    if not isinstance(data, dict):
        raise ValueError('Expected a JSON object.')
    auth = data.get('authorized_by')
    if not isinstance(auth, str) or not auth.strip():
        raise ValueError('Authorized by is required. Enter the owner or approval reference.')
    if len(auth) > 1024:
        raise ValueError('Authorized by must be at most 1,024 characters.')
    scope_text = data.get('scope')
    if not isinstance(scope_text, str) or not scope_text.strip():
        raise ValueError('An explicit scope with at least one allow rule is required.')
    if len(scope_text) > 65536:
        raise ValueError('Scope must be at most 65,536 characters.')
    scope = Scope.from_lines(scope_text.splitlines())
    if scope.is_empty():
        raise ValueError('An explicit scope with at least one allow rule is required.')
    targets = data.get('targets')
    if not isinstance(targets, list) or not 1 <= len(targets) <= 64:
        raise ValueError('Provide between 1 and 64 individual target hostnames or IPs.')
    targets = list(dict.fromkeys(target_name(target) for target in targets))
    nmap = data.get('nmap', False)
    if type(nmap) is not bool:
        raise ValueError('nmap must be true or false.')
    if set(data) - {'targets', 'scope', 'authorized_by', 'nmap'}:
        raise ValueError('Unknown scan option. Supported fields: targets, scope, authorized_by, nmap.')
    return targets, scope, auth.strip(), nmap


def create_app(host='127.0.0.1'):
    store = ScanStore()

    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            await store.close()

    app = FastAPI(title='vulnscope2', lifespan=lifespan, docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.store = store
    # Reject DNS rebinding by default. Wildcard listening is an explicit CLI opt-in.
    allowed = ['*'] if host in {'0.0.0.0', '::'} else ['localhost', '127.0.0.1', host]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed)

    @app.middleware('http')
    async def browser_boundary(request, call_next):
        origin = request.headers.get('origin')
        expected = f'{request.url.scheme}://{request.url.netloc}'
        if (origin is not None and origin != expected) or request.headers.get('sec-fetch-site') == 'cross-site':
            return JSONResponse({'detail': 'Use this server’s own web UI or a same-origin client.'}, status_code=403)
        if request.method not in {'GET', 'HEAD', 'OPTIONS'}:
            # A custom token also protects requests with no Origin header. This
            # is CSRF protection for a local tool, not remote-user authentication.
            token = request.headers.get('x-vulnscope-token', '')
            if not secrets.compare_digest(token.encode('utf-8'), store.token.encode('ascii')):
                return JSONResponse({'detail': 'Refresh the page before starting an assessment.'}, status_code=403)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        # CLI HTML exports have their own inline style; never alter their bytes.
        style = "'self' 'unsafe-inline'" if request.url.path.endswith('/report.html') else "'self'"
        response.headers['Content-Security-Policy'] = (
            f"default-src 'self'; script-src 'self'; style-src {style}; "
            "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        return response

    @app.get('/')
    async def index():
        return FileResponse(STATIC / 'index.html')

    @app.get('/api/config')
    async def config():
        return {'token': store.token, 'ports': sorted(COMMON_PORTS), 'max_targets': 64}

    @app.post('/api/scans', status_code=202)
    async def start(request: Request):
        if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
            raise HTTPException(415, 'Send the assessment as application/json.')
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_BODY:
                raise HTTPException(413, 'Assessment request exceeds 128 KiB.')
        try:
            args = validate_scan(json.loads(body))
        except (ValueError, ScopeError, UnicodeError) as exc:
            raise HTTPException(422, str(exc)) from exc
        try:
            scan = store.start(*args)
        except ValueError as exc:
            raise HTTPException(429, str(exc)) from exc
        return {'id': scan.id, 'state': scan.state, 'targets': scan.targets}

    def get_scan(scan_id):
        if scan_id not in store.runs:
            raise HTTPException(404, 'Assessment not found. It may have expired or the server restarted.')
        return store.runs[scan_id]

    @app.get('/api/scans/{scan_id}')
    async def status(scan_id: str):
        return get_scan(scan_id).snapshot()

    @app.post('/api/scans/{scan_id}/cancel')
    async def cancel(scan_id: str):
        scan = get_scan(scan_id)
        await store.cancel(scan)
        return scan.snapshot()

    @app.get('/api/scans/{scan_id}/events')
    async def events(scan_id: str, request: Request):
        scan = get_scan(scan_id)
        try:
            after = int(request.headers.get('last-event-id', '0'))
            if not 0 <= after <= scan.sequence:
                raise ValueError
        except ValueError as exc:
            raise HTTPException(400, 'Invalid Last-Event-ID.') from exc
        return StreamingResponse(scan.stream(after), media_type='text/event-stream',
                                 headers={'X-Accel-Buffering': 'no'})

    @app.get('/api/scans/{scan_id}/report.{format}')
    async def download(scan_id: str, format: str):
        if format not in {'json', 'html'}:
            raise HTTPException(404, 'Choose JSON or HTML.')
        scan = get_scan(scan_id)
        if scan.report is None:
            raise HTTPException(409, 'No final engine report is available for this assessment yet.')
        content = reporting.to_json(scan.report) if format == 'json' else reporting.to_html(scan.report)
        return Response(content, media_type='application/json' if format == 'json' else 'text/html',
                        headers={'Content-Disposition': f'attachment; filename="vulnscope2-{scan.id}.{format}"'})

    app.mount('/static', StaticFiles(directory=STATIC), name='static')
    return app
