"""Launch the optional, single-process web interface on localhost by default."""
from __future__ import annotations

import argparse


def main(argv=None):
    parser = argparse.ArgumentParser(description='vulnscope2 web UI (optional web dependencies required)')
    parser.add_argument('--host', default='127.0.0.1', help='Listen address; default: 127.0.0.1 (local only)')
    parser.add_argument('--port', type=int, default=8765, help='Listen port; default: 8765')
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error('--port must be between 1 and 65535')
    try:
        import uvicorn
        from .app import create_app
    except ImportError as exc:
        parser.exit(2, f'Web dependencies are missing: {exc}.\nInstall with: python3 -m pip install -r requirements-web.txt\n')
    uvicorn.run(create_app(host=args.host), host=args.host, port=args.port, workers=1,
                proxy_headers=False, timeout_graceful_shutdown=3)


if __name__ == '__main__':
    main()
