"""Reports preserve evidence and distinguish candidates from confirmed behavior."""
from __future__ import annotations

import html
import json
import re
from urllib.parse import urlsplit

COLORS = {'critical':'#ff7474','high':'#ffc275','medium':'#9bbcff','low':'#bbbdc7','info':'#91a0b6'}


def safe_terminal(value):
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]', '?', str(value))


def console(report):
    lines = [f'vulnscope2  {report.started_at}', f'authorized by: {report.authorized_by}',
             f'scope: {report.scope_summary}', f'targets: {", ".join(report.targets)}',
             'status: ' + ('INCOMPLETE - review errors / refusals' if report.errors else 'completed'),
             'findings  ' + '  '.join(f'{s}:{n}' for s,n in report.counts().items()), '']
    for finding in report.by_severity():
        where = f'{finding.target}:{finding.port}' if finding.port else finding.target
        lines.extend([f'[{finding.severity.upper()}] {finding.title}  {where} [{finding.validation}]',
                      f'    {finding.detail}', f'    evidence: {finding.evidence}'])
        if finding.remediation:
            lines.append(f'    fix: {finding.remediation}')
        if finding.cves:
            lines.append(f'    CVEs: {", ".join(finding.cves)}')
        if finding.reference:
            lines.append(f'    reference: {finding.reference}')
    if report.notes:
        lines.append('notes:')
        lines.extend('    ' + n for n in report.notes)
    if report.errors:
        lines.append('errors / refusals:')
        lines.extend('    ' + e for e in report.errors)
    return safe_terminal('\n'.join(lines))


def to_json(report):
    return json.dumps(report.to_dict(), indent=2)


def to_html(report):
    escape = html.escape
    rows = []
    for finding in report.by_severity():
        refs = []
        for url in [finding.reference] + [f'https://nvd.nist.gov/vuln/detail/{cve}' for cve in finding.cves]:
            if urlsplit(url).scheme in {'http','https'}:
                refs.append(f'<a href="{escape(url, quote=True)}">{escape(url)}</a>')
        where = f'{finding.target}:{finding.port}' if finding.port else finding.target
        rows.append(f'<article style="border-color:{COLORS[finding.severity]}">'
                    f'<h2>{escape(finding.severity.upper())} · {escape(finding.title)}</h2>'
                    f'<p class="meta">{escape(where)} · {escape(finding.ip)} · {escape(finding.validation)}</p>'
                    f'<p>{escape(finding.detail)}</p><pre>{escape(finding.evidence)}</pre>'
                    f'<p>{escape(finding.remediation)}</p><p>{"<br>".join(refs)}</p></article>')
    errors = ''.join(f'<li>{escape(e)}</li>' for e in report.errors)
    notes = ''.join(f'<li>{escape(n)}</li>' for n in report.notes)
    status = 'INCOMPLETE - review errors / refusals' if report.errors else 'Completed'
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>vulnscope2 assessment</title><style>
body{{background:#10151e;color:#e8edf5;font:15px/1.6 system-ui,sans-serif;max-width:1000px;margin:auto;padding:32px}}
h1{{font-size:28px}}h2{{font-size:18px}}.meta{{color:#a7b4c9}}article{{background:#182130;border-left:4px solid;padding:16px 24px;margin:16px 0}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 monospace}}a{{color:#9bbcff;overflow-wrap:anywhere}}li{{overflow-wrap:anywhere}}
</style></head><body><h1>vulnscope2 assessment</h1>
<p class="meta">{escape(report.started_at)}<br>Authorized by: {escape(report.authorized_by)}<br>
Scope: {escape(report.scope_summary)}<br>Targets: {escape(', '.join(report.targets))}</p>
<p><strong>{status}</strong></p><p>{escape(' · '.join(f'{s}: {n}' for s,n in report.counts().items()))}</p>
{''.join(rows) or '<p>No findings.</p>'}<h2>Notes</h2><ul>{notes}</ul>
<h2>Errors / refusals</h2><ul>{errors}</ul></body></html>'''
