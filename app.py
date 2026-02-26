"""
SubRecon v2.0 — FastAPI Web Application
Real-time passive subdomain scanner with WebSocket dashboard.

Usage:
    pip install -r requirements.txt
    uvicorn app:app --host 0.0.0.0 --port 8000 --reload
    Then open http://localhost:8000
"""

import asyncio
import html as _html
import re
import uuid
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from scanner_core import PassiveScanner, ScanResult

app = FastAPI(title="SubRecon", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# In-memory scan storage (sufficient for a single-user tool)
scan_store: Dict[str, ScanResult] = {}
active_scanners: Dict[str, PassiveScanner] = {}

DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)


# ── Routes ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket, domain: str = Query(...)):
    await websocket.accept()

    domain = domain.strip().lower()

    if not DOMAIN_RE.match(domain):
        await websocket.send_json({
            "phase": "error",
            "message": "Invalid domain format. Example: example.com",
        })
        await websocket.close()
        return

    scan_id = uuid.uuid4().hex[:8]
    scanner = PassiveScanner(domain)
    active_scanners[scan_id] = scanner

    await websocket.send_json({
        "phase": "init",
        "scan_id": scan_id,
        "domain": domain,
        "message": f"Starting scan for {domain}",
        "pct": 0,
    })

    async def progress(event: dict):
        event["scan_id"] = scan_id
        try:
            await websocket.send_json(event)
        except Exception:
            scanner.stop()

    try:
        result = await scanner.scan(progress)
        result.scan_id = scan_id
        scan_store[scan_id] = result
    except WebSocketDisconnect:
        scanner.stop()
    except Exception as exc:
        try:
            await websocket.send_json({
                "phase": "error",
                "scan_id": scan_id,
                "message": str(exc),
            })
        except Exception:
            pass
    finally:
        active_scanners.pop(scan_id, None)
        try:
            await websocket.close()
        except Exception:
            pass


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    result = scan_store.get(scan_id)
    if not result:
        return JSONResponse({"error": "Scan not found"}, status_code=404)
    return result.to_dict()


@app.get("/api/scan/{scan_id}/report")
async def download_report(scan_id: str):
    result = scan_store.get(scan_id)
    if not result:
        return JSONResponse({"error": "Scan not found"}, status_code=404)
    content = _build_html_report(result)
    filename = f"subrecon_{result.domain}_{scan_id}.html"
    return Response(
        content=content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── HTML report generator ────────────────────────────────────────────────────

def _build_html_report(result: ScanResult) -> str:
    h = _html.escape
    total_cves = sum(len(r.get("vulns", [])) for r in result.port_data)
    unique_ports = len({p for r in result.port_data for p in r.get("ports", [])})
    scan_date = (result.started_at or "")[:10]

    rows_html = ""
    all_rows = sorted(
        result.port_data,
        key=lambda x: len(x.get("vulns", [])),
        reverse=True,
    )
    # Add resolved subdomains with no port data
    ported = {r["subdomain"] for r in result.port_data}
    for r in result.resolved:
        if r["subdomain"] not in ported:
            all_rows.append({
                "subdomain": r["subdomain"],
                "ip": r["ip"],
                "ports": [],
                "vulns": [],
                "tags": [],
                "cpes": [],
            })

    for r in all_rows:
        ports_str = ", ".join(str(p) for p in sorted(r.get("ports", [])))
        vulns = r.get("vulns", [])
        tags_str = ", ".join(r.get("tags", []))
        vuln_html = "".join(
            f'<span class="badge red">{h(v)}</span>' for v in vulns
        ) or '<span class="ok">✓ Clean</span>'
        row_cls = "vuln" if vulns else ""
        rows_html += (
            f'<tr class="{row_cls}">'
            f"<td>{h(r['subdomain'])}</td>"
            f'<td class="mono">{h(r["ip"])}</td>'
            f'<td class="mono">{h(ports_str) or "—"}</td>'
            f"<td>{vuln_html}</td>"
            f"<td>{h(tags_str) or '—'}</td>"
            f"</tr>\n"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SubRecon — {h(result.domain)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,-apple-system,sans-serif;background:#f0f2f5;color:#222}}
  header{{background:#1a2744;color:#fff;padding:18px 28px}}
  header h1{{font-size:1.3em;font-weight:700}}
  header .meta{{font-size:.8em;opacity:.65;margin-top:4px}}
  .stats{{display:flex;gap:14px;padding:18px 28px;flex-wrap:wrap}}
  .stat{{background:#fff;border-radius:8px;padding:14px 22px;flex:1;min-width:120px;
         box-shadow:0 1px 3px rgba(0,0,0,.1)}}
  .stat .v{{font-size:1.9em;font-weight:700;color:#1a2744}}
  .stat .l{{font-size:.75em;color:#888;margin-top:3px;text-transform:uppercase;letter-spacing:.5px}}
  .stat.red .v{{color:#c0392b}}
  main{{padding:0 28px 28px}}
  table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
         overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1);font-size:.82em}}
  th{{background:#2c3e50;color:#fff;padding:9px 13px;text-align:left;font-weight:500;
      font-size:.76em;text-transform:uppercase;letter-spacing:.5px}}
  td{{padding:7px 13px;border-bottom:1px solid #eee;vertical-align:middle}}
  tr:last-child td{{border:none}}
  tr:hover td{{background:#f8f9fa}}
  tr.vuln td{{background:#fff5f5}}
  tr.vuln:hover td{{background:#ffe8e8}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:11px;
          font-size:.74em;font-family:monospace;margin:1px}}
  .badge.red{{background:#e74c3c;color:#fff}}
  .ok{{color:#27ae60;font-size:.85em}}
  .mono{{font-family:monospace}}
  footer{{text-align:center;padding:18px;color:#aaa;font-size:.75em}}
</style>
</head>
<body>
<header>
  <h1>SubRecon Report — {h(result.domain)}</h1>
  <div class="meta">
    Scan ID: {h(result.scan_id)} &bull; {h(scan_date)} &bull; SubRecon v2.0
  </div>
</header>
<div class="stats">
  <div class="stat">
    <div class="v">{len(result.subdomains)}</div>
    <div class="l">Subdomains</div>
  </div>
  <div class="stat">
    <div class="v">{len(result.resolved)}</div>
    <div class="l">Resolved IPs</div>
  </div>
  <div class="stat">
    <div class="v">{unique_ports}</div>
    <div class="l">Unique Ports</div>
  </div>
  <div class="stat {'red' if total_cves > 0 else ''}">
    <div class="v">{total_cves}</div>
    <div class="l">CVEs Detected</div>
  </div>
</div>
<main>
  <table>
    <thead>
      <tr>
        <th>Subdomain</th>
        <th>IP Address</th>
        <th>Open Ports</th>
        <th>Vulnerabilities</th>
        <th>Tags</th>
      </tr>
    </thead>
    <tbody>
      {rows_html or '<tr><td colspan="5" style="text-align:center;padding:20px;color:#999">No results</td></tr>'}
    </tbody>
  </table>
</main>
<footer>Generated by SubRecon v2.0 &bull; For authorized use only</footer>
</body>
</html>"""
