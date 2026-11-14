from __future__ import annotations
import html, json
from pathlib import Path

def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

def write_html(path: Path, payload: dict) -> None:
    rows = ["<tr>" + "".join(f"<td>{html.escape(str(f.get(k) or ''))}</td>" for k in ("timestamp", "event_id", "category", "file_path", "policy_name")) + "</tr>" for f in payload.get("findings", [])]
    body = f"""<!doctype html><meta charset='utf-8'><title>Driver Policy Audit</title><style>body{{font:14px system-ui;margin:2rem;color:#18212b}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd5df;padding:.55rem;text-align:left}}th{{background:#eef3f7}}</style><h1>Windows Driver Policy Audit</h1><p>Generated in read-only mode.</p><h2>System status</h2><pre>{html.escape(json.dumps(payload.get('status', {}), indent=2))}</pre><h2>Findings ({len(rows)})</h2><table><tr><th>Time</th><th>ID</th><th>Category</th><th>File</th><th>Policy</th></tr>{''.join(rows)}</table>"""
    path.write_text(body, encoding="utf-8")
