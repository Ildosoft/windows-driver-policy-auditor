from __future__ import annotations
import argparse, json
from pathlib import Path
from .events import collect_events, load_events
from .report import write_html, write_json
from .status import audit_driver, system_status

def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Read-only Windows driver policy diagnostics")
    sub = root.add_subparsers(dest="command", required=True); sub.add_parser("status")
    events = sub.add_parser("events"); events.add_argument("--limit", type=int, default=100); events.add_argument("--json", type=Path); events.add_argument("--html", type=Path)
    offline = sub.add_parser("offline"); offline.add_argument("xml", type=Path); offline.add_argument("--json", type=Path); offline.add_argument("--html", type=Path)
    driver = sub.add_parser("audit-driver"); driver.add_argument("path", type=Path)
    return root

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status": print(json.dumps(system_status(), indent=2)); return 0
    if args.command == "audit-driver": print(json.dumps(audit_driver(args.path), indent=2)); return 0
    findings = collect_events(args.limit) if args.command == "events" else load_events(args.xml)
    payload = {"status": system_status(), "findings": [item.to_dict() for item in findings]}
    if args.json: write_json(args.json, payload)
    if args.html: write_html(args.html, payload)
    print(json.dumps(payload, indent=2)); return 0
