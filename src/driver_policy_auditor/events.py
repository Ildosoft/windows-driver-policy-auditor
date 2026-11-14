from __future__ import annotations
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

TARGET_IDS = {3004, 3023, 3033, 3076, 3077, 3082, 3099}
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

@dataclass(frozen=True)
class Finding:
    event_id: int
    timestamp: str
    file_path: str | None
    policy_name: str | None
    category: str
    summary: str
    def to_dict(self) -> dict: return asdict(self)

def classify(event_id: int, message: str) -> str:
    text = message.lower()
    if event_id == 3099: return "policy-activation"
    if "revoked" in text or "expired" in text: return "revoked-or-expired-signature"
    if event_id in {3076, 3077, 3023} or "policy" in text: return "app-control-policy"
    if event_id in {3004, 3033} or "signing level" in text or "signature" in text: return "signature-requirement"
    if event_id == 3082: return "non-whql-audit"
    return "code-integrity"

def _data_map(event: ET.Element) -> dict[str, str]:
    return {(item.get("Name") or ""): (item.text or "") for item in event.findall(".//e:EventData/e:Data", NS)}

def _first(values: dict[str, str], names: Iterable[str]) -> str | None:
    return next((values[name] for name in names if values.get(name)), None)

def parse_events_xml(xml_text: str) -> list[Finding]:
    cleaned = re.sub(r"^\s*<\?xml[^>]+>\s*", "", xml_text)
    try: root = ET.fromstring(cleaned)
    except ET.ParseError: root = ET.fromstring(f"<Events>{cleaned}</Events>")
    events = [root] if root.tag.endswith("Event") else list(root)
    findings: list[Finding] = []
    for event in events:
        id_node = event.find("./e:System/e:EventID", NS)
        if id_node is None or not (id_node.text or "").isdigit(): continue
        event_id = int(id_node.text or 0)
        if event_id not in TARGET_IDS: continue
        time_node = event.find("./e:System/e:TimeCreated", NS)
        values = _data_map(event)
        message = " ".join(v for v in values.values() if v)
        findings.append(Finding(event_id, (time_node.get("SystemTime") if time_node is not None else "") or "",
            _first(values, ("FileNameBuffer", "FileName", "ImageName", "FilePath")),
            _first(values, ("PolicyNameBuffer", "PolicyName", "PolicyIdBuffer")),
            classify(event_id, message), message[:1000] or f"Code Integrity event {event_id}"))
    return findings

def collect_events(limit: int = 100) -> list[Finding]:
    query = "*[System[(EventID=3004 or EventID=3023 or EventID=3033 or EventID=3076 or EventID=3077 or EventID=3082 or EventID=3099)]]"
    result = subprocess.run(["wevtutil", "qe", "Microsoft-Windows-CodeIntegrity/Operational", f"/q:{query}", "/rd:true", f"/c:{limit}", "/f:xml"], check=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return parse_events_xml(result.stdout)

def load_events(path: Path) -> list[Finding]:
    return parse_events_xml(path.read_text(encoding="utf-8"))
