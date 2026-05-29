from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Template
from winseclite.core.models import Detection, ScanSession

HTML_TEMPLATE = """<!doctype html><html><head><meta charset='utf-8'><title>WinSecLite Report</title>
<style>body{font-family:Segoe UI,Arial;margin:32px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px;vertical-align:top}th{background:#f2f2f2}.critical,.high{color:#a40000;font-weight:bold}.medium{color:#8a5a00;font-weight:bold}.low{color:#005a9e}</style>
</head><body><h1>WinSecLite Scan Report</h1><p><b>Scan ID:</b> {{ session.id }}</p><p><b>Scan type:</b> {{ session.scan_type }}</p><p><b>Files scanned:</b> {{ session.files_scanned }}</p><p><b>Detections:</b> {{ detections|length }}</p>
<table><thead><tr><th>Severity</th><th>Score</th><th>Type</th><th>Object</th><th>Rule</th><th>Evidence</th><th>Action</th></tr></thead><tbody>{% for d in detections %}<tr><td class='{{ d.severity.value }}'>{{ d.severity.value }}</td><td>{{ d.risk_score }}</td><td>{{ d.object_type.value }}</td><td>{{ d.object_path }}</td><td>{{ d.rule_name or '' }}</td><td>{{ d.evidence }}</td><td>{{ d.recommended_action }}</td></tr>{% endfor %}</tbody></table></body></html>"""


class ReportBuilder:
    def __init__(self, report_dir: Path) -> None:
        self.report_dir = report_dir
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def write_json(self, session: ScanSession, detections: list[Detection]) -> Path:
        path = self.report_dir / f"scan-{session.id}.json"
        data = {"generated_at": datetime.now(timezone.utc).isoformat(), "scan": session.__dict__,
                "detections": [{"id": d.id, "object_type": d.object_type.value, "object_path": d.object_path,
                                "sha256": d.sha256, "rule_name": d.rule_name, "severity": d.severity.value,
                                "risk_score": d.risk_score, "evidence": d.evidence,
                                "recommended_action": d.recommended_action, "status": d.status.value,
                                "metadata": d.metadata} for d in detections]}
        data["scan"]["started_at"] = session.started_at.isoformat()
        data["scan"]["finished_at"] = session.finished_at.isoformat() if session.finished_at else None
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def write_html(self, session: ScanSession, detections: list[Detection]) -> Path:
        path = self.report_dir / f"scan-{session.id}.html"
        path.write_text(Template(HTML_TEMPLATE).render(session=session, detections=detections), encoding="utf-8")
        return path
