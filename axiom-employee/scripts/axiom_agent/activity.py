"""Cross-process-safe bounded activity metadata; never accepts document values."""
import json
import sqlite3
import os
import time
from .models import ACTIONS, EVENTS, SEVERITIES

OUTCOMES = {"UPLOAD_ALLOWED", "UPLOAD_WARNED", "UPLOAD_BLOCKED", "UPLOAD_REVIEW_REQUIRED", "UPLOAD_UNASSESSED", "UPLOAD_CANCELED", "UPLOAD_REDACTED", "AGENT_UNAVAILABLE","UNCHANGED", "WARNED", "CLIPBOARD_REPLACED", "CLIPBOARD_CLEARED", "REVIEW_REQUIRED", "BOUNDARY_NOT_INTERCEPTED", "STALE_SKIPPED", "PAUSED_SKIPPED", "ERROR"}

class ActivityStore:
    def __init__(self, root):
        self.path = root / "activity.sqlite3"
        fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS activity (id TEXT PRIMARY KEY, timestamp REAL, record TEXT)")
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA journal_mode=DELETE")
        return db
    def append(self, payload):
        # Whitelisted schema: no arbitrary metadata, names/paths, matched values or text.
        if payload.get("source") not in {"clipboard", "filesystem", "manual", "boundary", "browser"}: raise ValueError("Invalid activity source")
        if payload.get("event") not in EVENTS or payload.get("action") not in set(ACTIONS) | {"UNASSESSED"}:
            raise ValueError("Invalid activity decision")
        if payload.get("outcome") not in OUTCOMES: raise ValueError("Invalid enforcement outcome")
        if payload.get("action") == "UNASSESSED" and payload.get("outcome") not in {"ERROR", "PAUSED_SKIPPED", "UPLOAD_UNASSESSED", "AGENT_UNAVAILABLE", "UPLOAD_CANCELED"}: raise ValueError("Unassessed events cannot claim enforcement")
        if not isinstance(payload.get("id"), str) or not 1 <= len(payload["id"]) <= 100: raise ValueError("Invalid activity ID")
        policies = []
        for policy in payload.get("policies", [])[:100]:
            if policy.get("severity") not in SEVERITIES or policy.get("action") not in ACTIONS: raise ValueError("Invalid activity policy")
            policies.append({key: str(policy.get(key, ""))[:100] for key in ("rule_id", "rule_name", "severity", "action")})
        record = dict(id=payload["id"], timestamp=time.time(), source=payload["source"], event=payload["event"],
                      action=payload["action"], outcome=payload["outcome"], policies=policies,
                      document_type=str(payload.get("document_type", "text"))[:10],
                      detection_count=max(0, min(30000, int(payload.get("detection_count", 0)))))
        if record["source"] == "browser":
            from .browser import hostname, CLASSES
            if payload.get("destination_class") not in CLASSES: raise ValueError("Invalid destination classification")
            record["destination_class"] = payload["destination_class"]
            record["destination_hostname"] = hostname(payload.get("destination_hostname"))
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO activity VALUES (?, ?, ?)", (record["id"], record["timestamp"], json.dumps(record)))
            db.execute("DELETE FROM activity WHERE id NOT IN (SELECT id FROM activity ORDER BY timestamp DESC LIMIT 2000)")
        return record
    def recent(self):
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT record FROM activity ORDER BY timestamp DESC LIMIT 200")]
    def stats(self):
        midnight = time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1))
        with self.connect() as db:
            records = [json.loads(row[0]) for row in db.execute("SELECT record FROM activity WHERE timestamp >= ?", (midnight,))]
        return dict(files_scanned=sum(r["source"] == "filesystem" and r["outcome"] != "ERROR" for r in records),
                    privacy_events=sum(r["detection_count"] > 0 for r in records),
                    browser_blocks=sum(r["outcome"] == "UPLOAD_BLOCKED" for r in records),
                    protections_applied=sum(r["outcome"] in {"CLIPBOARD_REPLACED", "CLIPBOARD_CLEARED"} for r in records))
