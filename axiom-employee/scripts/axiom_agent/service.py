"""Shared operation boundary for desktop IPC and the loopback demo server."""
import base64
import csv
import io
from .storage import LocalStore
from .pipeline import Pipeline
from .models import ContentEvent
from .events import normalize_event
from .activity import ActivityStore

class Service:
    def __init__(self, store=None): self.store = store or LocalStore()
    def handle(self, request):
        op = request.get("op")
        if op in {"browser_settings", "browser_configure", "browser_evaluate", "browser_revision", "browser_classify"}:
            from . import browser
            if op == "browser_settings": return browser.settings(self.store)
            if op == "browser_configure": return browser.configure(self.store, request["settings"])
            if op == "browser_evaluate": return browser.evaluate(self.store, request["payload"])
            if op == "browser_revision": return browser.revision(self.store)
            if op == "browser_classify": return browser.destination(request["origin"], browser.settings(self.store))
        if op == "activity": return ActivityStore(self.store.root).recent()
        if op == "activity_stats": return ActivityStore(self.store.root).stats()
        if op == "background_record": return ActivityStore(self.store.root).append(request["record"])
        if op == "background_scan":
            event = normalize_event(request["event"])
            data = base64.b64decode(request["data"], validate=True)
            result = Pipeline(self.store.rules()).scan(request["name"], data, event)
            policies = {d["rule_id"]: {k: d[k] for k in ("rule_id", "rule_name", "severity", "action")}
                        for d in result["decisions"] if d["rule_id"] is not None}
            summary = dict(id=event.id, source=event.source, event=event.action, action=result["action"],
                           document_type=result["document"]["type"], detection_count=len(result["detections"]),
                           policies=list(policies.values()))
            if event.source == "clipboard" and result["action"] == "REDACT":
                summary["protected_text"] = "".join(s["text"] for s in result["protected_sections"])
            return summary
        if op == "rules": return self.store.rules()
        if op == "save_rules": return self.store.save_rules(request["rules"])
        if op == "audit": return self.store.events()
        if op in {"scan", "export"}:
            # Export re-runs extraction and policy with EXPORT context and current rules.
            # Never trust a caller-supplied protected preview or decision list.
            context_data = dict(request.get("context", {}))
            if op == "export": context_data["action"] = "EXPORT"
            data = base64.b64decode(request["data"], validate=True)
            result = Pipeline(self.store.rules()).scan(request["name"], data, ContentEvent(**context_data))
            self.store.audit(result["document"]["type"], result["decisions"], ContentEvent(**result["context"]))
            if op == "scan": return result
            if result["action"] == "BLOCK":
                names = sorted({d["rule_name"] for d in result["decisions"] if d["action"] == "BLOCK"})
                raise ValueError("Export blocked by: " + ", ".join(names))
            sections = result["protected_sections"]
            # Reconstruct CSV cells; all Office/PDF exports are explicit text derivatives.
            if result["document"]["type"] == "csv":
                rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig")), strict=True))
                for section in sections:
                    loc = section["location"]
                    rows[loc["row"]-1][loc["column"]-1] = section["text"]
                # CSV formula injection: protected output must not become executable cells.
                rows = [["'" + c if c.lstrip().startswith(("=", "+", "-", "@")) else c for c in row] for row in rows]
                output = io.StringIO(newline="")
                csv.writer(output).writerows(rows)
                text, extension = output.getvalue(), "csv"
            else:
                text = "\n\n".join(s["text"] for s in sections)
                extension = "txt"
            return dict(text=text, extension=extension, action=result["action"], warnings=[
                "Extracted-text derivative. Review before sharing; original layout and unextracted content are excluded."] +
                ["Policy warning: " + name for name in sorted({d["rule_name"] for d in result["decisions"] if d["action"] == "WARN"})])
        raise ValueError("Unknown operation")
