"""Local metadata only, with private permissions and atomic policy replacement."""
import json
import os
import tempfile
import threading
from pathlib import Path
from .policy import default_rules, validate_rules

class LocalStore:
    def __init__(self, root=None):
        self.root = Path(root or os.environ.get("AXIOM_DATA_DIR", str(Path.home() / ".axiom-local")))
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.RLock()
    def rules(self):
        with self.lock:
            path = self.root / "policies.json"
            return validate_rules(json.loads(path.read_text())) if path.exists() else default_rules()
    def save_rules(self, rules):
        validate_rules(rules)
        with self.lock:
            fd, name = tempfile.mkstemp(dir=self.root)
            try:
                with os.fdopen(fd, "w") as stream: json.dump(rules, stream)
                os.replace(name, self.root / "policies.json")
            finally:
                if os.path.exists(name): os.unlink(name)
        return rules
    def audit(self, document_type, decisions, event):
        import time
        # No names, paths, matches, excerpts, domains, or content are persisted.
        with self.lock:
            path = self.root / "audit.jsonl"
            if path.exists() and path.stat().st_size > 1_000_000:
                os.replace(path, self.root / "audit.previous.jsonl")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as stream:
                for decision in decisions:
                    stream.write(json.dumps(dict(timestamp=time.time(), rule_id=decision["rule_id"],
                        action=decision["action"], severity=decision["severity"], document_type=document_type,
                        event=event.action)) + "\n")
    def events(self):
        with self.lock:
            path = self.root / "audit.jsonl"
            return [json.loads(line) for line in path.read_text().splitlines()][-200:] if path.exists() else []
