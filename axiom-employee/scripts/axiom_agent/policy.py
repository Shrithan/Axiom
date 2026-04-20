import regex
from .models import ACTIONS, TRANSFORMS, SEVERITIES, EVENTS, DESTINATIONS
from .detectors import TYPES

def default_rules():
    return [dict(id="builtin-" + kind.lower(), name=name, kind="builtin", pattern=kind,
                 case_sensitive=False, severity=severity, action=action, transformation=transform,
                 replacement="[PROTECTED]", enabled=True, destinations=[], events=[])
            for kind, name, severity, action, transform in [
                ("SSN", "SSN protection", "HIGH", "BLOCK", "REDACT"),
                ("EMAIL", "Email privacy", "MEDIUM", "REDACT", "MASK"),
                ("PHONE", "Phone privacy", "MEDIUM", "REDACT", "MASK"),
                ("CARD", "Payment card protection", "HIGH", "REDACT", "MASK"),
                ("IP_ADDRESS", "IP address review", "LOW", "WARN", "REDACT"),
                *[(kind, "Secret protection: " + kind, "CRITICAL", "BLOCK", "REDACT")
                  for kind in ["API_KEY", "PRIVATE_KEY", "BEARER_TOKEN", "CONNECTION_STRING", "URL_CREDENTIALS"]]]]

def validate_rules(rules):
    if not isinstance(rules, list) or len(rules) > 100: raise ValueError("Maximum 100 rules")
    ids = set()
    for r in rules:
        if not isinstance(r, dict): raise ValueError("Invalid rule")
        if not isinstance(r.get("id"), str) or not 1 <= len(r["id"]) <= 100 or r["id"] in ids:
            raise ValueError("Rule IDs must be unique")
        ids.add(r["id"])
        for key, limit in [("name", 100), ("pattern", 512), ("replacement", 200)]:
            if not isinstance(r.get(key), str) or len(r[key]) > limit or (key != "replacement" and not r[key]):
                raise ValueError("Invalid rule " + key)
        if r.get("kind") not in {"keyword", "regex", "builtin"}: raise ValueError("Invalid detector kind")
        if r.get("severity") not in SEVERITIES or r.get("action") not in ACTIONS or r.get("transformation") not in TRANSFORMS:
            raise ValueError("Invalid severity, action or transformation")
        if type(r.get("enabled")) is not bool or type(r.get("case_sensitive")) is not bool:
            raise ValueError("Rule flags must be booleans")
        if r["kind"] == "builtin" and r["pattern"] not in TYPES - {"CUSTOM_PROTECTED_TERM"}:
            raise ValueError("Unknown built-in detector")
        for key, values in [("destinations", DESTINATIONS), ("events", EVENTS)]:
            if not isinstance(r.get(key), list) or any(v not in values for v in r[key]):
                raise ValueError("Invalid rule context")
        if r["kind"] == "regex":
            try:
                compiled = regex.compile(r["pattern"])
                if compiled.search("", timeout=.05): raise ValueError("Regex must not match empty text")
            except regex.error: raise ValueError("Invalid organization regex") from None
    return rules

class PolicyEngine:
    def __init__(self, rules): self.rules = validate_rules(rules)
    def evaluate(self, detections, context):
        decisions = []
        for detection in detections:
            matches = []
            for rule in self.rules:
                if not rule["enabled"]: continue
                if rule["destinations"] and context.destination not in rule["destinations"]: continue
                if rule["events"] and context.action not in rule["events"]: continue
                applicable = (rule["kind"] == "builtin" and rule["pattern"] == detection.type) or rule["id"] == detection.metadata.get("rule_id")
                if applicable: matches.append(rule)
            # Equal rank: rule ID order gives stable results independent of list ordering.
            matches.sort(key=lambda r: (-ACTIONS[r["action"]], r["id"]))
            rule = matches[0] if matches else None
            decisions.append(dict(detection_id=detection.id, action=rule["action"] if rule else "ALLOW",
                                  rule_id=rule["id"] if rule else None, rule_name=rule["name"] if rule else "No applicable policy",
                                  severity=rule["severity"] if rule else detection.severity,
                                  transformation=rule["transformation"] if rule else None,
                                  replacement=rule["replacement"] if rule else "",
                                  reason="Matched detection and event/destination conditions" if rule else "No enabled policy applies"))
        return decisions
