from dataclasses import asdict
from .models import ContentEvent, ACTIONS, EVENTS, DESTINATIONS
from .extraction import extract
from .detectors import PrivacyDetector, SecretDetector, OrganizationDetector
from .policy import PolicyEngine
from .transformation import transform

class Pipeline:
    def __init__(self, rules, extra_detectors=()):
        self.policy = PolicyEngine(rules)
        self.detectors = [PrivacyDetector(), SecretDetector(), OrganizationDetector(rules), *extra_detectors]
    def process(self, document, context=None):
        context = context or ContentEvent(file_type=document.type)
        if context.action not in EVENTS or context.destination not in DESTINATIONS:
            raise ValueError("Invalid content event or destination")
        detections = [d for detector in self.detectors for d in detector.detect(document)]
        decisions = self.policy.evaluate(detections, context)
        strongest = max((d["action"] for d in decisions), key=lambda a: ACTIONS[a], default="ALLOW")
        protected = transform(document, detections, decisions)
        return dict(document=asdict(document), detections=[asdict(d) for d in detections], decisions=decisions,
                    action=strongest, status={"ALLOW": "DETECTED", "WARN": "WARNED", "REDACT": "REDACTED", "BLOCK": "BLOCKED"}[strongest],
                    protected_sections=protected, context=asdict(context))
    def scan(self, name, data, context=None): return self.process(extract(name, data), context)
