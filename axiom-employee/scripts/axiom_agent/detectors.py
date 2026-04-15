"""Pluggable deterministic detectors; regex execution has a hard timeout."""
import ipaddress
import time
import regex
from .models import Detection

TYPES = {"SSN", "EMAIL", "PHONE", "CARD", "IP_ADDRESS", "API_KEY", "PRIVATE_KEY", "BEARER_TOKEN", "CONNECTION_STRING", "URL_CREDENTIALS", "CUSTOM_PROTECTED_TERM"}

def luhn(value):
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1: return False
    return sum((d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 == len(digits) % 2 else d for i, d in enumerate(digits)) % 10 == 0

def valid_ssn(value):
    a, b, c = value.split("-")
    return a not in {"000", "666"} and int(a) < 900 and b != "00" and c != "0000"

def valid_ip(value):
    try: ipaddress.ip_address(value); return True
    except ValueError: return False

def valid_phone(value):
    digits = ''.join(c for c in value if c.isdigit())
    if len(digits) == 11 and digits[0] == "1": digits = digits[1:]
    return len(digits) == 10 and digits[0] in "23456789" and digits[3] in "23456789"

PRIVACY = [
    ("SSN", r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", "HIGH", valid_ssn),
    ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b", "MEDIUM", lambda v: True),
    ("PHONE", r"(?<![\w-])(?:\+?1[ .-]?)?(?:\([0-9]{3}\)|[0-9]{3})[ .-]?[0-9]{3}[ .-]?[0-9]{4}(?![\w-])", "MEDIUM", valid_phone),
    ("CARD", r"(?<![0-9])(?:[0-9][ -]?){12,18}[0-9](?![0-9])", "HIGH", luhn),
    ("IP_ADDRESS", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "LOW", valid_ip),
]
SECRETS = [
    ("API_KEY", r"\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|sk-[A-Za-z0-9_-]{20,})\b", "CRITICAL", lambda v: True),
    ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "CRITICAL", lambda v: True),
    ("BEARER_TOKEN", r"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/-]{16,}=*", "HIGH", lambda v: True),
    ("URL_CREDENTIALS", r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@[^\s]+", "CRITICAL", lambda v: True),
    ("CONNECTION_STRING", r"(?i)\b(?:password|pwd|api_key|client_secret)\s*[:=]\s*[\"']?[^\s;\"']{6,}", "HIGH", lambda v: True),
]

class PatternDetector:
    def __init__(self, name, patterns): self.name, self.patterns = name, patterns
    def detect(self, document):
        detections = []
        deadline = time.monotonic() + 10
        for si, section in enumerate(document.sections):
            for kind, pattern, severity, validator, metadata, flags in self.patterns:
                if time.monotonic() > deadline: raise ValueError("Detection exceeded its execution budget")
                try:
                    for m in regex.finditer(pattern, section.text, flags=flags, timeout=0.05):
                        if time.monotonic() > deadline: raise ValueError("Detection exceeded its execution budget")
                        if m.end() == m.start() or not validator(m.group()): continue
                        detections.append(Detection(f"{self.name}:{kind}:{si}:{m.start()}:{len(detections)}", self.name, kind,
                            m.group(), si, m.start(), m.end(), section.location, 0.99, severity, metadata))
                        if len(detections) > 10000: raise ValueError("Too many detections")
                except TimeoutError:
                    raise ValueError("Detection rule exceeded its execution budget; scan stopped") from None
        return detections

class PrivacyDetector(PatternDetector):
    def __init__(self): super().__init__("privacy", [(*p, {}, 0) for p in PRIVACY])

class SecretDetector(PatternDetector):
    def __init__(self): super().__init__("secrets", [(*p, {}, 0) for p in SECRETS])

class OrganizationDetector(PatternDetector):
    def __init__(self, rules):
        patterns = []
        for r in rules:
            if r["enabled"] and r["kind"] in {"keyword", "regex"}:
                pattern = regex.escape(r["pattern"]) if r["kind"] == "keyword" else r["pattern"]
                patterns.append(("CUSTOM_PROTECTED_TERM", pattern, r["severity"], lambda v: True,
                                 {"rule_id": r["id"], "reason": r["name"]}, 0 if r["case_sensitive"] else regex.IGNORECASE))
        super().__init__("organization", patterns)
