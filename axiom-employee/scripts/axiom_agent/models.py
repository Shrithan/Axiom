from dataclasses import dataclass, field, asdict
from typing import Protocol
import time
import uuid

@dataclass
class Section:
    text: str
    location: dict

@dataclass
class Document:
    id: str
    name: str
    type: str
    sections: list[Section]
    metadata: dict = field(default_factory=dict)

@dataclass
class Detection:
    id: str
    detector: str
    type: str
    matched_text: str
    section: int
    start: int
    end: int
    location: dict
    confidence: float
    severity: str
    metadata: dict = field(default_factory=dict)

@dataclass
class ContentEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    source: str = "manual"
    content_type: str = "document"
    file_path: str = ""
    source_application_id: str = ""
    action: str = "OPEN"
    destination: str = "EXTERNAL"
    source_application: str = "Axiom"
    destination_domain: str = ""
    file_type: str = ""
    user: str = ""
    device: str = ""

class Detector(Protocol):
    def detect(self, document: Document) -> list[Detection]: ...

ACTIONS = {"ALLOW": 0, "WARN": 1, "REDACT": 2, "BLOCK": 3}
TRANSFORMS = {"REDACT", "MASK", "REMOVE", "REPLACE"}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
EVENTS = {"OPEN", "COPY", "PASTE", "ATTACH", "UPLOAD", "EXPORT", "PRINT", "SEND", "SCREEN_SHARE", "FILE_CREATED", "FILE_MODIFIED"}
DESTINATIONS = {"INTERNAL", "PARTNER", "EXTERNAL", "PUBLIC", "UNSPECIFIED"}
