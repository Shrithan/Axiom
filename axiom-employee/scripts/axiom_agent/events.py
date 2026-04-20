"""Normalized local events and future integration boundaries."""
from dataclasses import asdict
from typing import Protocol
from .models import ContentEvent, EVENTS, DESTINATIONS

SOURCES = {"manual", "filesystem", "clipboard", "boundary", "browser"}

def normalize_event(payload):
    if not isinstance(payload, dict): raise ValueError("Invalid event")
    allowed = ContentEvent.__dataclass_fields__
    if set(payload) - set(allowed): raise ValueError("Unsupported event fields")
    event = ContentEvent(**payload)
    if event.source not in SOURCES or event.action not in EVENTS or event.destination not in DESTINATIONS:
        raise ValueError("Invalid event source, action or destination")
    if not isinstance(event.timestamp, (int, float)) or not 0 < event.timestamp < 1e12:
        raise ValueError("Invalid event timestamp")
    for name in allowed:
        if name != "timestamp":
            value = getattr(event, name)
            if not isinstance(value, str) or len(value) > (4096 if name == "file_path" else 256):
                raise ValueError("Invalid event field")
    if not event.id: raise ValueError("Missing event ID")
    if event.source == "clipboard" and (event.action != "COPY" or event.content_type != "text"):
        raise ValueError("Clipboard events must be text COPY events")
    if event.source == "filesystem" and event.action not in {"FILE_CREATED", "FILE_MODIFIED"}:
        raise ValueError("Filesystem watcher does not observe document OPEN events")
    return event

class EventSource(Protocol):
    def start(self): ...
    def stop(self): ...
    def status(self) -> dict: ...

class BoundaryAdapter(Protocol):
    """Only a caller that controls the operation may enforce a returned decision."""
    def before_send(self, event: ContentEvent, content: bytes) -> dict: ...
    def before_upload(self, event: ContentEvent, content: bytes) -> dict: ...
    def before_attach(self, event: ContentEvent, content: bytes) -> dict: ...

class PolicyProvider(Protocol):
    """Future signed-bundle providers can implement this without changing detectors."""
    def rules(self) -> list[dict]: ...
