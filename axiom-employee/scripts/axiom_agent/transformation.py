"""Transform original offsets, once. Overlaps never reintroduce sensitive text."""
from .models import ACTIONS

def replacement(value, decision, kind):
    mode = decision["transformation"]
    if mode == "REMOVE": return ""
    if mode == "REPLACE": return decision["replacement"]
    if mode == "MASK" and kind in {"SSN", "CARD", "PHONE"}:
        positions = [i for i, char in enumerate(value) if char.isdigit()]
        keep = set(positions[-4:])
        return ''.join('*' if c.isdigit() and i not in keep else c for i, c in enumerate(value))
    # Email masking and general redaction conceal every non-whitespace character.
    return ''.join(c if c.isspace() else '█' for c in value)

def transform(document, detections, decisions):
    if any(d["action"] == "BLOCK" for d in decisions): return None
    decision_map = {d["detection_id"]: d for d in decisions}
    output = []
    for si, section in enumerate(document.sections):
        candidates = [(d, decision_map[d.id]) for d in detections if d.section == si and decision_map[d.id]["action"] == "REDACT"]
        candidates.sort(key=lambda pair: (pair[0].start, pair[0].end, pair[1]["rule_id"] or ""))
        groups = []
        for det, decision in candidates:
            if groups and det.start < groups[-1][1]:
                groups[-1][1] = max(groups[-1][1], det.end)
                groups[-1][2].append((det, decision))
            else: groups.append([det.start, det.end, [(det, decision)]])
        text = section.text
        for start, end, group in reversed(groups):
            if len(group) > 1:
                # A conservative union redaction resolves overlapping masks/replacements.
                protected = ''.join(c if c.isspace() else '█' for c in text[start:end])
            else:
                det, decision = group[0]
                protected = replacement(text[start:end], decision, det.type)
            text = text[:start] + protected + text[end:]
        output.append(dict(text=text, location=section.location))
    return output
