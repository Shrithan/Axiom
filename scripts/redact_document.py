#!/usr/bin/env python3
"""
Axiom — Universal document redactor subprocess
================================================
Supports: PDF (visual block redaction), DOCX, XLSX, PPTX (text replacement)
Protocol: newline-delimited JSON over stdin/stdout
"""
import sys, json, os, logging, tempfile

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="[Redactor] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

REDACT_DIR = os.path.join(tempfile.gettempdir(), "axiom_redacted")
os.makedirs(REDACT_DIR, exist_ok=True)

def replacement_text(label: str) -> str:
    return f"[REDACTED·{label}]"

SEV_COLOR = {
    "CRITICAL": (0.60, 0.10, 0.15),
    "HIGH":     (0.75, 0.35, 0.05),
    "MEDIUM":   (0.15, 0.30, 0.50),
    "LOW":      (0.30, 0.35, 0.40),
}

def _out_path(source_path: str, suffix: str) -> str:
    base = os.path.splitext(os.path.basename(source_path))[0]
    return os.path.join(REDACT_DIR, base + "_redacted" + suffix)

def _build_replacements(detections: list) -> list:
    """Return (raw_value, replacement) pairs sorted longest-first."""
    pairs = []
    seen = set()
    for d in detections:
        raw = str(d.get("raw_value", "")).strip()
        label = str(d.get("label", "PII")).upper()
        if raw and raw not in seen:
            seen.add(raw)
            pairs.append((raw, replacement_text(label)))
    pairs.sort(key=lambda p: len(p[0]), reverse=True)
    return pairs

# ── PDF ──────────────────────────────────────────────────────────────────────

def redact_pdf(source_path: str, detections: list) -> str:
    import pymupdf
    out_path = _out_path(source_path, ".pdf")
    doc = pymupdf.open(source_path)

    by_page = {}
    for d in detections:
        raw_val = str(d.get("raw_value", "")).strip()
        if raw_val:
            p_idx = max(0, int(d.get("page", 1)) - 1)
            by_page.setdefault(p_idx, []).append(d)

    for page_idx, page_dets in by_page.items():
        if page_idx >= len(doc):
            continue
        page = doc[page_idx]
        for d in page_dets:
            raw_value = str(d.get("raw_value", "")).strip()
            if not raw_value:
                continue
            fill = SEV_COLOR.get(d.get("severity", "MEDIUM").upper(), (0.2, 0.2, 0.2))
            instances = page.search_for(raw_value)
            if not instances:
                instances = page.search_for(raw_value.strip(".,;:()[]{}"))
            for rect in instances:
                rect_obj = rect.rect if hasattr(rect, "rect") else rect
                rect_obj.x0 -= 1.5; rect_obj.y0 -= 1.5
                rect_obj.x1 += 1.5; rect_obj.y1 += 1.5
                page.add_redact_annot(
                    rect_obj,
                    text=replacement_text(d.get("label", "PII")),
                    fontname="cour", fontsize=7,
                    fill=fill, text_color=(0.95, 0.95, 0.95),
                    align=pymupdf.TEXT_ALIGN_CENTER,
                )
        page.apply_redactions()

    doc.save(out_path, garbage=4, deflate=True)
    doc.close()
    log.info(f"PDF redacted -> {out_path}")
    return out_path

# ── DOCX ─────────────────────────────────────────────────────────────────────

def redact_docx(source_path: str, detections: list) -> str:
    """
    Redact a docx by directly patching XML entries inside the zip.
    Preserves all docx internals (embedded objects, custom XML, etc.).
    """
    import zipfile, shutil, html

    out_path = _out_path(source_path, ".docx")
    reps = _build_replacements(detections)
    if not reps:
        shutil.copy2(source_path, out_path)
        return out_path

    # Build pairs including XML-escaped variants
    expanded = []
    for raw, repl in reps:
        expanded.append((raw, repl))
        escaped = html.escape(raw, quote=False)
        if escaped != raw:
            expanded.append((escaped, repl))
    expanded.sort(key=lambda p: len(p[0]), reverse=True)

    import re as _re
    PATCH_PATTERNS = (
        _re.compile(r"^word/document\.xml$"),
        _re.compile(r"^word/header\d*\.xml$"),
        _re.compile(r"^word/footer\d*\.xml$"),
        _re.compile(r"^word/comments\.xml$"),
    )

    def _patch(data: bytes) -> bytes:
        text = data.decode("utf-8", errors="replace")
        for raw, repl in expanded:
            if raw in text:
                text = text.replace(raw, repl)
        return text.encode("utf-8")

    with zipfile.ZipFile(source_path, "r") as zin, \
         zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if any(pat.match(item.filename) for pat in PATCH_PATTERNS):
                data = _patch(data)
                log.info(f"DOCX patched entry: {item.filename}")
            zout.writestr(item, data)

    log.info(f"DOCX redacted -> {out_path}")
    return out_path

# ── XLSX ─────────────────────────────────────────────────────────────────────

def redact_xlsx(source_path: str, detections: list) -> str:
    """
    Redact an xlsx by directly patching the XML entries inside the zip archive.
    This preserves charts, pivot tables, named ranges, styles, and all other
    xlsx internals that openpyxl silently drops when round-tripping.
    """
    import zipfile, shutil, re as _re

    out_path = _out_path(source_path, ".xlsx")
    reps = _build_replacements(detections)
    if not reps:
        shutil.copy2(source_path, out_path)
        log.info(f"XLSX: no detections, copied as-is -> {out_path}")
        return out_path

    # Build a regex that matches any raw value inside an XML <v> or <t> text node,
    # as well as plain text in shared strings.
    # We do a simple string replacement on the raw XML bytes — safe because
    # the values we're redacting are plain-text PII tokens (not XML markup).
    def _xml_replace(xml_bytes: bytes, pairs: list) -> bytes:
        # xlsx shared strings and inline strings are XML-escaped, so also
        # build XML-escaped variants of each raw value.
        import html
        expanded = []
        for raw, repl in pairs:
            expanded.append((raw, repl))
            escaped = html.escape(raw, quote=False)
            if escaped != raw:
                expanded.append((escaped, repl))
        # Longest first (already sorted, but re-sort after adding escaped variants)
        expanded.sort(key=lambda p: len(p[0]), reverse=True)

        text = xml_bytes.decode("utf-8", errors="replace")
        for raw, repl in expanded:
            if raw in text:
                text = text.replace(raw, repl)
        return text.encode("utf-8")

    # Sheet XML files and the shared strings table are where cell text lives
    PATCH_PATTERNS = (
        _re.compile(r"^xl/worksheets/sheet\d+\.xml$"),
        _re.compile(r"^xl/sharedStrings\.xml$"),
    )

    with zipfile.ZipFile(source_path, "r") as zin, \
         zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if any(pat.match(item.filename) for pat in PATCH_PATTERNS):
                data = _xml_replace(data, reps)
                log.info(f"XLSX patched entry: {item.filename}")
            zout.writestr(item, data)

    log.info(f"XLSX redacted -> {out_path}")
    return out_path

# ── PPTX ─────────────────────────────────────────────────────────────────────

def redact_pptx(source_path: str, detections: list) -> str:
    """
    Redact a pptx by directly patching slide XML entries inside the zip.
    Preserves all pptx internals (animations, embedded media, etc.).
    """
    import zipfile, shutil, html

    out_path = _out_path(source_path, ".pptx")
    reps = _build_replacements(detections)
    if not reps:
        shutil.copy2(source_path, out_path)
        return out_path

    expanded = []
    for raw, repl in reps:
        expanded.append((raw, repl))
        escaped = html.escape(raw, quote=False)
        if escaped != raw:
            expanded.append((escaped, repl))
    expanded.sort(key=lambda p: len(p[0]), reverse=True)

    import re as _re
    PATCH_PATTERN = _re.compile(r"^ppt/slides/slide\d+\.xml$")

    def _patch(data: bytes) -> bytes:
        text = data.decode("utf-8", errors="replace")
        for raw, repl in expanded:
            if raw in text:
                text = text.replace(raw, repl)
        return text.encode("utf-8")

    with zipfile.ZipFile(source_path, "r") as zin, \
         zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if PATCH_PATTERN.match(item.filename):
                data = _patch(data)
                log.info(f"PPTX patched entry: {item.filename}")
            zout.writestr(item, data)

    log.info(f"PPTX redacted -> {out_path}")
    return out_path

# ── Router ────────────────────────────────────────────────────────────────────

def redact_document(source_path: str, detections: list) -> str:
    ext = os.path.splitext(source_path)[1].lower()
    if ext == ".pdf":
        return redact_pdf(source_path, detections)
    elif ext in (".docx", ".doc"):
        return redact_docx(source_path, detections)
    elif ext in (".xlsx", ".xls"):
        return redact_xlsx(source_path, detections)
    elif ext in (".pptx", ".ppt"):
        return redact_pptx(source_path, detections)
    else:
        raise ValueError(f"Unsupported file type for redaction: {ext}")

# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    sys.stdout.write(json.dumps({"id": "init", "ready": True, "error": None}) + "\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            path = redact_document(req["source_path"], req["detections"])
            sys.stdout.write(json.dumps({"id": req["id"], "redacted_path": path, "error": None}) + "\n")
        except Exception as e:
            log.exception("Redaction failed")
            sys.stdout.write(json.dumps({"id": req.get("id", "err"), "error": str(e), "redacted_path": None}) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()