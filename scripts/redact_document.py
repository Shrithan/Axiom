#!/usr/bin/env python3
"""
Axiom — Document redactor subprocess
=====================================
Takes an original file + detections from the scanner, produces a redacted
copy in a temp directory. The original is NEVER modified.

Supports: PDF (native PyMuPDF redaction)
          DOCX / XLSX / PPTX → converted to PDF first, then redacted

Protocol (newline-delimited JSON over stdin/stdout):
  Rust → Python:
    {
      "id":         "1",
      "source_path": "/path/to/original.pdf",
      "detections": [
        {"label":"EMAIL","raw_value":"bob@acme.com","page":1, ...},
        ...
      ]
    }

  Python → Rust:
    {
      "id":           "1",
      "redacted_path": "/tmp/axiom_redacted/original_redacted.pdf",
      "error":        null
    }

Requires:
  pip install pymupdf python-docx openpyxl python-pptx
"""

import sys, json, os, logging, tempfile, shutil, re
logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="[Redactor] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

REDACT_DIR = os.path.join(tempfile.gettempdir(), "axiom_redacted")
os.makedirs(REDACT_DIR, exist_ok=True)

# Replacement label style:  ██ REDACTED·EMAIL ██
def replacement_text(label: str) -> str:
    return f"[REDACTED·{label}]"

# Severity → redaction bar colour (RGB 0-1)
# Sleek, matte "Enterprise" colors (PyMuPDF uses 0.0 to 1.0 scale)
SEV_COLOR = {
    "CRITICAL": (0.60, 0.10, 0.15),   # Deep Crimson
    "HIGH":     (0.75, 0.35, 0.05),   # Burnt Orange
    "MEDIUM":   (0.15, 0.30, 0.50),   # Deep Navy Space
    "LOW":      (0.30, 0.35, 0.40),   # Slate Grey
}
DEFAULT_COLOR = (0.2, 0.2, 0.2)


# ---------------------------------------------------------------------------
# Non-PDF → PDF conversion (needed to enable PyMuPDF redaction)
# ---------------------------------------------------------------------------

def convert_to_pdf(source_path: str, out_dir: str) -> str:
    """
    Convert DOCX/XLSX/PPTX to PDF using LibreOffice headless if available,
    otherwise fall back to a best-effort python-docx → reportlab approach.
    Returns the path to the converted PDF.
    """
    import subprocess
    base = os.path.splitext(os.path.basename(source_path))[0]
    out_pdf = os.path.join(out_dir, base + "_converted.pdf")

    # Try LibreOffice first (best quality)
    for lo in ("libreoffice", "soffice", "/Applications/LibreOffice.app/Contents/MacOS/soffice"):
        try:
            result = subprocess.run(
                [lo, "--headless", "--convert-to", "pdf",
                 "--outdir", out_dir, source_path],
                capture_output=True, timeout=60
            )
            # LibreOffice names the output <basename>.pdf
            lo_out = os.path.join(out_dir, base + ".pdf")
            if result.returncode == 0 and os.path.exists(lo_out):
                log.info(f"Converted via LibreOffice: {lo_out}")
                return lo_out
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    raise RuntimeError(
        "Cannot convert to PDF: LibreOffice not found. "
        "Install LibreOffice or supply a PDF directly."
    )


# ---------------------------------------------------------------------------
# Core redaction — PyMuPDF
# ---------------------------------------------------------------------------

def redact_pdf(source_path: str, detections: list) -> str:
    import pymupdf

    base     = os.path.splitext(os.path.basename(source_path))[0]
    out_path = os.path.join(REDACT_DIR, base + "_redacted.pdf")
    doc = pymupdf.open(source_path)

    by_page: dict[int, list] = {}
    for d in detections:
        raw_value = str(d.get("raw_value", "")).strip()
        if raw_value:
            by_page.setdefault(max(0, int(d.get("page", 1)) - 1), []).append(d)

    redaction_count = 0

    for page_idx, page_dets in by_page.items():
        if page_idx >= len(doc): continue
        page = doc[page_idx]
        drawn_rects = [] # Spatial deduplication

        for d in page_dets:
            raw_value = str(d.get("raw_value", "")).strip()
            if not raw_value: continue

            label     = d.get("label", "PII").upper()
            fill      = SEV_COLOR.get(d.get("severity", "MEDIUM").upper(), DEFAULT_COLOR)
            repl_text = replacement_text(label)

            # 1. Try exact match
            instances = page.search_for(raw_value)
            if not instances:
                instances = page.search_for(raw_value, quads=True)

            # 2. Fallback: Strip punctuation (fixes issues with trailing periods)
            if not instances:
                clean_val = raw_value.strip(".,;:()[]{}")
                instances = page.search_for(clean_val)

            # 3. Fallback: Word-by-word (fixes line-break issues)
            if not instances and " " in clean_val:
                for word in clean_val.split():
                    word_clean = word.strip(".,;:()[]{}")
                    if len(word_clean) > 3: # Skip small words to avoid over-redacting
                        instances.extend(page.search_for(word_clean))

            if not instances:
                log.warning(f"  p{page_idx+1}: '{raw_value[:30]}' not found in text layer")
                continue

            for rect in instances:
                # If it has a rect attribute (from quads), use it
                rect_obj = rect.rect if hasattr(rect, "rect") else rect
                
                # Check if we already drew a box here
                # Check if we already drew a box here
                if not any(rect_obj.intersects(drawn) for drawn in drawn_rects):
                    
                    # Add 1.5px of padding so the redaction box breathes a little
                    rect_obj.x0 -= 1.5
                    rect_obj.y0 -= 1.5
                    rect_obj.x1 += 1.5
                    rect_obj.y1 += 1.5

                    page.add_redact_annot(
                        rect_obj, 
                        text=repl_text, 
                        fontname="cour",                 # Courier for a technical/classified look
                        fontsize=7,                      # Slightly smaller, much neater
                        fill=fill, 
                        text_color=(0.95, 0.95, 0.95),   # Soft off-white
                        align=pymupdf.TEXT_ALIGN_CENTER
                    )
                    drawn_rects.append(rect_obj)
                    redaction_count += 1

        page.apply_redactions()

    for page in doc:
        page.insert_text((10, page.rect.height - 12), "⚠ AXIOM REDACTED PREVIEW", fontname="helv", fontsize=7, color=(0.6, 0.0, 0.0))

    doc.save(out_path, garbage=4, deflate=True)
    doc.close()
    return out_path

def redact_document(source_path: str, detections: list) -> str:
    """
    Entry point. Returns path to redacted PDF.
    Converts non-PDF files first.
    """
    ext = os.path.splitext(source_path)[1].lower()

    if ext == ".pdf":
        return redact_pdf(source_path, detections)

    # Non-PDF: convert first, then redact
    log.info(f"Converting {ext} → PDF before redacting…")
    tmp_dir   = tempfile.mkdtemp(prefix="axiom_conv_")
    try:
        pdf_path = convert_to_pdf(source_path, tmp_dir)
        return redact_pdf(pdf_path, detections)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    # Check pymupdf
    try:
        import pymupdf  # noqa
    except ImportError:
        sys.stdout.write(json.dumps({
            "id": "init", "ready": False,
            "error": "pymupdf not installed — run: pip install pymupdf",
        }) + "\n")
        sys.stdout.flush()
        sys.exit(1)

    sys.stdout.write(json.dumps({"id": "init", "ready": True, "error": None}) + "\n")
    sys.stdout.flush()
    log.info("Redactor ready")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            sys.stdout.write(json.dumps({"id": "?", "redacted_path": None, "error": f"JSON: {e}"}) + "\n")
            sys.stdout.flush()
            continue

        req_id      = req.get("id", "?")
        source_path = req.get("source_path", "")
        detections  = req.get("detections", [])
        log.info(f"Request id={req_id} path={source_path!r} dets={len(detections)}")

        if not source_path or not os.path.exists(source_path):
            sys.stdout.write(json.dumps({
                "id": req_id, "redacted_path": None,
                "error": f"File not found: {source_path}",
            }) + "\n")
            sys.stdout.flush()
            continue

        try:
            out_path = redact_document(source_path, detections)
            resp = {"id": req_id, "redacted_path": out_path, "error": None}
        except Exception as e:
            log.error(f"Redaction failed: {e}", exc_info=True)
            resp = {"id": req_id, "redacted_path": None, "error": str(e)}

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()