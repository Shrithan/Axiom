#!/usr/bin/env python3
"""
Axiom — PDF PII scanner subprocess
===================================
Protocol (newline-delimited JSON over stdin/stdout):

  Rust  → Python: {"id": "1", "pdf_path": "/path/to/file.pdf"}
  Python → Rust:  {"id": "1", "detections": [...], "error": null}

Each detection:
  {"label": "EMAIL", "severity": "MEDIUM", "redacted": "test****", "page": 1}

Requires: pip install pdfminer.six
"""

import sys, json, re, logging
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="[PDFScanner] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PII patterns
# ---------------------------------------------------------------------------

PII_PATTERNS = [
    ("SSN",         "CRITICAL", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CREDIT_CARD", "CRITICAL", re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b")),
    ("AWS_KEY",     "CRITICAL", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("JWT",         "CRITICAL", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("PRIVATE_KEY", "CRITICAL", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("PASSWORD",    "CRITICAL", re.compile(r"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*\S+")),
    ("API_KEY",     "CRITICAL", re.compile(r"(?i)(?:api[_\-]?key|access[_\-]?token)\s*[:=]\s*[A-Za-z0-9_\-]{16,}")),
    ("EMAIL",       "MEDIUM",   re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("PHONE",       "MEDIUM",   re.compile(r"\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b")),
    ("IP_ADDRESS",  "LOW",      re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

def redact(text):
    return text[:4] + "****" if len(text) > 4 else "*" * len(text)

# ---------------------------------------------------------------------------
# PDF text extraction — page by page
# ---------------------------------------------------------------------------

def extract_pages(pdf_path: str):
    """Yield (page_number, text) for each page. Requires pdfminer.six."""
    from pdfminer.high_level import extract_pages as pm_extract
    from pdfminer.layout import LTTextContainer

    for page_num, page_layout in enumerate(pm_extract(pdf_path), start=1):
        page_text = ""
        for element in page_layout:
            if isinstance(element, LTTextContainer):
                page_text += element.get_text()
        yield page_num, page_text


def scan_pdf(pdf_path: str) -> list:
    log.info(f"Scanning: {pdf_path}")
    detections = []
    seen = set()

    try:
        pages = list(extract_pages(pdf_path))
    except Exception as e:
        log.error(f"PDF extraction failed: {e}")
        raise

    log.info(f"  {len(pages)} page(s) extracted")

    for page_num, text in pages:
        if not text.strip():
            continue
        for label, severity, pattern in PII_PATTERNS:
            for m in pattern.finditer(text):
                matched = m.group(0)
                key = (label, matched)
                if key in seen:
                    continue
                seen.add(key)
                log.info(f"  p{page_num} {label}: {redact(matched)!r}")
                detections.append({
                    "label":    label,
                    "severity": severity,
                    "redacted": redact(matched),
                    "page":     page_num,
                })

    log.info(f"Total: {len(detections)} detection(s)")
    return detections

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    # Check pdfminer is available
    try:
        import pdfminer
    except ImportError:
        err = {"id": "init", "detections": [], "error": "pdfminer.six not installed — run: pip install pdfminer.six", "ready": False}
        sys.stdout.write(json.dumps(err) + "\n")
        sys.stdout.flush()
        sys.exit(1)

    # Signal ready
    sys.stdout.write(json.dumps({"id": "init", "detections": [], "error": None, "ready": True}) + "\n")
    sys.stdout.flush()
    log.info("Ready — waiting for PDF scan requests")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            sys.stdout.write(json.dumps({"id": "?", "detections": [], "error": f"JSON: {e}"}) + "\n")
            sys.stdout.flush()
            continue

        req_id   = req.get("id", "?")
        pdf_path = req.get("pdf_path", "")
        log.info(f"Request id={req_id} path={pdf_path!r}")

        try:
            dets = scan_pdf(pdf_path)
            resp = {"id": req_id, "detections": dets, "error": None}
        except Exception as e:
            resp = {"id": req_id, "detections": [], "error": str(e)}

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()