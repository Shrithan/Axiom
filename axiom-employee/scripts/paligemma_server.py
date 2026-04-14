#!/usr/bin/env python3
"""
Axiom — PaliGemma 3B vision subprocess server (OCR + regex edition)
====================================================================
Strategy: use PaliGemma OCR to extract all text, then regex for PII.
Only run a bbox query for confirmed regex hits.
"""

import sys, json, base64, re, io, logging
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="[PaliGemma] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

_model = _processor = _device = None

def load_model():
    global _model, _processor, _device
    log.info("Loading PaliGemma 3B…")
    import torch
    from transformers import PaliGemmaForConditionalGeneration, PaliGemmaProcessor
    model_id = "google/paligemma-3b-mix-448"
    _device = "mps" if torch.backends.mps.is_available() else "cuda" if torch.cuda.is_available() else "cpu"
    log.info(f"Using device: {_device}")
    _processor = PaliGemmaProcessor.from_pretrained(model_id)
    _model = PaliGemmaForConditionalGeneration.from_pretrained(model_id, torch_dtype=torch.bfloat16, device_map=_device)
    _model.eval()
    log.info("PaliGemma 3B ready ✓")

# PII patterns: (label, severity, regex)
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

LOC_RE = re.compile(r"<loc(\d{4})>")

def run_prompt(image, prompt, max_new_tokens=512):
    import torch
    inputs = _processor(text=prompt, images=image, return_tensors="pt", padding=True).to(_device)
    with torch.inference_mode():
        output = _model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False)
    input_len = inputs["input_ids"].shape[1]
    return _processor.decode(output[0][input_len:], skip_special_tokens=True)

def loc_to_norm(val):
    return max(0.0, min(1.0, val / 1023.0))

def find_text_bbox(image, text):
    """Locate specific text in image. Returns (x,y,w,h) normalised or None."""
    excerpt = text[:40].strip()
    try:
        raw = run_prompt(image, f"<image> detect text \"{excerpt}\"", max_new_tokens=32)
    except Exception as e:
        log.warning(f"bbox query failed: {e}")
        return None
    locs = [int(v) for v in LOC_RE.findall(raw)]
    if len(locs) < 4:
        return None
    y1, x1, y2, x2 = [loc_to_norm(locs[i]) for i in range(4)]
    if x2 <= x1 or y2 <= y1 or (x2 - x1) * (y2 - y1) > 0.90:
        return None
    return (x1, y1, x2 - x1, y2 - y1)

def redact(text):
    return text[:4] + "****" if len(text) > 4 else "*" * len(text)

def detect_pii(image):
    # Step 1: OCR the whole screen
    log.info("Running OCR…")
    try:
        ocr_text = run_prompt(image, "<image> ocr", max_new_tokens=512)
        log.info(f"OCR ({len(ocr_text)} chars): {ocr_text[:300]!r}")
    except Exception as e:
        log.error(f"OCR failed: {e}")
        return []

    if not ocr_text.strip():
        log.info("OCR empty — no detections")
        return []

    # Step 2: regex scan
    detections = []
    seen = set()
    for label, severity, pattern in PII_PATTERNS:
        for m in pattern.finditer(ocr_text):
            matched = m.group(0)
            key = (label, matched)
            if key in seen:
                continue
            seen.add(key)
            log.info(f"  HIT {label}: {redact(matched)!r}")

            # Step 3: try to get bbox
            bbox = find_text_bbox(image, matched)
            if bbox:
                x, y, w, h = bbox
                log.info(f"    located at x={x:.3f} y={y:.3f} w={w:.3f} h={h:.3f}")
            else:
                log.info(f"    no bbox (will show in panel only)")
                x = y = w = h = 0.0

            detections.append({
                "label":    label,
                "severity": severity,
                "redacted": redact(matched),
                "x": round(x, 4), "y": round(y, 4),
                "w": round(w, 4), "h": round(h, 4),
                "has_bbox": bbox is not None,
            })

    log.info(f"Total: {len(detections)} detection(s)")
    return detections

def process_request(req):
    from PIL import Image
    req_id = req.get("id", "?")
    try:
        image = Image.open(io.BytesIO(base64.b64decode(req["image"]))).convert("RGB")
    except Exception as e:
        return {"id": req_id, "detections": [], "error": f"Image decode failed: {e}"}
    try:
        return {"id": req_id, "detections": detect_pii(image), "error": None}
    except Exception as e:
        log.error(f"Detection failed: {e}", exc_info=True)
        return {"id": req_id, "detections": [], "error": str(e)}

def main():
    try:
        load_model()
    except Exception as e:
        sys.stdout.write(json.dumps({"id": "init", "detections": [], "error": f"Model load failed: {e}"}) + "\n")
        sys.stdout.flush()
        sys.exit(1)

    sys.stdout.write(json.dumps({"id": "init", "detections": [], "error": None, "ready": True}) + "\n")
    sys.stdout.flush()
    log.info("Ready — waiting for requests")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            sys.stdout.write(json.dumps({"id": "?", "detections": [], "error": f"JSON parse: {e}"}) + "\n")
            sys.stdout.flush()
            continue
        log.info(f"Request id={req.get('id')} image_len={len(req.get('image',''))}")
        resp = process_request(req)
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()