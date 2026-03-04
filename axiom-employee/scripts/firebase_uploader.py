#!/usr/bin/env python3
"""
Axiom — Firebase Firestore uploader subprocess
================================================
Handles all Firestore REST operations for both employee and admin sides.
Protocol: newline-delimited JSON over stdin/stdout

Required env vars:
  AXIOM_FIREBASE_PROJECT_ID   — your Firebase project ID
  AXIOM_FIREBASE_API_KEY      — your Firebase Web API key (for Auth REST)
  AXIOM_FIREBASE_ID_TOKEN     — (optional) pre-obtained ID token; if absent,
                                 the subprocess signs in with service-account
                                 email/password set via AXIOM_FB_EMAIL / AXIOM_FB_PASS

Collections used:
  employees       — employee records (mirrors the old `employees` SQL table)
  activity_log    — scan activity records (mirrors the old `activity_log` SQL table)
"""

import sys, json, os, logging, time
import urllib.request, urllib.error

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="[Firebase] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

PROJECT_ID = "axiom-be6c0"
API_KEY    = "AIzaSyBz0BaaRtAS9hGZbh3uaJ-2QKZhktfXNgs"
ID_TOKEN   = ""  # leave empty — script will sign in with email/password below

FIRESTORE_BASE = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents"
AUTH_URL       = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

_cached_token: str = ""
_token_expiry: float = 0.0

def _sign_in() -> str:
    """Sign in with email/password and return an ID token."""
    email    = "YOUR_EMAIL_HERE"      # e.g. backend@axiom.local
    password = "YOUR_PASSWORD_HERE"   # the password you set in Firebase Auth
    if not email or not password:
        raise RuntimeError("Email and password not set in firebase_uploader.py")
    body = json.dumps({"email": email, "password": password, "returnSecureToken": True}).encode()
    req = urllib.request.Request(AUTH_URL, data=body,
                                  headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read())
    return data["idToken"]


def get_token() -> str:
    global _cached_token, _token_expiry
    if ID_TOKEN:
        return ID_TOKEN
    now = time.monotonic()
    if _cached_token and now < _token_expiry:
        return _cached_token
    _cached_token = _sign_in()
    _token_expiry = now + 3000  # refresh ~50 min
    return _cached_token


def _headers() -> dict:
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {get_token()}",
    }

# ---------------------------------------------------------------------------
# Firestore value encoding / decoding
# ---------------------------------------------------------------------------

def _encode_value(v) -> dict:
    if v is None:
        return {"nullValue": None}
    if isinstance(v, bool):
        return {"booleanValue": v}
    if isinstance(v, int):
        return {"integerValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, str):
        return {"stringValue": v}
    if isinstance(v, list):
        return {"arrayValue": {"values": [_encode_value(i) for i in v]}}
    if isinstance(v, dict):
        return {"mapValue": {"fields": {k: _encode_value(val) for k, val in v.items()}}}
    return {"stringValue": str(v)}


def _decode_value(v: dict):
    if "nullValue" in v:      return None
    if "booleanValue" in v:   return v["booleanValue"]
    if "integerValue" in v:   return int(v["integerValue"])
    if "doubleValue" in v:    return v["doubleValue"]
    if "stringValue" in v:    return v["stringValue"]
    if "timestampValue" in v: return v["timestampValue"]
    if "arrayValue" in v:
        return [_decode_value(i) for i in v["arrayValue"].get("values", [])]
    if "mapValue" in v:
        return {k: _decode_value(val) for k, val in v["mapValue"].get("fields", {}).items()}
    return None


def _encode_doc(data: dict) -> dict:
    return {"fields": {k: _encode_value(v) for k, v in data.items()}}


def _decode_doc(doc: dict) -> dict:
    return {k: _decode_value(v) for k, v in doc.get("fields", {}).items()}

# ---------------------------------------------------------------------------
# Firestore REST helpers
# ---------------------------------------------------------------------------

def _request(method: str, url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=_headers(), method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        raise RuntimeError(f"Firestore {method} {url} → {e.code}: {err_body}") from e


def fs_get(collection: str, doc_id: str) -> dict | None:
    url = f"{FIRESTORE_BASE}/{collection}/{doc_id}"
    try:
        doc = _request("GET", url)
        return _decode_doc(doc)
    except RuntimeError as e:
        if "404" in str(e):
            return None
        raise


def fs_set(collection: str, doc_id: str, data: dict) -> dict:
    """Create or overwrite a document."""
    url = f"{FIRESTORE_BASE}/{collection}/{doc_id}"
    return _request("PATCH", url, _encode_doc(data))


def fs_update(collection: str, doc_id: str, data: dict) -> dict:
    """Partial update — only the provided fields."""
    fields_mask = "&".join(f"updateMask.fieldPaths={k}" for k in data.keys())
    url = f"{FIRESTORE_BASE}/{collection}/{doc_id}?{fields_mask}"
    return _request("PATCH", url, _encode_doc(data))


def fs_list(collection: str, page_size: int = 500) -> list[dict]:
    url = f"{FIRESTORE_BASE}/{collection}?pageSize={page_size}"
    result = _request("GET", url)
    docs = result.get("documents", [])
    return [_decode_doc(d) for d in docs]


def fs_query(collection: str, field: str, op: str, value) -> list[dict]:
    """
    Run a simple single-field equality query via the runQuery endpoint.
    op: one of EQUAL, LESS_THAN, GREATER_THAN, etc.
    """
    url = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents:runQuery"
    body = {
        "structuredQuery": {
            "from": [{"collectionId": collection}],
            "where": {
                "fieldFilter": {
                    "field": {"fieldPath": field},
                    "op": op,
                    "value": _encode_value(value),
                }
            },
            "limit": 500,
        }
    }
    results = _request("POST", url, body)
    if not isinstance(results, list):
        return []
    return [_decode_doc(r["document"]) for r in results if "document" in r]


def fs_delete(collection: str, doc_id: str) -> None:
    url = f"{FIRESTORE_BASE}/{collection}/{doc_id}"
    _request("DELETE", url)

# ---------------------------------------------------------------------------
# Operation handlers
# ---------------------------------------------------------------------------

def handle(req: dict) -> dict:
    op  = req.get("op", "")
    rid = req.get("id", "?")

    # ── Write activity log entry ────────────────────────────────────────────
    if op == "log_activity":
        data = req["data"]
        fs_set("activity_log", data["id"], data)
        log.info(f"activity_log/{data['id']} written")
        return {"id": rid, "ok": True, "error": None}

    # ── Login (verify employee credentials) ────────────────────────────────
    elif op == "login":
        results = fs_query("employees", "username", "EQUAL", req["username"])
        for emp in results:
            if emp.get("password") == req["password"] and emp.get("status") == "active":
                return {"id": rid, "ok": True, "error": None,
                        "user": {"id": emp["id"], "name": emp["name"],
                                 "department": emp.get("department", "")}}
        return {"id": rid, "ok": False, "error": "Invalid credentials or account suspended."}

    # ── List all employees ──────────────────────────────────────────────────
    elif op == "list_employees":
        docs = fs_list("employees")
        return {"id": rid, "ok": True, "error": None, "employees": docs}

    # ── Add employee ────────────────────────────────────────────────────────
    elif op == "add_employee":
        data = req["data"]
        existing = fs_query("employees", "username", "EQUAL", data["username"])
        if existing:
            return {"id": rid, "ok": False, "error": f"Username '{data['username']}' already exists."}
        fs_set("employees", data["id"], data)
        log.info(f"employees/{data['id']} created")
        return {"id": rid, "ok": True, "error": None}

    # ── Update employee (partial patch) ────────────────────────────────────
    elif op == "update_employee":
        fs_update("employees", req["doc_id"], req["patch"])
        doc = fs_get("employees", req["doc_id"])
        return {"id": rid, "ok": True, "error": None, "employee": doc}

    # ── Remove employee ─────────────────────────────────────────────────────
    elif op == "remove_employee":
        fs_delete("employees", req["doc_id"])
        return {"id": rid, "ok": True, "error": None}

    # ── List activity log ───────────────────────────────────────────────────
    elif op == "list_activity":
        emp_id = req.get("employee_id")
        if emp_id:
            docs = fs_query("activity_log", "employee_id", "EQUAL", emp_id)
        else:
            docs = fs_list("activity_log")
        # Sort by timestamp descending (Firestore REST doesn't guarantee order)
        docs.sort(key=lambda d: d.get("timestamp", 0), reverse=True)
        return {"id": rid, "ok": True, "error": None, "logs": docs}

    # ── Update last_seen / stats on employee after scan ────────────────────
    elif op == "update_employee_stats":
        fs_update("employees", req["doc_id"], req["patch"])
        return {"id": rid, "ok": True, "error": None}

    elif op == "mark_redacted":
        fs_update("activity_log", req["doc_id"], {"redacted": True})
        log.info(f"activity_log/{req["doc_id"]} marked redacted")
        return {"id": rid, "ok": True, "error": None}


    else:
        return {"id": rid, "ok": False, "error": f"Unknown op: {op}"}

# ---------------------------------------------------------------------------
# Bootstrap: ensure default admin employee exists
# ---------------------------------------------------------------------------

def bootstrap_admin():
    if not PROJECT_ID:
        log.warning("AXIOM_FIREBASE_PROJECT_ID not set — skipping bootstrap")
        return
    try:
        existing = fs_get("employees", "e_admin")
        if existing is None:
            fs_set("employees", "e_admin", {
                "id": "e_admin", "name": "Admin User", "username": "admin",
                "password": "password", "department": "IT", "status": "active",
                "last_seen": 0, "total_scans": 0, "total_detections": 0,
                "risk_score": 0, "avatar_initials": "AD",
            })
            log.info("Default admin employee created in Firestore")
    except Exception as e:
        log.warning(f"Bootstrap skipped: {e}")

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    try:
        # Validate credentials immediately
        get_token()
        bootstrap_admin()
    except Exception as e:
        sys.stdout.write(json.dumps({"id": "init", "ready": False, "error": str(e)}) + "\n")
        sys.stdout.flush()
        sys.exit(1)

    sys.stdout.write(json.dumps({"id": "init", "ready": True, "error": None}) + "\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req  = json.loads(line)
            resp = handle(req)
        except Exception as e:
            log.exception("Operation failed")
            req_id = json.loads(line).get("id", "?") if line else "?"
            resp = {"id": req_id, "ok": False, "error": str(e)}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()