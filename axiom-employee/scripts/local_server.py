"""Same-origin loopback host; no external requests or content logging."""
import json
import secrets
import subprocess
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "dist"
TOKEN = secrets.token_urlsafe(32)
ORIGIN = "http://127.0.0.1:8765"

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs): super().__init__(*args, directory=str(ROOT), **kwargs)
    def log_message(self, *args): pass
    def valid_host(self): return self.headers.get("Host") == "127.0.0.1:8765"
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
        super().end_headers()
    def respond(self, status, data):
        raw = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_GET(self):
        if not self.valid_host(): return self.respond(403, {"error": "Invalid host"})
        if self.path == "/api/session": return self.respond(200, {"token": TOKEN})
        if self.path.startswith("/api/"): return self.respond(404, {"error": "Not found"})
        super().do_GET()
    def do_POST(self):
        if not self.valid_host() or self.headers.get("Origin") != ORIGIN or self.headers.get("X-Axiom-Token") != TOKEN:
            return self.respond(403, {"error": "Invalid local request"})
        if self.path != "/api/agent": return self.respond(404, {"error": "Not found"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 30 * 1024 * 1024: raise ValueError("Request exceeds limits")
            raw = self.rfile.read(size)
            json.loads(raw)
            worker = subprocess.run([sys.executable, str(Path(__file__).with_name("agent_ipc.py"))],
                input=raw, capture_output=True, timeout=30)
            response = json.loads(worker.stdout)
            self.respond(400 if "error" in response else 200, response)
        except Exception as exc:
            message = str(exc) if isinstance(exc, ValueError) else "Local operation failed"
            self.respond(400, {"error": message})

if __name__ == "__main__":
    if not ROOT.is_dir(): raise SystemExit("Run npm run build first")
    print("Axiom local agent: " + ORIGIN, flush=True)
    HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
