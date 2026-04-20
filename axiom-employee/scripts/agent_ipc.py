"""Single local request on stdin; safe errors only on stdout."""
import json
import sys
sys.dont_write_bytecode = True
from axiom_agent.service import Service
try:
    request = json.loads(sys.stdin.read(30 * 1024 * 1024))
    print(json.dumps({"result": Service().handle(request)}))
except Exception as exc:
    message = str(exc) if isinstance(exc, ValueError) else "Local operation failed; check parser dependencies and data directory permissions"
    print(json.dumps({"error": message}))
