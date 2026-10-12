"""Private loopback preview of staged rules using existing production nodes/state."""
import importlib.util
import json
import os
from pathlib import Path
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import yaml
from snapshot import read_json, validate_manifest, validate_inline

HERE = Path(__file__).resolve().parent
BASE = Path(os.environ.get("SUBGEN_DIR", "/opt/proxy-stack/subgen"))
STATE = BASE / "snapshot-state"
spec = importlib.util.spec_from_file_location("production_preview", HERE / "generator.py")
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
token_file = HERE / "preview-token"
if not token_file.exists():
    token_file.write_text(secrets.token_urlsafe(32), encoding="ascii")
    token_file.chmod(0o600)
TOKEN = token_file.read_text().strip()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_HEAD(self): self.serve(False)
    def do_GET(self): self.serve(True)
    def serve(self, body):
        if self.path == "/healthz":
            data = b"preview ready\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if body: self.wfile.write(data)
            return
        if not secrets.compare_digest(self.path, "/preview/" + TOKEN):
            self.send_error(404)
            return
        try:
            tag = read_json(STATE / "staged.json")["build_id"]
            m = validate_manifest(read_json(STATE / tag / "build-manifest.json"))
            inline = validate_inline(m, read_json(STATE / tag / "inline-rules.json"))
            cfg = read_json(BASE / "config.json")
            doc = generator.make_config(cfg, generator.node_states(cfg), snapshot_override=(m, inline))
            data = yaml.safe_dump(doc, allow_unicode=True, sort_keys=False).encode()
        except Exception:
            self.send_error(503, "Preview unavailable")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Rule-Build", tag)
        self.send_header("Profile-Update-Interval", "24")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if body: self.wfile.write(data)

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8768), Handler).serve_forever()
