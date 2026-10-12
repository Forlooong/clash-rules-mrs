#!/usr/bin/env python3
"""Exercise actual Mihomo matching; all traced outbounds end at loopback mocks."""
import argparse
import collections
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from runtime.snapshot import assemble, read_json

class Mock(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_CONNECT(self):
        try:
            self.connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            data = b""
            self.connection.settimeout(5)
            while b"\r\n\r\n" not in data:
                chunk = self.connection.recv(4096)
                if not chunk: return
                data += chunk
            self.connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nx")
            time.sleep(.8)
            self.connection.sendall(b"x")
        except OSError:
            pass
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"x"); self.wfile.flush()
        time.sleep(.8)
        self.wfile.write(b"x")

def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def trace(rule):
    fields = rule.rsplit(",", 2)
    if rule.endswith(",no-resolve"):
        prefix, action, option = fields
        return prefix + "," + {"DIRECT": "TRACE_DIRECT", "REJECT": "TRACE_REJECT"}.get(action, action) + "," + option
    prefix, action = rule.rsplit(",", 1)
    return prefix + "," + {"DIRECT": "TRACE_DIRECT", "REJECT": "TRACE_REJECT"}.get(action, action)

def exercise(mihomo, config, cases):
    proxy_port, api_port = port(), port()
    config.update({"mixed-port": proxy_port, "external-controller": "127.0.0.1:" + str(api_port),
                   "find-process-mode": "off",
                   "secret": "", "allow-lan": False, "bind-address": "127.0.0.1", "log-level": "info"})
    config["rules"] = [trace(r) for r in config["rules"]]
    with tempfile.TemporaryDirectory(dir=ROOT / "raw") as directory:
        path = Path(directory)
        cfg = path / "config.yaml"
        cfg.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
        proc = subprocess.Popen([mihomo, "-d", str(ROOT), "-f", str(cfg)], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        logs = collections.deque(maxlen=40)
        reader = threading.Thread(target=lambda: [logs.append(line.strip()) for line in proc.stdout], daemon=True)
        reader.start()
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            api = "http://127.0.0.1:" + str(api_port) + "/connections"
            for _ in range(100):
                if proc.poll() is not None: raise AssertionError("\n".join(logs))
                try:
                    opener.open(api, timeout=.2).close()
                    break
                except OSError: time.sleep(.1)
            else: raise AssertionError("Core did not start")
            # File providers initialize asynchronously after the controller opens.
            names = set(config.get("rule-providers", {}))
            for _ in range(200):
                loaded = json.load(opener.open(api.replace("/connections", "/providers/rules"), timeout=1))["providers"]
                if all(loaded.get(n, {}).get("ruleCount", 0) > 0 for n in names):
                    break
                time.sleep(.05)
            else:
                raise AssertionError("Rule providers did not finish initialization")
            for host, chain, payload in cases:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as conn:
                    conn.sendall(("GET http://" + host + "/ HTTP/1.1\r\nHost: " + host +
                                  "\r\nConnection: close\r\n\r\n").encode())
                    match = None
                    for _ in range(500):
                        current = json.load(opener.open(api, timeout=1))["connections"] or []
                        match = next((c for c in current if c["metadata"].get("host") == host), None)
                        if match: break
                        time.sleep(.02)
                    if not match:
                        raise AssertionError("No core connection for " + host + "\n" + "\n".join(logs))
                    if chain not in match["chains"]:
                        raise AssertionError((host, chain, match))
                    actual = str(match.get("rulePayload", ""))
                    if payload is not None and payload not in actual:
                        raise AssertionError((host, payload, match))
                    print(json.dumps({"host": host, "rule": match["rule"], "payload": actual,
                                      "chains": match["chains"]}, ensure_ascii=True))
                    conn.recv(4096)
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
            proc.stdout.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mihomo", default="mihomo")
    args = p.parse_args()
    mock = ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    threading.Thread(target=mock.serve_forever, daemon=True).start()
    def config():
        return {"mode": "rule", "proxies": [
            {"name": name, "type": "http", "server": "127.0.0.1", "port": mock.server_port}
            for name in ("TRACE_DIRECT", "TRACE_REJECT", "TRACE_PROXY")],
            "proxy-groups": [{"name": "节点选择", "type": "select", "proxies": ["TRACE_PROXY"]}]}
    try:
        m, inline = read_json(ROOT / "out/build-manifest.json"), read_json(ROOT / "out/inline-rules.json")
        full = assemble(config(), m, inline, local_dir=ROOT / "out")
        exercise(args.mihomo, full, [
            ("binance.com", "TRACE_DIRECT", "personal-direct-domain"),
            ("api.bybit-global.com", "TRACE_DIRECT", "personal-direct-domain"),
            ("dl.google.com", "TRACE_DIRECT", "acl-unban-domain"),
            ("google.com", "TRACE_PROXY", "google"),
            ("netflix.com", "TRACE_PROXY", "services-proxy"),
            ("github.com", "TRACE_PROXY", "services-proxy"),
            ("chatgpt.com", "TRACE_PROXY", "services-proxy"),
            ("youtube.com", "TRACE_PROXY", None),
            ("doubleclick.net", "TRACE_REJECT", "reject"),
            ("miwifi.com", "TRACE_DIRECT", "private"),
        ])
        # Isolate regexes otherwise shadowed by equivalent domain suffixes.
        regex = config()
        regex["rules"] = [r + ",节点选择" for r in inline["sections"]["services"] if r.startswith("DOMAIN-REGEX,")]
        regex["rules"] += [r + ",DIRECT" for r in inline["sections"]["private"] if r.startswith("DOMAIN-REGEX,")]
        regex["rules"].append("MATCH,DIRECT")
        exercise(args.mihomo, regex, [
            ("apiproxy-device-prod-nlb-test.amazonaws.com", "TRACE_PROXY", "apiproxy"),
            ("chatgpt-async-webps-prod-test-123.webpubsub.azure.com", "TRACE_PROXY", "chatgpt"),
            ("r1---sn-2x3abcde.googlevideo.com", "TRACE_PROXY", "googlevideo"),
            ("ordinary.amazonaws.com", "TRACE_DIRECT", ""),
            ("ordinary.webpubsub.azure.com", "TRACE_DIRECT", ""),
            ("ordinary.cloudflare.com", "TRACE_DIRECT", ""),
            ("routerlab", "TRACE_DIRECT", "^[a-z]"),
        ])
        exact_file = ROOT / "raw/exact-test.yaml"
        exact_file.write_text("payload:\n  - example.com\n  - '+.suffix-example.com'\n", encoding="utf-8")
        exact_mrs = ROOT / "raw/exact-test.mrs"
        subprocess.run([args.mihomo, "convert-ruleset", "domain", "yaml", str(exact_file), str(exact_mrs)], check=True)
        exact = config()
        exact["rule-providers"] = {"exact": {"type": "file", "behavior": "domain", "format": "mrs", "path": str(exact_mrs)}}
        exact["rules"] = ["RULE-SET,exact,节点选择", "MATCH,DIRECT"]
        exercise(args.mihomo, exact, [
            ("example.com", "TRACE_PROXY", "exact"), ("sub.example.com", "TRACE_DIRECT", ""),
            ("suffix-example.com", "TRACE_PROXY", "exact"), ("sub.suffix-example.com", "TRACE_PROXY", "exact"),
            ("similar-example.com", "TRACE_DIRECT", ""),
        ])
        print("PASS: 22 actual-core routing checks (traced to loopback; no public traffic)")
    finally:
        mock.shutdown()
        mock.server_close()

if __name__ == "__main__":
    main()
