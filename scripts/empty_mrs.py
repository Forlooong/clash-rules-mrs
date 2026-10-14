#!/usr/bin/env python3
"""Encode and verify a true empty domain set for Mihomo 1.19.32.

Upstream's reader requires at least one edge label, while its converter refuses
count zero before either encoding or dumping. A two-node trie with no terminal
bits and no wildcard edge represents the empty language: the NUL edge below is
structural, not a stored/matching placeholder domain. Even an input containing
NUL cannot reach a terminal. All real domain strings are rejected at the root.

Sources (pinned tag): MetaCubeX/mihomo/v1.19.32
  rules/provider/{mrs_reader,mrs_converter,domain_strategy}.go
  component/trie/{domain_set_bin,domain_set}.go

Classical KEYWORD/REGEX predicates are separate data; this module never deletes
or translates them. Do not pretend that the stock count-zero converter can
round-trip this artifact: full provider loading is the compatibility check.
"""
import argparse
import collections
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request

import yaml
import zstandard


# MRSv1, domain behavior, count=0, reserved length=0, DomainSet version=1.
# LOUDS [0,1,1] is a root with one child and that child's end marker. Neither
# node is terminal (leaves=0); the one NUL label is not '+' or '*'.
EMPTY_DOMAIN_RAW = (b"MRS\x01\x00" + struct.pack(">qqBqQqQq", 0, 0, 1, 1, 0, 1, 6, 1) + b"\x00")
SAMPLE_DOMAINS = ("a", "aa", "example.com", "sub.example.com", "localhost",
                  "binance.com", "bybit.com", "whatsapp.net", "keyword-whatsapp.example",
                  "xn--fiqs8s.example", "EXAMPLE.COM", "a.b.c.invalid")


def encode_empty_mrs(behavior="domain"):
    """Return an MRS carrying zero domain rules, without adding any domain."""
    if behavior != "domain":
        raise ValueError("Only the verified empty domain MRS encoding is supported")
    return zstandard.ZstdCompressor(level=3, write_checksum=True).compress(EMPTY_DOMAIN_RAW)


def _structural_check(data):
    if not isinstance(data, bytes) or not data or len(data) > 4096:
        raise ValueError("Expected a bounded, nonempty encoded domain MRS")
    try:
        if zstandard.get_frame_parameters(data).content_size != len(EMPTY_DOMAIN_RAW):
            raise ValueError("Invalid empty MRS uncompressed length")
        raw = zstandard.ZstdDecompressor().decompress(data, max_output_size=len(EMPTY_DOMAIN_RAW),
                                                     allow_extra_data=False)
    except zstandard.ZstdError as exc:
        raise ValueError("Invalid empty MRS compression") from exc
    if raw != EMPTY_DOMAIN_RAW:
        raise ValueError("Not the verified zero-terminal, zero-rule domain trie")
    return {"behavior": "domain", "count": 0, "domains": [], "terminal_bits": 0,
            "fingerprint": hashlib.sha256(b"").hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _Fallback(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.send_header("X-Empty-MRS-Fallback", "yes")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_CONNECT(self):
        self.send_response(200, "Connection established")
        self.end_headers()
        self.close_connection = False


def verify_empty_mrs(data, mihomo=None):
    """Verify structure; optionally load and exercise the pinned real core.

    Runtime verification uses only loopback mock HTTP traffic. It changes no
    existing client, OS proxy, DNS, TUN, VPS or external service configuration.
    """
    result = _structural_check(data)
    if mihomo is None:
        return result
    path = Path(mihomo)
    mihomo = str(path.resolve()) if path.exists() else shutil.which(str(mihomo)) or str(mihomo)
    version = subprocess.check_output([mihomo, "-v"], text=True, timeout=10).strip()
    if not re.search(r"\bv1\.19\.32\b", version):
        raise ValueError("Empty MRS runtime verification requires pinned Mihomo v1.19.32")
    result["core_version"] = version.splitlines()[0]
    api_port, mixed_port = _free_port(), _free_port()
    while mixed_port == api_port:
        mixed_port = _free_port()
    fallback = ThreadingHTTPServer(("127.0.0.1", 0), _Fallback)
    fallback.daemon_threads = True
    worker = threading.Thread(target=fallback.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="empty-mrs-core-") as folder:
            directory = Path(folder)
            source = directory / "empty.mrs"
            source.write_bytes(data)
            converted = subprocess.run([mihomo, "convert-ruleset", "domain", "mrs", str(source),
                                        str(directory / "dump.txt")], capture_output=True, timeout=10)
            if converted.returncode == 0 or b"empty rule" not in converted.stdout + converted.stderr:
                raise ValueError("Unexpected stock-core count-zero converter behavior")
            result["converter"] = "stock converter rejects count zero before dumping"
            config = {
                "mixed-port": mixed_port, "external-controller": "127.0.0.1:" + str(api_port),
                "allow-lan": False, "bind-address": "127.0.0.1", "secret": "", "mode": "rule",
                "log-level": "info", "find-process-mode": "off", "ipv6": False,
                "dns": {"enable": False}, "tun": {"enable": False},
                "hosts": {domain: "192.0.2.1" for domain in SAMPLE_DOMAINS},
                "proxies": [{"name": "EMPTY-TEST-FALLBACK", "type": "http", "server": "127.0.0.1",
                             "port": fallback.server_port}],
                "rule-providers": {"empty": {"type": "file", "behavior": "domain", "format": "mrs", "path": str(source)}},
                "rules": ["RULE-SET,empty,REJECT", "MATCH,EMPTY-TEST-FALLBACK"],
            }
            config_path = directory / "config.yaml"
            config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
            environment = dict(os.environ, SAFE_PATHS=str(directory), SKIP_SAFE_PATH_CHECK="false")
            checked = subprocess.run([mihomo, "-t", "-d", str(directory), "-f", str(config_path)],
                                     capture_output=True, timeout=15, env=environment)
            if checked.returncode:
                raise ValueError("Pinned core rejected empty-provider configuration")
            proc = subprocess.Popen([mihomo, "-d", str(directory), "-f", str(config_path)], stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", env=environment)
            logs = collections.deque(maxlen=40)
            reader = threading.Thread(target=lambda: [logs.append(line.strip()) for line in proc.stdout], daemon=True)
            reader.start()
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            api = "http://127.0.0.1:" + str(api_port)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        raise ValueError("Pinned core exited during empty-provider loading")
                    try:
                        with opener.open(api + "/providers/rules", timeout=.3) as response:
                            provider = json.load(response)["providers"]["empty"]
                        # A zero count alone cannot distinguish an uninitialized
                        # provider. A forced local-file reload must return 204.
                        request = urllib.request.Request(api + "/providers/rules/empty", method="PUT")
                        with opener.open(request, timeout=2) as response:
                            if response.status != 204:
                                raise ValueError("Empty provider did not complete its update")
                        break
                    except (OSError, KeyError):
                        time.sleep(.05)
                else:
                    raise ValueError("Empty provider could not be loaded: " + "\n".join(logs))
                with opener.open(api + "/providers/rules", timeout=2) as response:
                    provider = json.load(response)["providers"]["empty"]
                if provider.get("ruleCount") != 0 or provider.get("behavior", "").lower() != "domain":
                    raise ValueError("Loaded provider does not expose the expected empty domain set")
                for domain in SAMPLE_DOMAINS:
                    with socket.create_connection(("127.0.0.1", mixed_port), timeout=3) as connection:
                        connection.settimeout(3)
                        connection.sendall(("GET http://" + domain + "/ HTTP/1.1\r\nHost: " + domain +
                                            "\r\nConnection: close\r\n\r\n").encode("ascii"))
                        body = bytearray()
                        while b"\r\n\r\n" not in body:
                            try:
                                chunk = connection.recv(4096)
                            except TimeoutError as exc:
                                raise ValueError("Loopback routing timed out for " + domain + ": " + "\n".join(logs)) from exc
                            if not chunk:
                                break
                            body.extend(chunk)
                        if not bytes(body).startswith(b"HTTP/1.1 200") or b"x-empty-mrs-fallback: yes" not in bytes(body).lower():
                            raise ValueError("Empty set unexpectedly intercepted " + domain)
                result.update(provider_loaded=True, rule_count=provider["ruleCount"],
                              nonmatching_cases=len(SAMPLE_DOMAINS), runtime_match=False)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                reader.join(timeout=2)
                proc.stdout.close()
    finally:
        fallback.shutdown()
        fallback.server_close()
        worker.join(timeout=2)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write the encoded empty domain set")
    parser.add_argument("--mihomo", help="Verify loading and loopback matching with pinned v1.19.32")
    args = parser.parse_args()
    data = encode_empty_mrs()
    result = verify_empty_mrs(data, args.mihomo)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(data)
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
