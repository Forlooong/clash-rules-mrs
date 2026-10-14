#!/usr/bin/env python3
"""Mihomo 1.19.32 DNS checks using only loopback DNS, SOCKS and HTTP servers.

The generated resolver roles are substituted with labelled local TCP DNS
servers; #DIRECT / #节点选择 and policy ordering remain unchanged. No public
resolver, account, VPS, OS proxy or TUN is touched.
"""
import argparse
import collections
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import select
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from runtime.dns import assemble_dns, DOMESTIC, REMOTE


def recv_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("Unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            while True:
                packet = recv_exact(self.request, struct.unpack("!H", recv_exact(self.request, 2))[0])
                pos, labels = 12, []
                while packet[pos]:
                    length = packet[pos]
                    labels.append(packet[pos + 1:pos + length + 1].decode("ascii"))
                    pos += length + 1
                name = ".".join(labels).lower()
                end = pos + 5
                qtype = struct.unpack("!H", packet[pos + 1:pos + 3])[0]
                self.server.events.append((self.server.label, name, qtype))
                failed = self.server.label == "remote" and self.server.failure.is_set()
                answer = b""
                if qtype == 1 and not failed:
                    ip = "192.0.2.10" if name.startswith("foreign") else "127.0.0.1"
                    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(ip)
                flags = 0x8182 if failed else 0x8180
                response = packet[:2] + struct.pack("!HHHHH", flags, 1, int(bool(answer)), 0, 0) + packet[12:end] + answer
                self.request.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, IndexError, UnicodeError):
            pass


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(5)
        try:
            if self.server.offline.is_set():
                return
            with self.server.active_lock:
                self.server.active.add(sock)
            version, methods = recv_exact(sock, 2)
            if version != 5:
                return
            recv_exact(sock, methods)
            sock.sendall(b"\x05\x00")
            version, command, _, kind = recv_exact(sock, 4)
            if version != 5 or command != 1:
                return
            if kind == 1:
                host = socket.inet_ntoa(recv_exact(sock, 4))
            elif kind == 3:
                host = recv_exact(sock, recv_exact(sock, 1)[0]).decode("ascii")
            else:
                return
            port = struct.unpack("!H", recv_exact(sock, 2))[0]
            self.server.events.append((host, port))
            # Even if a fixture regresses, the mock cannot connect to the public
            # Internet: only its explicitly registered loopback ports are allowed.
            if port not in self.server.allowed_ports:
                sock.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            with socket.create_connection(("127.0.0.1", port), timeout=3) as other:
                sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                while True:
                    ready, _, _ = select.select([sock, other], [], [], 3)
                    if not ready:
                        return
                    for incoming in ready:
                        data = incoming.recv(65536)
                        if not data:
                            return
                        (other if incoming is sock else sock).sendall(data)
        except (OSError, ValueError):
            pass
        finally:
            with self.server.active_lock:
                self.server.active.discard(sock)


class HTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "8")
        self.end_headers()
        self.wfile.write(b"LOOPBACK")


def query(port, host):
    wire = b"".join(bytes([len(part)]) + part.encode("ascii") for part in host.split(".")) + b"\0"
    packet = struct.pack("!HHHHHH", 1234, 0x100, 1, 0, 0, 0) + wire + struct.pack("!HH", 1, 1)
    with socket.create_connection(("127.0.0.1", port), timeout=15) as sock:
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        result = recv_exact(sock, struct.unpack("!H", recv_exact(sock, 2))[0])
    return result[3] & 15


def fixture():
    payloads = {"private-domain": ["+.private.test", "+.lan"],
                "services-proxy": ["api.overlap.test"], "cn-domain": ["+.overlap.test", "+.cn.test"],
                "personal-direct-domain": ["wallet.private.test"],
                "personal-proxy-domain": ["proxy.lan"]}
    document = {"dns": {"enhanced-mode": "redir-host", "ipv6": False},
                "rule-providers": {name: {"type": "inline", "behavior": "domain", "payload": values}
                                   for name, values in payloads.items()},
                "tun": {"enable": False}, "ipv6": False}
    document["rule-providers"]["cn-ipcidr"] = {"type": "inline", "behavior": "ipcidr", "payload": ["127.0.0.0/8"]}
    manifest = {"schema_version": 2, "policy_version": "balanced-v2"}
    inline = {"schema_version": 2, "sections": {
        "personal_direct": [], "personal_proxy": [r"DOMAIN-REGEX,^api[0-9]+\.overlap\.test$"],
        "private": [], "services": [], "direct": [r"DOMAIN-REGEX,^cn[0-9]+\.other\.test$"]},
        "domain_index": payloads}
    document = assemble_dns(document, manifest, inline)
    # Exercise the persistent-state key-sorting hazard before running the core.
    return assemble_dns(json.loads(json.dumps(document, sort_keys=True)), manifest, inline)


def run(mihomo):
    version = subprocess.check_output([mihomo, "-v"], text=True, encoding="utf-8")
    if "v1.19.32 " not in version:
        raise AssertionError("DNS integration checks require pinned Mihomo v1.19.32")
    dns_events, socks_events, servers = [], [], []
    failure = threading.Event()
    try:
        dns_servers = {}
        for label in ("bootstrap", "domestic", "remote", "private"):
            server = TCPServer(("127.0.0.1", 0), DNSHandler)
            server.label, server.events, server.failure = label, dns_events, failure
            dns_servers[label] = server
            servers.append(server)
        http = ThreadingHTTPServer(("127.0.0.1", 0), HTTPHandler)
        socks = TCPServer(("127.0.0.1", 0), SocksHandler)
        socks.events = socks_events
        socks.offline, socks.active, socks.active_lock = threading.Event(), set(), threading.Lock()
        socks.allowed_ports = {dns_servers["remote"].server_address[1], http.server_port}
        servers += [http, socks]
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()

        config = fixture()
        replacements = {**{v: "tcp://127.0.0.1:%d#节点选择" % dns_servers["remote"].server_address[1] for v in REMOTE},
                        **{v: "tcp://127.0.0.1:%d#DIRECT" % dns_servers["domestic"].server_address[1] for v in DOMESTIC},
                        "system": "tcp://127.0.0.1:%d#DIRECT" % dns_servers["private"].server_address[1]}

        def localize(value):
            if isinstance(value, str):
                return replacements.get(value, value)
            if isinstance(value, list):
                return list(dict.fromkeys(localize(v) for v in value))
            if isinstance(value, dict):
                return {k: localize(v) for k, v in value.items()}
            return value

        config["dns"] = localize(config["dns"])
        bootstrap = ["tcp://127.0.0.1:%d#DIRECT" % dns_servers["bootstrap"].server_address[1]]
        config["dns"]["default-nameserver"] = bootstrap
        config["dns"]["proxy-server-nameserver"] = bootstrap
        mixed_port, dns_port, api_port = free_port(), free_port(), free_port()
        config["dns"]["listen"] = "127.0.0.1:" + str(dns_port)
        config.update({"mixed-port": mixed_port, "external-controller": "127.0.0.1:" + str(api_port),
                       "bind-address": "127.0.0.1", "allow-lan": False, "find-process-mode": "off",
                       "log-level": "warning", "mode": "rule", "proxies": [
                           {"name": "MOCK", "type": "socks5", "server": "node-bootstrap.test", "port": socks.server_address[1]}],
                       "proxy-groups": [{"name": "节点选择", "type": "select", "proxies": ["MOCK"]}],
                       "rules": ["RULE-SET,personal-direct-domain,DIRECT", "RULE-SET,personal-proxy-domain,节点选择",
                                 "RULE-SET,dns-only-personal,节点选择", "RULE-SET,private-domain,DIRECT",
                                 "RULE-SET,services-proxy,节点选择", "RULE-SET,cn-domain,DIRECT",
                                 "RULE-SET,dns-only-direct,DIRECT", "RULE-SET,cn-ipcidr,DIRECT", "MATCH,节点选择"]})
        with tempfile.TemporaryDirectory(prefix="mrs-dns-core-") as temporary:
            directory = Path(temporary)
            path = directory / "config.yaml"
            path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
            checked = subprocess.run([mihomo, "-t", "-d", str(directory), "-f", str(path)], capture_output=True, timeout=15)
            if checked.returncode:
                raise AssertionError(checked.stdout.decode("utf-8", errors="replace") + checked.stderr.decode("utf-8", errors="replace"))
            process = subprocess.Popen([mihomo, "-d", str(directory), "-f", str(path)], stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
            logs = collections.deque(maxlen=40)
            threading.Thread(target=lambda: [logs.append(line.strip()) for line in process.stdout], daemon=True).start()
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                for _ in range(100):
                    try:
                        with opener.open("http://127.0.0.1:%d/proxies" % api_port, timeout=.2) as response:
                            if "MOCK" in json.load(response)["proxies"]:
                                break
                    except OSError:
                        pass
                    if process.poll() is not None:
                        raise AssertionError("Core stopped: " + "\n".join(logs))
                    time.sleep(.05)
                else:
                    raise AssertionError("Core startup timed out: " + "\n".join(logs))
                cases = [("cold-unknown.test", "remote"), ("ordinary.overlap.test", "domestic"),
                         ("api.overlap.test", "remote"), ("wallet.private.test", "remote"),
                         ("proxy.lan", "remote"), ("api123.overlap.test", "remote"),
                         ("cn123.other.test", "domestic"), ("router.private.test", "private")]
                for host, expected in cases:
                    before = len(dns_events)
                    if query(dns_port, host):
                        raise AssertionError("DNS lookup failed: " + host + "\n" + "\n".join(logs))
                    actual = {label for label, name, _ in dns_events[before:] if name == host}
                    if actual != {expected}:
                        raise AssertionError((host, expected, actual))
                if not any(label == "bootstrap" and name == "node-bootstrap.test" for label, name, _ in dns_events):
                    raise AssertionError("Cold startup did not use independent bootstrap DNS")

                # Unknown CN destination: active IP matching resolves through the
                # remote role, then connects directly to the loopback HTTP target.
                for host, uses_proxy in (("unknown-cn.test", False), ("foreign-unknown.test", True)):
                    before_dns, before_socks = len(dns_events), len(socks_events)
                    with socket.create_connection(("127.0.0.1", mixed_port), timeout=10) as conn:
                        request = "GET http://%s:%d/ HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n" % (host, http.server_port, host, http.server_port)
                        conn.sendall(request.encode())
                        response = b""
                        while True:
                            block = conn.recv(4096)
                            if not block:
                                break
                            response += block
                    if b"LOOPBACK" not in response:
                        raise AssertionError((host, response, list(logs)))
                    observed = any(port == http.server_port for _, port in socks_events[before_socks:])
                    if observed != uses_proxy:
                        raise AssertionError((host, "unexpected business route", observed))
                    if {label for label, name, _ in dns_events[before_dns:] if name == host} != {"remote"}:
                        raise AssertionError((host, "IP fallback used wrong DNS role"))

                failure.set()
                before = len(dns_events)
                if query(dns_port, "cold-failure.test") == 0:
                    raise AssertionError("Failed remote DNS unexpectedly resolved")
                labels = {label for label, name, _ in dns_events[before:] if name == "cold-failure.test"}
                if labels != {"remote"}:
                    raise AssertionError(("Remote outage fell back to a local resolver", labels))
                # Also sever the transport, including pooled DNS connections,
                # rather than treating a remote SERVFAIL as a proxy outage.
                socks.offline.set()
                with socks.active_lock:
                    for active in list(socks.active):
                        try:
                            active.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                before = len(dns_events)
                if query(dns_port, "proxy-offline.test") == 0:
                    raise AssertionError("Offline proxy unexpectedly resolved")
                labels = {label for label, name, _ in dns_events[before:] if name == "proxy-offline.test"}
                if labels - {"remote"}:
                    raise AssertionError(("Offline proxy used a direct DNS resolver", labels))
                print("PASS: 13 pinned-core DNS/routing checks; all destinations restricted to loopback")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                process.stdout.close()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mihomo", default="mihomo")
    args = parser.parse_args()
    run(str(Path(args.mihomo).resolve()) if Path(args.mihomo).exists() else args.mihomo)


if __name__ == "__main__":
    main()
