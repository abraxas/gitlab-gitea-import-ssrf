#!/usr/bin/env python3
"""TTL-0 DNS rebind for gitea.lab. Other names are forwarded."""


import json
import os
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GITEA_NAME = os.environ.get("GITEA_NAME", "gitea.lab").strip(".").lower()
PUBLIC_A = os.environ.get("PUBLIC_A", "1.1.1.1")
LOOPBACK_A = os.environ.get("LOOPBACK_A", "127.0.0.1")
FORWARD_DNS = os.environ.get("FORWARD_DNS", "1.1.1.1")
DNS_BIND = os.environ.get("DNS_BIND", "0.0.0.0")
DNS_PORT = int(os.environ.get("DNS_PORT", "53"))
CONTROL_BIND = os.environ.get("CONTROL_BIND", "0.0.0.0")
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "8080"))
READY_PATH = "/tmp/dns-ready"

QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_NS = 2
QCLASS_IN = 1

_lock = threading.Lock()
_state = {
    "mode": os.environ.get("REBIND_MODE", "pairs"),
    "a_lookups": 0,
    "events": [],
}


def log(msg: str) -> None:
    print(msg, flush=True)


def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def parse_name(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    seen = 0
    while True:
        if offset >= len(buf):
            raise ValueError("name overflow")
        length = buf[offset]
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise ValueError("pointer overflow")
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            seen += 1
            if seen > 16:
                raise ValueError("pointer loop")
            continue
        offset += 1
        labels.append(buf[offset : offset + length].decode("ascii", "replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels).lower().rstrip("."), end


def encode_name(name: str) -> bytes:
    out = b""
    if name:
        for label in name.split("."):
            raw = label.encode("ascii")
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def is_gitea(name: str) -> bool:
    n = name.lower().rstrip(".")
    return n == GITEA_NAME or n.startswith(GITEA_NAME + ".")


def pick_a() -> str:
    mode = _state["mode"]
    n = _state["a_lookups"]
    if mode == "public":
        return PUBLIC_A
    if mode == "loopback":
        return LOOPBACK_A
    if mode == "pairs":
        if n <= 2:
            return PUBLIC_A
        return LOOPBACK_A if (n % 2 == 1) else PUBLIC_A
    if n <= 2:
        return PUBLIC_A
    return LOOPBACK_A


def record_a(name: str) -> str:
    with _lock:
        _state["a_lookups"] += 1
        ip = pick_a()
        event = {
            "n": _state["a_lookups"],
            "name": name,
            "ip": ip,
            "mode": _state["mode"],
            "ts": time.time(),
        }
        _state["events"].append(event)
        if len(_state["events"]) > 200:
            _state["events"] = _state["events"][-200:]
    log(f"dns-a n={event['n']} name={name} ip={ip} mode={event['mode']}")
    return ip


def answer_a(qid: int, qname: str, ip: str) -> bytes:
    flags = 0x8400
    header = struct.pack("!HHHHHH", qid, flags, 1, 1, 0, 0)
    question = encode_name(qname) + struct.pack("!HH", QTYPE_A, QCLASS_IN)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_A, QCLASS_IN, 0, 4) + ip_to_bytes(ip)
    return header + question + rr


def answer_empty(qid: int, qname: str, qtype: int, rcode: int = 0) -> bytes:
    flags = 0x8400 | (rcode & 0xF)
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    question = encode_name(qname) + struct.pack("!HH", qtype, QCLASS_IN)
    return header + question


def forward(query: bytes) -> bytes | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.sendto(query, (FORWARD_DNS, 53))
        data, _ = sock.recvfrom(4096)
        return data
    except OSError as exc:
        log(f"dns-forward-fail {exc}")
        return None
    finally:
        sock.close()


def handle_query(data: bytes) -> bytes | None:
    if len(data) < 12:
        return None
    qid, flags, qdcount, *_rest = struct.unpack("!HHHHHH", data[:12])
    if qdcount < 1:
        return None
    try:
        qname, offset = parse_name(data, 12)
        if offset + 4 > len(data):
            return None
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    except ValueError as exc:
        log(f"dns-parse-fail {exc}")
        return None

    if qclass != QCLASS_IN:
        return forward(data)

    if is_gitea(qname):
        if qtype == QTYPE_A:
            ip = record_a(qname)
            return answer_a(qid, qname, ip)
        if qtype == QTYPE_AAAA:
            log(f"dns-aaaa name={qname} nodata")
            return answer_empty(qid, qname, qtype, rcode=0)
        log(f"dns-other-type name={qname} qtype={qtype} nodata")
        return answer_empty(qid, qname, qtype, rcode=0)

    forwarded = forward(data)
    if forwarded:
        return forwarded
    return struct.pack("!HHHHHH", qid, 0x8002, qdcount, 0, 0, 0) + data[12:]


def dns_loop() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((DNS_BIND, DNS_PORT))
    log(f"dns-listen {DNS_BIND}:{DNS_PORT} gitea={GITEA_NAME} mode={_state['mode']}")
    with open(READY_PATH, "w", encoding="utf-8") as fh:
        fh.write("ready\n")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError as exc:
            log(f"dns-recv-fail {exc}")
            time.sleep(0.2)
            continue
        try:
            resp = handle_query(data)
            if resp:
                sock.sendto(resp, addr)
        except Exception as exc:  # noqa: BLE001 — keep DNS up
            log(f"dns-handle-fail {type(exc).__name__}: {exc}")


class ControlHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.startswith("/stats"):
            with _lock:
                payload = {
                    "mode": _state["mode"],
                    "a_lookups": _state["a_lookups"],
                    "events": list(_state["events"][-40:]),
                }
            self._send(200, payload)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/")
        if path == "/reset":
            with _lock:
                _state["a_lookups"] = 0
                _state["events"].append({"n": 0, "name": "reset", "ip": "", "mode": _state["mode"], "ts": time.time()})
            log("dns-reset")
            self._send(200, {"ok": True, "mode": _state["mode"], "a_lookups": 0})
            return
        if path.startswith("/mode/"):
            mode = path.split("/mode/", 1)[1].strip()
            if mode not in ("first2_then_loopback", "pairs", "public", "loopback"):
                self._send(400, {"error": "bad mode"})
                return
            with _lock:
                _state["mode"] = mode
                _state["a_lookups"] = 0
            log(f"dns-mode {mode}")
            self._send(200, {"ok": True, "mode": mode, "a_lookups": 0})
            return
        self._send(404, {"error": "not found"})

    def log_message(self, fmt: str, *args: object) -> None:
        log("dns-control " + (fmt % args))


def control_loop() -> None:
    httpd = ThreadingHTTPServer((CONTROL_BIND, CONTROL_PORT), ControlHandler)
    log(f"dns-control {CONTROL_BIND}:{CONTROL_PORT}")
    httpd.serve_forever()


def main() -> int:
    threading.Thread(target=control_loop, daemon=True).start()
    dns_loop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
