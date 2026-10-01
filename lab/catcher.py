#!/usr/bin/env python3
"""HTTPS Gitea-shaped oracle on GitLab loopback."""


import json
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WITNESS = os.environ.get("WITNESS", "GITLAB-GITEA-IMPORT-SSRF-WITNESS")
TLS_CERT = os.environ.get("TLS_CERT", "/certs/gitea.crt")
TLS_KEY = os.environ.get("CATCHER_TLS_KEY") or os.environ.get("TLS_KEY", "/certs/gitea.key")
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "443"))
HTTPS_PORT_ALT = int(os.environ.get("HTTPS_PORT_ALT", "8443"))


def log(msg: str) -> None:
    print(msg, flush=True)


def json_bytes(payload: object, status: int = 200) -> tuple[int, bytes, str]:
    body = json.dumps(payload).encode("utf-8")
    return status, body, "application/json"


def gitea_payload(path: str) -> tuple[int, bytes, str]:
    user = {
        "id": 1,
        "login": "lab",
        "username": "lab",
        "email": "lab@localhost.invalid",
    }
    repo = {
        "id": 1,
        "name": WITNESS,
        "full_name": f"lab/{WITNESS}",
        "description": WITNESS,
        "clone_url": "https://gitea.lab/lab/witness.git",
        "html_url": "https://gitea.lab/lab/witness",
        "private": False,
        "owner": {"login": "lab"},
    }
    if path.endswith("/rate_limit") or path.endswith("/rate_limit/"):
        reset = 2147483647
        payload = {
            "resources": {
                "core": {"limit": 5000, "remaining": 4999, "reset": reset, "used": 1},
                "search": {"limit": 30, "remaining": 30, "reset": reset, "used": 0},
                "graphql": {"limit": 5000, "remaining": 5000, "reset": reset, "used": 0},
            },
            "rate": {"limit": 5000, "remaining": 4999, "reset": reset, "used": 1},
        }
        return json_bytes(payload)
    if path.rstrip("/").endswith("/user"):
        return json_bytes(user)
    if "/user/repos" in path or path.rstrip("/").endswith("/repos"):
        return json_bytes([repo])
    if path in ("/", "/health", "/healthz"):
        return 200, WITNESS.encode("utf-8"), "text/plain; charset=utf-8"
    return json_bytes([repo])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self) -> None:
        path = self.path.split("?", 1)[0]
        peer = self.client_address[0] if self.client_address else "?"
        host = self.headers.get("Host", "")
        status, body, ctype = gitea_payload(path)
        log(
            f"catcher {self.command} {path} peer={peer} host={host} "
            f"status={status} witness={WITNESS in body.decode('utf-8', 'replace')}"
        )
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.send_header("X-RateLimit-Limit", "5000")
        self.send_header("X-RateLimit-Remaining", "4999")
        self.send_header("X-RateLimit-Reset", "2147483647")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:
        self._reply()

    def do_HEAD(self) -> None:
        self._reply()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._reply()

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("catcher-http " + (fmt % args) + "\n")
        sys.stderr.flush()


def serve(port: int) -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(TLS_CERT, TLS_KEY)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    log(f"catcher-listen 127.0.0.1:{port} witness={WITNESS}")
    httpd.serve_forever()


def main() -> int:
    if not os.path.isfile(TLS_CERT) or not os.path.isfile(TLS_KEY):
        log("catcher-fatal missing TLS cert/key")
        return 1
    threads = [
        threading.Thread(target=serve, args=(HTTPS_PORT,), daemon=False),
        threading.Thread(target=serve, args=(HTTPS_PORT_ALT,), daemon=True),
    ]
    threads[0].start()
    threads[1].start()
    threads[0].join()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OSError as exc:
        log(f"catcher-fatal {exc}")
        raise SystemExit(1)
