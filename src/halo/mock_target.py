from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator


class MockHandler(BaseHTTPRequestHandler):
    server_version = "HALOMock/1.0"

    def log_message(self, format: str, *args) -> None:
        return

    def _identity(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth == "Bearer user-token":
            return "user"
        if auth == "Bearer admin-token":
            return "admin"
        return "anonymous"

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        ident = self._identity()
        if self.path == "/":
            body = b"""<!doctype html><html><body>
            <h1>HALO Mock SPA</h1><a href='/app'>Open app</a>
            <script>
              fetch('/api/me').catch(()=>{});
              fetch('/api/admin/secret').catch(()=>{});
            </script></body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return
        if self.path == "/app":
            body = b"<html><body><div id='spa'>account manager</div><script>fetch('/api/account/42')</script></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return
        if self.path == "/api/me":
            if ident == "anonymous":
                self._json(401, {"error": "login required"})
            else:
                self._json(200, {"user": ident, "account_id": 42})
            return
        if self.path == "/api/account/42":
            if ident == "anonymous":
                self._json(401, {"error": "login required"})
            else:
                self._json(200, {"account_id": 42, "email": "owner@example.test", "balance": 9001})
            return
        if self.path == "/api/admin/secret":
            if ident == "anonymous":
                self._json(401, {"error": "login required"})
            elif ident in {"user", "admin"}:
                self._json(200, {"secret": "synthetic-admin-only-value"})
            return
        self._json(404, {"error": "not found"})


@contextmanager
def mock_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
