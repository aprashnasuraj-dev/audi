from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit


class MockHandler(BaseHTTPRequestHandler):
    server_version = "HALOMock/1.1"

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

    def _html(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        ident = self._identity()
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            port = int(self.server.server_address[1])
            flow_script = ""
            if query.get("flow") == ["1"] and ident != "anonymous":
                flow_script = (
                    "setTimeout(() => { window.location = 'http://localhost:%d/flow'; }, 40);" % port
                )
            body = f"""<!doctype html><html><body>
            <h1>HALO Mock SPA</h1><a href='/app'>Open app</a>
            <script>
              fetch('/api/me').catch(()=>{{}});
              fetch('/api/admin/secret').catch(()=>{{}});
              {flow_script}
            </script></body></html>""".encode("utf-8")
            self._html(body)
            return

        if path == "/flow":
            body = b"""<html><body><div id='flow'>authenticated sibling-host flow</div>
            <script>
              fetch('/api/account/42').catch(()=>{});
              fetch('http://blocked.invalid/trap').catch(()=>{});
            </script></body></html>"""
            self._html(body)
            return

        if path == "/app":
            body = b"<html><body><div id='spa'>account manager</div><script>fetch('/api/account/42')</script></body></html>"
            self._html(body)
            return

        if path == "/api/me":
            if ident == "anonymous":
                self._json(401, {"error": "login required"})
            else:
                self._json(200, {"user": ident, "account_id": 42})
            return
        if path == "/api/account/42":
            if ident == "anonymous":
                self._json(401, {"error": "login required"})
            else:
                self._json(200, {"account_id": 42, "email": "owner@example.test", "balance": 9001})
            return
        if path == "/api/admin/secret":
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
