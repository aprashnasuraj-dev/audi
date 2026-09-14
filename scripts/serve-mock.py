#!/usr/bin/env python3
from http.server import ThreadingHTTPServer

from halo.mock_target import MockHandler


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8765), MockHandler)
    print("HALO mock target listening on http://127.0.0.1:8765/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
