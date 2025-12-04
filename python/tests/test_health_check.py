from __future__ import annotations

import http.server
import threading
from socketserver import TCPServer

from scripts.health_check import check


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args) -> None:  # silence default logging
        return


def test_health_check_success() -> None:
    with TCPServer(("localhost", 0), _Handler) as server:
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        result = check(f"http://localhost:{port}")
        server.shutdown()
        thread.join()
    assert result.ok is True
    assert result.status == 200
    assert result.error is None

