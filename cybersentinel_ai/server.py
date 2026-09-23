"""Small local HTTP adapter for the CyberSentinel analysis engine."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .api import analyze_events_from_dicts


class AnalysisHandler(BaseHTTPRequestHandler):
    """Expose event analysis to the login frontend without extra dependencies."""

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "http://localhost:3000")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self._send_json(204, {})

    def do_POST(self) -> None:
        if self.path != "/api/analyze":
            self._send_json(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
            events = request.get("events") if isinstance(request, dict) else request
            if not isinstance(events, list):
                raise ValueError("Request must contain an events array")
            result = analyze_events_from_dicts(events)
            if os.getenv("DB_PERSIST", "false").lower() == "true":
                from .database import CyberSentinelRepository
                result["database"] = CyberSentinelRepository().persist_result(result)
            self._send_json(200, result)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception:
            self._send_json(500, {"error": "Analysis failed"})

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[CyberSentinel] {format % args}")


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8090), AnalysisHandler)
    print("CyberSentinel analysis API listening on http://127.0.0.1:8090")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()