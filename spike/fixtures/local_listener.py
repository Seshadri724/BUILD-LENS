#!/usr/bin/env python3
"""Stands in for the attacker's collection server in the M0.5 detection
proof (ROADMAP.md Phase 0). Binds to 127.0.0.1 only -- the whole point of
this fixture is that nothing ever leaves the CI runner. Logs whatever it
receives so the workflow log makes the "exfiltrated" payload visible
alongside the probe's own TAINTED_EGRESS record.
"""
import http.server
import socketserver
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        print(f"LISTENER RECEIVED: {body.decode(errors='replace')!r}", flush=True)
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # keep the workflow log to the one line above


if __name__ == "__main__":
    with socketserver.TCPServer(("127.0.0.1", 9999), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            sys.exit(0)
