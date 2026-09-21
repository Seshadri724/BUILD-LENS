#!/usr/bin/env python3
"""
Simple HTTP listener on 127.0.0.1:8088 to serve as the destination for live integration tests.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(length)
        print(f"[listener] Received {len(body)} bytes from exfiltration target", flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK\n")

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK\n")

    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 8088), Handler)
    print("[listener] Listening on http://127.0.0.1:8088...", flush=True)
    server.serve_forever()
