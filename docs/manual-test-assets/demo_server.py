#!/usr/bin/env python3
"""Demo sign-in server for the credentials manual test (owner-run QA).

Serves this directory AND answers POSTs (python3 -m http.server 501s them,
which forces a scary "Error response" page mid-test; the save prompt itself
is unaffected). POST /signin returns a friendly 200 page. Nothing is
recorded, logged to disk, or sent anywhere — request logging stays on so
you can see the browser's traffic in the terminal.

Run from anywhere:  python3 demo_server.py  (port 8080)
"""
import os
import socket
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

DIR = os.path.dirname(os.path.abspath(__file__))


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIR, **kwargs)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)  # discard the form body; nothing is stored
        body = (
            b"<!DOCTYPE html><html><head><meta charset='utf-8'>"
            b"<title>Signed in (demo)</title></head><body>"
            b"<h1>Signed in (demo)</h1>"
            b"<p>Nothing was stored or sent &mdash; this is a local test stub.</p>"
            b"<p><a href='/login-form.html'>Back to the login form</a> to test the "
            b"autofill popup.</p></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DualStackServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6  # accept both ::1 and 127.0.0.1

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


if __name__ == "__main__":
    DualStackServer(("::", 8080), Handler).serve_forever()
