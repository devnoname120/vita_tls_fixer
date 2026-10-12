#!/usr/bin/env python3
"""Local diagnostic endpoint. Supply a certificate trusted by the Vita."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
from pathlib import Path
import secrets
import ssl
import re
from urllib.parse import parse_qsl, urlsplit


def probe_nonce(path: str) -> str | None:
    if len(path) > 1024:
        raise ValueError("request target too long")
    values = [value for key, value in parse_qsl(urlsplit(path).query, keep_blank_values=True,
                                               max_num_fields=32) if key == "tls_fixer_probe"]
    if not values:
        return None
    if len(values) != 1 or re.fullmatch(r"[0-9a-f]{32}", values[0]) is None:
        raise ValueError("invalid probe nonce")
    return values[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--tls", choices=("1.2", "1.3"), default="1.3")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    version = ssl.TLSVersion.TLSv1_3 if args.tls == "1.3" else ssl.TLSVersion.TLSv1_2
    context.minimum_version = context.maximum_version = version
    context.load_cert_chain(args.cert, args.key)
    context.set_alpn_protocols(["http/1.1"])
    run_id = secrets.token_hex(8)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            self.request.settimeout(10)
            super().setup()

        def do_GET(self) -> None:
            try:
                nonce = probe_nonce(self.path)
            except ValueError:
                self.send_error(400, "Invalid probe request")
                self.close_connection = True
                return
            record = {
                "run": run_id,
                "response": secrets.token_hex(8),
                "utc": datetime.now(timezone.utc).isoformat(),
                "tls": self.connection.version(),
                "cipher": self.connection.cipher()[0],
                "alpn": self.connection.selected_alpn_protocol(),
            }
            if nonce is not None:
                record["probe_nonce"] = nonce
            encoded = json.dumps(record, indent=2)
            payload = ("<!doctype html><meta charset=utf-8><title>tls_fixer browser test</title>"
                       "<h1>tls_fixer browser test</h1><pre>" + html.escape(encoded) + "</pre>").encode()
            print(encoded, flush=True)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            if nonce is not None:
                self.send_header("X-TLS-Fixer-Probe-Nonce", nonce)
            self.end_headers()
            self.wfile.write(payload)
            self.close_connection = True

        def log_message(self, format: str, *values: object) -> None:
            pass

    with ThreadingHTTPServer((args.bind, args.port), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print(f"tls_fixer diagnostic run={run_id} TLS={args.tls} port={args.port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
