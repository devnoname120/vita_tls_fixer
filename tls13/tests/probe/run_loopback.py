#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

SERVER_PATH = Path(__file__).resolve().parents[3] / "tools/tls13_test_server.py"
spec = importlib.util.spec_from_file_location("tls_fixer_probe_server", SERVER_PATH)
server_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server_module)


def certificate(root, name):
    cert, key = root / (name + ".pem"), root / (name + ".key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", str(key), "-out", str(cert)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


def run(binary, root, cert, key, other, protocol, scenario):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    selected = "1.2" if scenario == "wrong-version" and protocol == "1.3" else "1.3" if scenario == "wrong-version" else protocol
    context.minimum_version = context.maximum_version = (ssl.TLSVersion.TLSv1_3 if selected == "1.3" else ssl.TLSVersion.TLSv1_2)
    context.load_cert_chain(cert, key)
    if scenario == "ticket-limit":
        context.num_tickets = 20
    nonce = secrets.token_hex(16)
    observed, errors = [], []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        port = listener.getsockname()[1]

        def serve():
            try:
                raw, _ = listener.accept()
                raw.settimeout(5)
                with context.wrap_socket(raw, server_side=True) as peer:
                    request = bytearray()
                    while b"\r\n\r\n" not in request and len(request) < 1024:
                        chunk = peer.recv(128)
                        if not chunk:
                            return
                        request.extend(chunk)
                    path = bytes(request).split(b" ")[1].decode("ascii")
                    echoed = server_module.probe_nonce(path)
                    assert echoed == nonce
                    observed.append((peer.version(), echoed))
                    value = "0" * 32 if scenario == "bad-echo" else nonce
                    length = "99999999" if scenario == "oversize" else "3"
                    response = ("HTTP/1.1 200 OK\r\nContent-Length: " + length +
                                "\r\nX-TLS-Fixer-Probe-Nonce: " + value + "\r\n\r\n").encode()
                    if scenario != "eof":
                        response += b"abc"
                    for offset in range(0, len(response), 11):
                        peer.sendall(response[offset:offset + 11])
            except (ssl.SSLError, ConnectionError, BrokenPipeError, socket.timeout) as exc:
                if scenario in ("valid", "partial", "close-fail", "eof"):
                    errors.append(repr(exc))
            except Exception as exc:
                errors.append(repr(exc))

        worker = None
        if not scenario.startswith("clock-"):
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
        subprocess.run([str(binary), str(other if scenario == "untrusted" else cert), str(port),
                        protocol, scenario, nonce], check=True, timeout=20)
        if worker is not None:
            worker.join(7)
            assert not worker.is_alive() and not errors, (scenario, errors)
        if scenario in ("valid", "partial", "eof", "bad-echo", "oversize", "close-fail", "late-close"):
            assert observed == [("TLSv" + protocol, nonce)], observed


def main():
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        cert, key = certificate(root, "server")
        other, _ = certificate(root, "other")
        for protocol in ("1.3", "1.2"):
            for scenario in ("valid", "partial", "wrong-host", "untrusted", "wrong-version", "timeout",
                             "eof", "bad-echo", "oversize", "close-fail", "late-close"):
                run(binary, root, cert, key, other, protocol, scenario)
            for scenario in ("clock-rewind", "clock-expired"):
                run(binary, root, cert, key, other, protocol, scenario)
        run(binary, root, cert, key, other, "1.3", "ticket-limit")
    print("27 real-engine/platform probe scenarios passed")


if __name__ == "__main__":
    main()
