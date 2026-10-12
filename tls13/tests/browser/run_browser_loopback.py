#!/usr/bin/env python3
import argparse
from pathlib import Path
import resource
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "transport"))
from run_loopback import certificates, openssl


def run_case(binary, directory, scenario, version):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(12)
    port = listener.getsockname()[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = version
    context.load_cert_chain(directory / ("expired.pem" if scenario == "expired" else "server.pem"), directory / "server.key")
    context.set_alpn_protocols(["http/1.1"])
    names, protocols, errors = [], [], []
    context.set_servername_callback(lambda sock, name, ignored: names.append(name))
    expected_failure = scenario in {"wrong-host", "untrusted", "default-callback-untrusted",
                                   "default-callback-wrong-host", "bad-record", "changed-write", "timeout",
                                   "legacy-callback", "legacy-existing", "cancel-handshake", "missing-ca",
                                   "expired", "wrong-host-peer-disabled", "empty-ca"}

    def serve():
        try:
            raw, _ = listener.accept()
            raw.settimeout(10)
            if scenario.startswith("legacy-") or scenario in {"missing-ca", "empty-ca"}:
                with raw:
                    assert raw.recv(1) == b"", "legacy fallback sent provider data"
                return
            if scenario == "cancel-handshake":
                with raw:
                    while raw.recv(4096):
                        pass
                return
            if scenario == "bad-record":
                with raw:
                    raw.sendall(b"not-a-tls-record")
                return
            if scenario == "timeout":
                time.sleep(0.4)
            with context.wrap_socket(raw, server_side=True) as connection:
                protocols.append(connection.version())
                assert connection.selected_alpn_protocol() in {None, "http/1.1"}
                request = b""
                while b"\r\n\r\n" not in request:
                    part = connection.recv(4096)
                    if not part:
                        return
                    request += part
                assert request.startswith(b"GET / HTTP/1.1\r\n")
                connection.sendall(bytes(i % 251 for i in range(5000)))
                if scenario == "abrupt":
                    fd = connection.detach()
                    socket.socket(fileno=fd).close()
                else:
                    connection.unwrap().close()
        except OSError as exc:
            if not expected_failure:
                errors.append(repr(exc))
        except Exception as exc:
            errors.append(repr(exc))
        finally:
            listener.close()

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    if scenario == "memory-full-ca":
        trust = directory / "combined-ca.pem"
    else:
        trust = directory / ("other.pem" if scenario in {"untrusted", "default-callback-untrusted",
                                                          "peer-disabled"} else "ca.pem")
    expected = "TLSv1.3" if version == ssl.TLSVersion.TLSv1_3 else "TLSv1.2"
    try:
        result = subprocess.run([str(binary), str(trust), str(port), scenario, expected],
                                capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"{scenario}: client timed out") from exc
    server.join(2)
    if result.returncode != 0:
        raise AssertionError(f"{scenario}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    assert not errors and not server.is_alive(), (scenario, errors)
    if not expected_failure:
        assert expected in protocols, (scenario, protocols)
        if scenario not in {"host-disabled", "ipv4-host", "ipv6-host"}:
            assert "localhost" in names, (scenario, names)
    print(result.stdout.strip(), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--scenario")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    cases = [("valid", ssl.TLSVersion.TLSv1_2), ("valid", ssl.TLSVersion.TLSv1_3)]
    cases += [(name, ssl.TLSVersion.TLSv1_3) for name in ["blocking", "second-socket", "wrong-host", "untrusted",
        "peer-disabled", "host-disabled", "ipv4-host", "ipv6-host", "abrupt", "bad-record", "timeout",
        "write-retry", "changed-write", "legacy-callback", "legacy-existing"]]
    cases += [(name, ssl.TLSVersion.TLSv1_3) for name in ["default-callback-valid",
        "default-callback-untrusted", "default-callback-wrong-host"]]
    cases += [(name, ssl.TLSVersion.TLSv1_3) for name in ["cancel-handshake", "custom-ca", "missing-ca",
        "expired", "wrong-host-peer-disabled", "empty-ca", "memory", "memory-full-ca"]]
    with tempfile.TemporaryDirectory(prefix="tls_fixer-browser-") as temporary:
        directory = Path(temporary)
        certificates(directory)
        bundled_ca = Path(__file__).resolve().parents[3] / "misc" / "certs.cer"
        (directory / "combined-ca.pem").write_bytes(
            bundled_ca.read_bytes() + b"\n" + (directory / "ca.pem").read_bytes())
        openssl(directory, "x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-days", "-1", "-extfile", "server.ext", "-out", "expired.pem")
        failures = []
        for scenario, version in cases:
            if args.scenario is None or args.scenario == scenario:
                try:
                    run_case(args.binary.resolve(), directory, scenario, version)
                except AssertionError as exc:
                    failures.append(str(exc))
        if failures:
            raise AssertionError("\n\n".join(failures))


if __name__ == "__main__":
    main()
