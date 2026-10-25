#!/usr/bin/env python3
import argparse
import datetime
from pathlib import Path
import resource
import socket
import ssl
import subprocess
import tempfile
import threading


def openssl(directory, *arguments):
    subprocess.run(["openssl", *arguments], cwd=directory, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def certificates(directory):
    openssl(directory, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=tls_fixer test root")
    openssl(directory, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key",
            "-out", "server.csr", "-subj", "/CN=localhost")
    (directory / "server.ext").write_text(
        "basicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n"
        "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    openssl(directory, "x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-days", "2", "-extfile", "server.ext", "-out", "server.pem")
    openssl(directory, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", "other.key", "-out", "other.pem", "-days", "2", "-subj", "/CN=other root")
    openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-keyout", "sha1-ca.key", "-out", "sha1-ca.pem", "-days", "2",
            "-subj", "/CN=tls_fixer SHA1 test root")
    openssl(directory, "x509", "-req", "-in", "server.csr", "-CA", "sha1-ca.pem",
            "-CAkey", "sha1-ca.key", "-CAcreateserial", "-sha1", "-days", "2",
            "-extfile", "server.ext", "-out", "sha1-server.pem")
    (directory / "sha1-index.txt").write_text("")
    (directory / "sha1-serial").write_text("01\n")
    (directory / "sha1-ca.conf").write_text(
        "[ca]\ndefault_ca=sign\n[sign]\ndatabase=sha1-index.txt\nserial=sha1-serial\n"
        "new_certs_dir=.\npolicy=policy\n[policy]\ncommonName=supplied\n")
    now = datetime.datetime.now(datetime.timezone.utc)
    openssl(directory, "ca", "-config", "sha1-ca.conf", "-batch", "-notext",
            "-cert", "sha1-ca.pem", "-keyfile", "sha1-ca.key", "-md", "sha1",
            "-startdate", (now - datetime.timedelta(days=3)).strftime("%Y%m%d%H%M%SZ"),
            "-enddate", (now - datetime.timedelta(days=1)).strftime("%Y%m%d%H%M%SZ"),
            "-extfile", "server.ext", "-in", "server.csr", "-out", "sha1-expired.pem")


def run_case(binary, directory, scenario, version):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(15)
    port = listener.getsockname()[1]
    errors = []
    negotiated = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = version
    certificate = "server.pem"
    if scenario.startswith("sha1-"):
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
        certificate = "sha1-expired.pem" if scenario == "sha1-expired" else "sha1-server.pem"
    context.load_cert_chain(directory / certificate, directory / "server.key")
    context.set_servername_callback(lambda connection, name, unused: negotiated.append(name))

    def serve():
        try:
            raw, _ = listener.accept()
            raw.settimeout(12)
            if scenario == "bad-record":
                with raw:
                    raw.sendall(b"not-a-tls-record")
                return
            with context.wrap_socket(raw, server_side=True) as connection:
                negotiated.append(connection.version())
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = connection.recv(4096)
                    if not chunk:
                        return
                    request += chunk
                payload = bytes(i % 251 for i in range(5000))
                connection.sendall(payload)
                if scenario == "abrupt":
                    fd = connection.detach()
                    socket.socket(fileno=fd).close()
                else:
                    connection.unwrap().close()
        except (OSError, ssl.SSLError) as exc:
            if scenario not in {"wrong-host", "wrong-ip", "untrusted", "bad-record", "callback-reject", "changed-write-retry",
                                "sha1-wrong-host", "sha1-untrusted", "sha1-expired"}:
                errors.append(str(exc))
        finally:
            listener.close()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    trust = directory / ("other.pem" if scenario in {"untrusted", "sha1-untrusted", "game-ca"}
                         else "sha1-ca.pem" if scenario.startswith("sha1-") else "ca.pem")
    if scenario == "memory-full-ca":
        trust = directory / "full.pem"
        bundle = Path(__file__).resolve().parents[3] / "misc/certs.cer"
        trust.write_bytes(bundle.read_bytes() + b"\n" + (directory / "ca.pem").read_bytes())
    expected_version = "TLSv1.3" if version == ssl.TLSVersion.TLSv1_3 else "TLSv1.2"
    try:
        command = [str(binary), str(trust), str(port), scenario, expected_version]
        if scenario in {"game-ca", "game-ca-system"}:
            command.append(str(directory / ("ca.pem" if scenario == "game-ca" else "other.pem")))
        result = subprocess.run(command,
                                capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"{scenario}: transport timed out") from exc
    worker.join(2)
    if result.returncode != 0:
        raise AssertionError(f"{scenario}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    if errors or worker.is_alive():
        raise AssertionError(f"{scenario}: server did not terminate cleanly: {errors}")
    if scenario not in {"bad-record", "wrong-host", "wrong-ip", "ipv4-host", "ipv6-host", "override-allowed",
                        "sha1-wrong-host"}:
        assert "localhost" in negotiated, (scenario, "SNI missing", negotiated)
    if scenario != "bad-record":
        assert expected_version in negotiated, (scenario, negotiated)
    print(result.stdout.strip(), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--scenario")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryDirectory(prefix="tls_fixer-loopback-") as temporary:
        directory = Path(temporary)
        certificates(directory)
        cases = [("valid", ssl.TLSVersion.TLSv1_2), ("valid", ssl.TLSVersion.TLSv1_3)]
        cases.extend(("memory-full-ca", version) for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
        cases.extend((name, version) for name in ["game-ca", "game-ca-system"]
                     for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
        cases.extend(("sha1-cert", version) for version in
                     [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
        cases.extend((scenario, ssl.TLSVersion.TLSv1_3) for scenario in
                     ["sha1-wrong-host", "sha1-untrusted", "sha1-expired"])
        cases.extend((scenario, ssl.TLSVersion.TLSv1_3) for scenario in
                     ["wrong-host", "untrusted", "abrupt", "bad-record", "reentrant", "recreate-invalid",
                      "ipv4-host", "ipv6-host", "wrong-ip", "override-allowed", "callback-reject",
                      "write-retry", "changed-write-retry"])
        failures = []
        for scenario, version in cases:
            if args.scenario is None or scenario == args.scenario:
                try:
                    run_case(args.binary.resolve(), directory, scenario, version)
                except AssertionError as exc:
                    failures.append(str(exc))
        if failures:
            raise AssertionError("\n\n".join(failures))


if __name__ == "__main__":
    main()
