#!/usr/bin/env python3
"""Self-signed server certificates trusted by exact match: real certificates from openssl, checked
by test_exact_trust (Mbed TLS with the providers' store index and verification callback)."""
import argparse
import datetime
from pathlib import Path
import subprocess
import tempfile

NOT_TRUSTED, EXPIRED, CN_MISMATCH = 0x08, 0x01, 0x04


def openssl(directory, *arguments):
    subprocess.run(["openssl", *arguments], cwd=directory, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def self_signed(directory, name, *extra):
    openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
            "-keyout", name + ".key", "-out", name + ".pem", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost", *extra)


def certificates(directory):
    server = ("-addext", "basicConstraints=critical,CA:FALSE")
    # The server's own certificate, and another with the same name but a different key
    self_signed(directory, "server", *server)
    self_signed(directory, "lookalike", *server)
    # One made with openssl's defaults, which is a CA and already worked before
    self_signed(directory, "default")
    # A root unrelated to the server, as the rest of a real store
    openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-keyout", "root.key", "-out", "root.pem", "-subj", "/CN=tls_fixer test root")
    # The server's certificate again, but expired
    (directory / "index.txt").write_text("")
    (directory / "serial").write_text("01\n")
    (directory / "expired.conf").write_text(
        "[ca]\ndefault_ca=sign\n[sign]\ndatabase=index.txt\nserial=serial\nnew_certs_dir=.\n"
        "policy=policy\ncopy_extensions=copy\n[policy]\ncommonName=supplied\n")
    (directory / "server.ext").write_text("basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost\n")
    openssl(directory, "req", "-new", "-key", "server.key", "-out", "server.csr", "-subj", "/CN=localhost")
    now = datetime.datetime.now(datetime.timezone.utc)
    openssl(directory, "ca", "-config", "expired.conf", "-batch", "-notext", "-selfsign",
            "-keyfile", "server.key", "-md", "sha256",
            "-startdate", (now - datetime.timedelta(days=3)).strftime("%Y%m%d%H%M%SZ"),
            "-enddate", (now - datetime.timedelta(days=1)).strftime("%Y%m%d%H%M%SZ"),
            "-extfile", "server.ext", "-in", "server.csr", "-out", "expired.pem")
    # A normal server certificate issued by the root, which is not self-signed
    openssl(directory, "x509", "-req", "-in", "server.csr", "-CA", "root.pem", "-CAkey", "root.key",
            "-CAcreateserial", "-days", "2", "-extfile", "server.ext", "-out", "issued.pem")


def store(directory, name, *members):
    path = directory / (name + ".store")
    path.write_bytes(b"".join((directory / (member + ".pem")).read_bytes() for member in members))
    return path


def flags(binary, directory, store_path, certificate, host="localhost", mode="exact"):
    result = subprocess.run([str(binary), str(store_path), str(directory / (certificate + ".pem")), host, mode],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (certificate, result.stdout, result.stderr)
    return int(result.stdout.strip().split("=")[1], 16)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve()
    with tempfile.TemporaryDirectory(prefix="tls_fixer-exact-trust-") as temporary:
        directory = Path(temporary)
        certificates(directory)
        with_server = store(directory, "with-server", "root", "server")
        cases = [
            # The server's own certificate in the store is trusted, though it is not a CA
            ("trusted as itself", with_server, "server", "localhost", "exact", 0),
            # Mbed TLS alone does not, with trust read through a callback: the reason for the rule
            ("Mbed TLS alone", with_server, "server", "localhost", "plain", NOT_TRUSTED),
            # Not in the store, or only a certificate with the same name and another key
            ("missing", store(directory, "without", "root"), "server", "localhost", "exact", NOT_TRUSTED),
            ("lookalike", store(directory, "lookalike", "root", "lookalike"), "server", "localhost", "exact",
             NOT_TRUSTED),
            # Its other checks still apply
            ("wrong host", with_server, "server", "wrong.invalid", "exact", CN_MISMATCH),
            ("expired", store(directory, "expired", "root", "expired"), "expired", "localhost", "exact", EXPIRED),
            # A certificate that isn't self-signed is never trusted as itself
            ("issued, not self-signed", store(directory, "issued", "issued"), "issued", "localhost", "exact",
             NOT_TRUSTED),
            # openssl's default self-signed certificate is a CA, and is trusted either way
            ("CA default", store(directory, "default", "default"), "default", "localhost", "plain", 0),
            ("CA default, with the rule", store(directory, "default", "default"), "default", "localhost", "exact", 0),
        ]
        failures = []
        for name, store_path, certificate, host, mode, expected in cases:
            actual = flags(binary, directory, store_path, certificate, host, mode)
            if actual != expected:
                failures.append(f"{name}: flags {actual:08X}, expected {expected:08X}")
            else:
                print(f"exact trust: {name} PASS")
        if failures:
            raise AssertionError("\n".join(failures))


if __name__ == "__main__":
    main()
