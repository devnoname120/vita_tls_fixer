#!/usr/bin/env python3
"""Validate and generate public, app-local inputs for the standalone TLS probe."""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import ssl
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_SHA256 = "2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_certificate(path):
    with Path(path).open("rb") as stream:
        data = stream.read(65537)
    if not data or len(data) > 65536:
        raise ValueError("CA certificate input must be between 1 and 65536 bytes")
    return data


def validate(address, name, tls13_port, tls12_port, ca):
    try:
        ip = ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError as exc:
        raise ValueError("an explicit canonical private-LAN IPv4 address is required") from exc
    networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    if str(ip) != address or not any(ip in ipaddress.ip_network(network) for network in networks):
        raise ValueError("probe traffic must use an explicit private-LAN IPv4 address")
    labels = name.split(".")
    if not name or len(name) > 253 or any(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) is None for label in labels):
        raise ValueError("invalid DNS verification identity")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise ValueError("DNS verification identity must be separate from the numeric peer address")
    ports = []
    for port in (tls13_port, tls12_port):
        text = str(port)
        if re.fullmatch(r"[1-9][0-9]{0,4}", text) is None or not 1024 <= int(text) <= 65535:
            raise ValueError("ports must be distinct TCP ports in 1024..65535")
        ports.append(int(text))
    if ports[0] == ports[1]:
        raise ValueError("strict-version endpoints must have different ports")
    data = read_certificate(ca)
    if not data or len(data) > 65536 or re.fullmatch(
            rb"\s*-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*", data) is None:
        raise ValueError("CA input must contain one public PEM certificate and no other material")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=data.decode("ascii"))
    except (ssl.SSLError, ValueError, UnicodeError) as exc:
        raise ValueError("invalid PEM certificate") from exc
    return {"title_id": "TLSF00002", "address": address, "dns_name": name,
            "tls13_port": ports[0], "tls12_port": ports[1], "ca_sha256": digest(data),
            "strict_versions": ["TLSv1.3", "TLSv1.2"], "hostname_verification": True,
            "system_trust_store_modified": False, "hardware_validated": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--tls13-port", required=True)
    parser.add_argument("--tls12-port", required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--build-type", default="Release")
    parser.add_argument("--compile-flags", default="")
    parser.add_argument("--toolchain", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = validate(args.address, args.name, args.tls13_port, args.tls12_port, args.ca)
        if digest(args.archive.read_bytes()) != ARCHIVE_SHA256:
            raise ValueError("TLS archive identity differs from the pinned engine")
        config["mbedtls_archive_sha256"] = ARCHIVE_SHA256
        files = sorted((ROOT / "tls13/probe").glob("*")) + [
            ROOT / "tls13/provider/platform_shims.c", ROOT / "tls13/CMakeLists.txt",
            ROOT / "tls13/crypto/CMakeLists.txt", ROOT / "tls13/crypto/mbedtls_user_config.h",
            ROOT / "tls13/crypto/psa_user_config.h", ROOT / "tls13/crypto/threading_alt.h",
            ROOT / "font.c", Path(__file__).resolve()]
        config["sources"] = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in files if path.is_file()}
        config["compiler"] = subprocess.run([args.compiler, "--version"], capture_output=True,
                                            text=True, check=True, timeout=10).stdout.splitlines()[0]
        config["build_type"] = args.build_type
        config["compile_flags"] = args.compile_flags
        config["toolchain_sha256"] = digest(args.toolchain.read_bytes()) if args.toolchain else None
        config["build_id"] = digest(json.dumps(config, sort_keys=True, separators=(",", ":")).encode())
        args.output.mkdir(parents=True, exist_ok=True)
        material = read_certificate(args.ca)
        if digest(material) != config["ca_sha256"]:
            raise ValueError("CA changed during configuration")
        (args.output / "probe-ca.pem").write_bytes(material)
        (args.output / "probe-build.json").write_text(json.dumps(config, indent=2) + "\n")
        fields = {"TLS_FIXER_PROBE_ADDRESS": config["address"], "TLS_FIXER_PROBE_DNS_NAME": config["dns_name"],
                  "TLS_FIXER_PROBE_BUILD_ID": config["build_id"], "TLS_FIXER_PROBE_CA_SHA256": config["ca_sha256"]}
        header = "#ifndef TLS_FIXER_PROBE_CONFIG_H\n#define TLS_FIXER_PROBE_CONFIG_H\n"
        header += "".join("#define " + key + " " + json.dumps(value) + "\n" for key, value in fields.items())
        header += f"#define TLS_FIXER_PROBE_TLS13_PORT {config['tls13_port']}u\n"
        header += f"#define TLS_FIXER_PROBE_TLS12_PORT {config['tls12_port']}u\n#endif\n"
        (args.output / "probe_config.h").write_text(header)
        print("PROBE_CONFIGURED", config["build_id"])
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
