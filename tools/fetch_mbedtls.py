#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

VERSION = "4.2.0"
ARCHIVE_NAME = f"mbedtls-{VERSION}.tar.bz2"
ARCHIVE_SHA256 = "2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea"


class DependencyError(RuntimeError):
    pass


def verify_archive(path: Path) -> None:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != ARCHIVE_SHA256:
        raise DependencyError(
            f"SHA-256 mismatch for {path}: {actual}; expected {ARCHIVE_SHA256}"
        )


def download_archive(destination: Path) -> None:
    try:
        subprocess.run(
            ["gh", "release", "download", f"mbedtls-{VERSION}",
             "--repo", "Mbed-TLS/mbedtls", "--pattern", ARCHIVE_NAME,
             "--output", str(destination)],
            check=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DependencyError(f"Mbed TLS release download failed: {exc}") from exc


def ensure_archive(directory: Path) -> Path:
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / ARCHIVE_NAME
    if archive.exists():
        verify_archive(archive)
        return archive

    with tempfile.TemporaryDirectory(prefix=".mbedtls-download-", dir=directory) as temporary:
        candidate = Path(temporary) / ARCHIVE_NAME
        download_archive(candidate)
        verify_archive(candidate)
        os.replace(candidate, archive)
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch the checksum-pinned Mbed TLS release using gh")
    parser.add_argument("--cache", type=Path, default=Path(__file__).resolve().parents[1] / "build" / "deps")
    args = parser.parse_args()
    try:
        print(ensure_archive(args.cache))
    except (DependencyError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
