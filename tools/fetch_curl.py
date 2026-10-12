#!/usr/bin/env python3
"""Fetch the checksum-pinned curl source used by the Vita installer."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

ARCHIVE_NAME = 'curl-8.17.0.tar.gz'
ARCHIVE_SHA256 = 'e8e74cdeefe5fb78b3ae6e90cd542babf788fa9480029cfcee6fd9ced42b7910'


def verify(path):
    if hashlib.sha256(path.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('curl source archive SHA-256 mismatch')


def ensure_archive(directory):
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / ARCHIVE_NAME
    if archive.exists():
        verify(archive)
        return archive
    with tempfile.TemporaryDirectory(prefix='.curl-download-', dir=directory) as temporary:
        candidate = Path(temporary) / ARCHIVE_NAME
        subprocess.run(['gh', 'release', 'download', 'curl-8_17_0', '--repo', 'curl/curl',
                        '--pattern', ARCHIVE_NAME, '--output', str(candidate)], check=True, timeout=300)
        verify(candidate)
        candidate.replace(archive)
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=Path(__file__).resolve().parents[1] / "build/deps")
    args = parser.parse_args()
    try:
        print(ensure_archive(args.cache))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
