#!/usr/bin/env python3
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
from run_loopback import certificate

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    cert, key = certificate(root, "probe")
    empty = root / "empty.pem"
    empty.write_bytes(b"")
    large = root / "large.pem"
    large.write_bytes(b"X" * 65537)
    missing = root / "missing.pem"
    cases = [(cert, hashlib.sha256(cert.read_bytes()).hexdigest(), "valid"),
             (cert, "0" * 64, "hash"), (cert, "bad", "invalid"),
             (empty, "0" * 64, "file"), (large, "0" * 64, "file"),
             (missing, "0" * 64, "file"),
             (key, hashlib.sha256(key.read_bytes()).hexdigest(), "invalid")]
    for path, digest, scenario in cases:
        subprocess.run([sys.argv[1], str(path), digest, scenario], check=True, timeout=15)
print("7 bounded public-CA reader scenarios passed")
