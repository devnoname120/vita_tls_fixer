"""Apply the version-pinned, small receive-buffer change to a build extraction."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

source = Path(sys.argv[1])
directory = Path(__file__).resolve().parent / "patches"
manifest = json.loads((directory / "small-rx-4.2.json").read_text())
states = []
for name, hashes in manifest.items():
    digest = hashlib.sha256((source / name).read_bytes()).hexdigest()
    states.append("before" if digest == hashes["before"] else "after" if digest == hashes["after"] else "unknown")
if all(state == "after" for state in states):
    raise SystemExit(0)
if not all(state == "before" for state in states):
    raise SystemExit("Small receive-buffer source is modified or partially patched")
subprocess.run(["patch", "--batch", "--forward", "-p1", "-i", str(directory / "small-rx-4.2.patch")],
               cwd=source, check=True)
for name, hashes in manifest.items():
    if hashlib.sha256((source / name).read_bytes()).hexdigest() != hashes["after"]:
        raise SystemExit("Unexpected Small receive-buffer output: " + name)
