#!/usr/bin/env python3
"""Capture bounded, metadata-only diagnostics from the primary Vita on a private LAN."""

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import sys
import threading
import time

PEER = "192.168.1.146"
PACKET = struct.Struct("!4s16sIIIIiQ")
STAGES = (
    "connect.enter", "options.enter", "options.return", "alloc.enter", "alloc.return",
    "setup.enter", "setup.return", "timer.enter", "timer.return", "handshake.enter",
    "handshake.return", "verify.return", "active", "connect.return", "send.enter", "send.return",
    "recv.enter", "recv.return", "close.enter", "close.return", "legacy.enter", "legacy.return",
    "bio.send.enter", "bio.send.return", "bio.recv.enter", "bio.recv.return", "wait.enter", "wait.return",
    "module.enter", "module.active", "pending.enter", "pending.return", "check.enter", "check.return",
    "legacy.option", "legacy.value", "callback.reject", "callback.policy",
)


def validate_endpoint(value: dict) -> dict:
    host = str(ipaddress.IPv4Address(value["host"]))
    networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    if not any(ipaddress.IPv4Address(host) in ipaddress.IPv4Network(network) for network in networks):
        raise ValueError("The runtime receiver must be on a private LAN interface")
    port = value["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("Invalid runtime receiver port")
    nonce = value["nonce"]
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-fA-F]{32}", nonce) is None:
        raise ValueError("A 128-bit hexadecimal runtime-session nonce is required")
    if value.get("expected_peer") != PEER:
        raise ValueError("Only the primary Vita is an authorized runtime source")
    result = dict(value, host=host, nonce=nonce.lower())
    if "provider_sha256" in result and re.fullmatch(r"[0-9a-f]{64}", result["provider_sha256"]) is None:
        raise ValueError("Invalid diagnostic provider hash")
    return result


class RuntimeLog:
    def __init__(self, nonce: bytes, stream, *, max_records: int = 512, max_processes: int = 8):
        if len(nonce) != 16 or not 1 <= max_records <= 512 or not 1 <= max_processes <= 8:
            raise ValueError("Invalid bounded-recorder configuration")
        self.nonce = nonce
        self.stream = stream
        self.max_records = max_records
        self.max_processes = max_processes
        self.accepted = self.rejected = self.duplicates = 0
        self.seen = set()
        self.latest = {}

    def accept(self, data: bytes, peer: tuple) -> bool:
        if peer[0] != PEER or len(data) != PACKET.size:
            self.rejected += 1
            return False
        magic, nonce, sequence, pid, tid, stage, result, timestamp = PACKET.unpack(data)
        if (magic != b"ITR1" or nonce != self.nonce or sequence >= 128
                or not 0 < pid < 0x80000000 or not 0 < tid < 0x80000000
                or not 1 <= stage <= len(STAGES)):
            self.rejected += 1
            return False
        key = (pid, sequence)
        if key in self.seen:
            self.duplicates += 1
            return False
        if self.accepted >= self.max_records or (pid not in self.latest and len(self.latest) >= self.max_processes):
            self.rejected += 1
            return False
        row = {"sequence": sequence, "pid": pid, "tid": tid, "stage_id": stage,
               "stage": STAGES[stage - 1], "result": result, "device_us": timestamp,
               "received_utc": datetime.now(timezone.utc).isoformat()}
        self.stream.write(json.dumps(row, separators=(",", ":")) + "\n")
        self.stream.flush()
        self.seen.add(key)
        self.accepted += 1
        if pid not in self.latest or sequence > self.latest[pid]["sequence"]:
            self.latest[pid] = row
        return True

    def summary(self) -> dict:
        return {"accepted": self.accepted, "rejected": self.rejected, "duplicates": self.duplicates,
                "at_limit": self.accepted >= self.max_records,
                "processes": [{"pid": pid, "last_observed": latest,
                               "missing_before_latest": [n for n in range(latest["sequence"])
                                                         if (pid, n) not in self.seen]}
                              for pid, latest in sorted(self.latest.items())],
                "interpretation": "UDP can lose, reorder or spoof packets; absence is not proof of non-execution"}


class RuntimeCapture:
    def __init__(self, endpoint: dict, output: Path, *, duration: float = 120,
                 socket_factory=socket.socket):
        self.endpoint = validate_endpoint(endpoint)
        if not 0 < duration <= 600:
            raise ValueError("Runtime capture must have a bounded duration")
        self.duration = duration
        self.output = Path(output)
        self.socket_factory = socket_factory
        self.stop_event = threading.Event()
        self.error = None
        self.summary = None
        self.stream = self.sock = self.worker = None

    def __enter__(self):
        self.output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.output.with_suffix(self.output.suffix + ".summary.json").exists():
            raise FileExistsError("Runtime summary already exists")
        try:
            self.sock = self.socket_factory(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            self.sock.bind((self.endpoint["host"], self.endpoint["port"]))
            self.sock.settimeout(0.2)
            self.stream = self.output.open("x", encoding="utf-8")
            os.chmod(self.output, 0o600)
            self.log = RuntimeLog(bytes.fromhex(self.endpoint["nonce"]), self.stream)
            self.worker = threading.Thread(target=self._receive, name="tls_fixer-runtime-capture")
            self.worker.start()
            return self
        except BaseException:
            if self.sock is not None:
                self.sock.close()
            if self.stream is not None:
                self.stream.close()
            raise

    def _receive(self):
        deadline = time.monotonic() + self.duration
        try:
            while not self.stop_event.is_set() and time.monotonic() < deadline and self.log.accepted < self.log.max_records:
                try:
                    data, peer = self.sock.recvfrom(PACKET.size + 1)
                except socket.timeout:
                    continue
                self.log.accept(data, peer)
        except Exception as exc:
            self.error = type(exc).__name__ + ": " + str(exc)
        finally:
            self.stop_event.set()

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop_event.set()
        self.worker.join(2)
        if self.worker.is_alive():
            self.sock.close()
            self.worker.join(2)
        if self.worker.is_alive():
            raise RuntimeError("Runtime receiver did not stop; its files have not been closed under a live writer")
        self.sock.close()
        try:
            self.stream.flush()
            os.fsync(self.stream.fileno())
        finally:
            self.stream.close()
        self.summary = self.log.summary()
        self.summary.update(endpoint=self.endpoint, output=str(self.output), error=self.error,
                            complete=self.error is None, captured_until=datetime.now(timezone.utc).isoformat())
        summary_path = self.output.with_suffix(self.output.suffix + ".summary.json")
        with summary_path.open("x", encoding="utf-8") as stream:
            os.chmod(summary_path, 0o600)
            json.dump(self.summary, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("endpoint", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=120)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.endpoint.stat().st_size > 4096:
            raise ValueError("Oversized runtime endpoint file")
        endpoint = validate_endpoint(json.loads(args.endpoint.read_text()))
        with RuntimeCapture(endpoint, args.output, duration=args.seconds) as capture:
            print("RUNTIME_RECEIVER_READY", endpoint["host"], endpoint["port"], flush=True)
            capture.stop_event.wait(args.seconds + 1)
        print(json.dumps(capture.summary, indent=2))
        return 0 if capture.summary["complete"] and capture.summary["accepted"] else 3
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print("Runtime capture stopped: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
