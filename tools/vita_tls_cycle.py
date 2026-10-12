#!/usr/bin/env python3
"""Prepare one guarded tls_fixer boot, then observe a separately operated browser UI test."""

import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import ftplib
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
HOST = "192.168.1.146"
CONFIG = "/ur0:/tai/config.txt"
ALTERNATE_CONFIG = "/ux0:/tai/config.txt"
KERNEL = "/ux0:/data/tls_fixer-one-shot/tls_fixer.skprx"
REPORT = "/ur0:/tai/tls_fixer-disarm-result.txt"
TRACE = "/ur0:/tai/tls_fixer-startup.log"
PROTECTED = (
    "/ur0:/tai/boot_config.txt", "/ur0:/tai/yamt.cfg", "/ur0:/tai/yamt.skprx",
    "/ur0:/tai/yamt_helper.skprx", "/ur0:/tai/vitacompanion.suprx",
    "/ur0:/tai/vitacompanion_kernel.skprx",
)
FIXED_CAPTURE = (CONFIG, KERNEL, REPORT, TRACE, *PROTECTED)
READ_LIMIT = 4 * 1024 * 1024
LOG_LIMIT = 1024 * 1024
COMMAND_RESPONSE_TIMEOUT = 20


class MissingFile(FileNotFoundError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def fresh_directory(parent: Path, prefix: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = parent / (prefix + "-" + stamp + "-" + uuid.uuid4().hex[:8])
    path.mkdir(parents=True, mode=0o700, exist_ok=False)
    return path


class Vita:
    def _ftp(self):
        ftp = ftplib.FTP(timeout=5)
        try:
            ftp.connect(HOST, 1337)
            ftp.login()
            return ftp
        except BaseException:
            ftp.close()
            raise

    def read(self, path: str, limit: int = READ_LIMIT) -> bytes:
        if any(c in path for c in "\r\n\0"):
            raise ValueError("Invalid remote path")
        ftp = self._ftp()
        data = bytearray()
        try:
            def receive(chunk):
                if len(data) + len(chunk) > limit:
                    raise ValueError("Read limit exceeded: " + path)
                data.extend(chunk)
            ftp.retrbinary("RETR " + path, receive)
            return bytes(data)
        except ftplib.error_perm as exc:
            if str(exc) == "550 File not found.":
                raise MissingFile(path) from exc
            raise
        finally:
            ftp.close()

    def names(self, path: str) -> list[str]:
        ftp = self._ftp()
        names = []
        try:
            def receive(name):
                if len(names) >= 4096 or len(name) > 1024:
                    raise ValueError("Directory inventory limit exceeded")
                names.append(name)
            ftp.retrlines("NLST " + path, receive)
            return names
        finally:
            ftp.close()

    def command(self, command: str, *, on_sent=None) -> str:
        if command != "reboot":
            raise ValueError("Only reboot is supported here; open the browser through its normal LiveArea UI")
        with socket.create_connection((HOST, 1338), timeout=5) as stream:
            stream.settimeout(COMMAND_RESPONSE_TIMEOUT)
            stream.sendall(command.encode("ascii") + b"\n")
            if on_sent is not None:
                on_sent()
            # vitacompanion does not reliably reply after a write-side shutdown.
            result = bytearray()
            deadline = time.monotonic() + COMMAND_RESPONSE_TIMEOUT
            while len(result) < 8192:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Command response deadline exceeded")
                stream.settimeout(remaining)
                block = stream.recv(min(1024, 8192 - len(result)))
                if not block:
                    break
                result.extend(block)
                if b"\n" in result:
                    break
            return result.decode("utf-8", "replace")


def safe_leaf(name: str) -> str:
    for prefix in ("/ux0:/data/", "ux0:/data/"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    if not name or name in (".", "..") or len(name) > 255 or any(c in name for c in "/\\:\r\n\0"):
        raise ValueError("Unsafe directory entry")
    return name


def capture(vita, destination: Path) -> dict:
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    receipt = {"host": HOST, "read_only": True, "snapshot": str(destination),
               "files": [], "core_names": [], "complete": False,
               "at": datetime.now(timezone.utc).isoformat()}
    try:
        def save_remote(remote):
            try:
                data = vita.read(remote, LOG_LIMIT)
            except MissingFile:
                receipt["files"].append({"path": remote, "missing": True})
                return b""
            relative = remote.lstrip("/").replace(":", "")
            local = destination / relative
            local.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            local.write_bytes(data)
            entry = {"path": remote, "local": relative, "bytes": len(data), "sha256": digest(data)}
            receipt["files"].append(entry)
            again = vita.read(remote, LOG_LIMIT)
            entry["stable_read"] = data == again
            if again != data:
                local.with_name(local.name + ".second-read").write_bytes(again)
                entry["second_sha256"] = digest(again)
            return data

        current_trace = b""
        for remote in FIXED_CAPTURE:
            data = save_remote(remote)
            if remote == TRACE:
                current_trace = data
        raw_names = vita.names("/ux0:/data")
        if len(raw_names) > 4096:
            raise ValueError("Directory inventory limit exceeded")
        leaves = sorted({safe_leaf(name) for name in raw_names})
        receipt["core_names"] = [n for n in leaves if n.lower().endswith((".psp2dmp", ".spsp2dmp", ".dmp", ".core"))]
        logs = [n for n in leaves if re.fullmatch(r"tls_fixer-browser-[0-9a-fA-F]{8}\.log", n)]
        current_pids = {int(pid, 16) for pid in re.findall(rb" pid=([0-9a-f]{8}) ", current_trace)}
        logs.sort(key=lambda name: (int(name[len("tls_fixer-browser-"):-len(".log")], 16) not in current_pids, name))
        receipt["browser_log_names"] = logs[:64]
        receipt["omitted_browser_log_names"] = logs[64:]
        for name in logs[:64]:
            save_remote("/ux0:/data/" + name)
        receipt["complete"] = not any(f.get("missing") for f in receipt["files"])
        return receipt
    except BaseException as exc:
        receipt["error"] = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        save_json(destination / "receipt.json", receipt)


def stable_read(vita, path: str, limit: int = READ_LIMIT) -> bytes:
    first = vita.read(path, limit)
    if vita.read(path, limit) != first:
        raise ValueError("File changed during verification: " + path)
    return first


def require_no_alternate(vita) -> None:
    try:
        vita.read(ALTERNATE_CONFIG, LOG_LIMIT)
    except MissingFile:
        return
    raise ValueError("Alternate taiHEN configuration exists")


def sfo_strings(data: bytes) -> dict[str, str]:
    if len(data) < 20:
        raise ValueError("Truncated SFO header")
    magic, version, keys, values, count = struct.unpack_from("<5I", data)
    if magic != 0x46535000 or version != 0x101 or count > 128 or not 20 + count * 16 <= keys <= values <= len(data):
        raise ValueError("Invalid SFO layout")
    result = {}
    for i in range(count):
        keyoff, kind, size, capacity, offset = struct.unpack_from("<HHIII", data, 20 + i * 16)
        start = keys + keyoff
        end = data.find(b"\0", start, values)
        if not keys <= start < end < values or size > capacity or values + offset + capacity > len(data):
            raise ValueError("Invalid SFO field")
        key = data[start:end].decode("ascii")
        if key in result:
            raise ValueError("Duplicate SFO key")
        if kind == 0x204:
            value = data[values + offset:values + offset + size]
            if not value.endswith(b"\0") or b"\0" in value[:-1]:
                raise ValueError("Invalid SFO string")
            result[key] = value[:-1].decode("utf-8")
    return result


def check_title(vita, title_id: str) -> dict[str, str]:
    if re.fullmatch(r"[A-Z0-9]{9}", title_id) is None:
        raise ValueError("Invalid browser title ID")
    fields = sfo_strings(stable_read(vita, f"/vs0:/app/{title_id}/sce_sys/param.sfo", LOG_LIMIT))
    if fields.get("TITLE_ID") != title_id:
        raise ValueError("Installed title ID differs from the selected browser")
    return fields


def wait_reboot(vita, timeout: float, clock=time.monotonic, sleep=time.sleep, cancelled=None) -> bytes:
    deadline = clock() + timeout
    disconnected = False
    while clock() < deadline:
        if cancelled is not None and cancelled.is_set():
            raise InterruptedError("Reboot observation cancelled")
        try:
            config = vita.read(CONFIG, LOG_LIMIT)
        except (OSError, EOFError, ftplib.Error):
            disconnected = True
        else:
            if disconnected:
                return config
        sleep(1)
    raise TimeoutError("No observed disconnect/reconnect; command will not be resent")


def request_reboot(vita, outcome: dict, timeout: float, *, prefix: str = "",
                   clock=time.monotonic, sleep=time.sleep) -> bytes:
    cancelled = threading.Event()
    observed = {}
    observer = None

    def watch():
        try:
            observed["config"] = wait_reboot(vita, timeout, clock, sleep, cancelled)
        except BaseException as exc:
            observed["error"] = exc

    def sent():
        nonlocal observer
        if observer is not None:
            raise RuntimeError("Reboot command was sent more than once")
        observer = threading.Thread(target=watch, name="tls_fixer-reboot-observer")
        observer.start()

    try:
        try:
            reply = vita.command("reboot", on_sent=sent)
            outcome[prefix + "response"] = reply
            if "Error:" in reply:
                raise ValueError("Reboot command was rejected: " + reply)
        except (OSError, EOFError) as exc:
            outcome[prefix + "transport_error"] = str(exc)
        if observer is None:
            raise RuntimeError("Reboot delivery was not confirmed; command will not be resent")
        observer.join(timeout + 6)
        if observer.is_alive():
            raise TimeoutError("Reboot observer did not complete within its deadline")
        if "error" in observed:
            raise observed["error"]
        return observed["config"]
    finally:
        cancelled.set()
        if observer is not None and observer.is_alive():
            observer.join(7)
            if observer.is_alive():
                raise RuntimeError("Reboot observer is still active; no further device action is permitted")


def require_clean_boot(vita, old_trace: bytes, disabled: bytes, checks: list[dict]) -> None:
    if stable_read(vita, CONFIG, LOG_LIMIT) != disabled:
        raise ValueError("Self-disarming configuration was not verified; browser will not launch")
    require_no_alternate(vita)
    for item in checks:
        if item["path"] in (TRACE, REPORT):
            continue
        if digest(stable_read(vita, item["path"])) != item["sha256"]:
            raise ValueError("Payload/protected file changed across reboot: " + item["path"])
    data = stable_read(vita, REPORT, 256)
    if len(data) != 256 or not data.startswith(b"TLS_FIXER-DISARM-RESULT v1\n") or not data.endswith(b"END\n"):
        raise ValueError("Malformed startup report")
    fields = {}
    for line in data.splitlines():
        match = re.fullmatch(rb"\s*([a-z_]+)=([a-z0-9.]+)\s*", line)
        if match:
            key, value = (v.decode("ascii") for v in match.groups())
            if key in fields:
                raise ValueError("Duplicate startup report field")
            fields[key] = value
    required = {"outcome": "00000000", "stage": "gate.complete", "writes": "00000001",
                "verified": "00000001", "trace_setup": "00000000", "err": "00000000",
                "op": "00000000", "m": "1"}
    if any(fields.get(k) != v for k, v in required.items()):
        raise ValueError("Incomplete or failed startup/recorder report")
    raw = stable_read(vita, TRACE, LOG_LIMIT)
    if raw == old_trace:
        raise ValueError("Trace was not refreshed by this boot")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from analyze_boot_trace import analyze_trace, RECORD
    parsed = analyze_trace(raw)
    if parsed["trailing_partial_bytes"] or parsed["record_limit_reached"]:
        raise ValueError("Incomplete or exhausted boot trace")
    records = [RECORD.fullmatch(line).groupdict() for line in raw.splitlines(keepends=True)]
    if records[0]["stage"] != b"trace.open":
        raise ValueError("Missing fresh trace header")
    if not any(r["stage"] == b"startup.providers" and int(r["obj"], 16) & 2 for r in records):
        raise ValueError("Browser prerequisites are not ready")
    if not any(r["stage"] == b"hook.install.return" and 0 < int(r["rc"], 16) < 0x80000000 for r in records):
        raise ValueError("Loader hook installation was not verified")
    if any(r["stage"] == b"provider.start.enter" for r in records):
        raise ValueError("Browser provider already ran before the controlled launch; preserve this session")


def browser_start_evidence(boot_trace: bytes, browser_trace: bytes) -> dict:
    result = {"trace_advanced": False, "provider_start_attempts": 0,
              "provider_started": False, "successful_provider_pids": []}
    if not browser_trace.startswith(boot_trace):
        result["error"] = "Browser trace does not extend this cycle's boot capture"
        return result
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from analyze_boot_trace import analyze_trace, RECORD
    try:
        parsed = analyze_trace(browser_trace)
    except (TypeError, ValueError) as exc:
        result["error"] = str(exc)
        return result
    if parsed["trailing_partial_bytes"] or parsed["record_limit_reached"]:
        result["error"] = "Browser trace is incomplete or exhausted"
        return result
    appended = browser_trace[len(boot_trace):]
    result["trace_advanced"] = bool(appended)
    pending = {}
    successful = set()
    for line in appended.splitlines(keepends=True):
        fields = RECORD.fullmatch(line).groupdict()
        stage = fields["stage"]
        pid, tid, obj, rc = (int(fields[k], 16) for k in ("pid", "tid", "obj", "rc"))
        key = (pid, tid)
        if stage == b"provider.start.enter" and pid > 0:
            result["provider_start_attempts"] += 1
            pending[key] = (obj, None)
        elif stage == b"provider.start.return" and key in pending:
            target, _ = pending[key]
            if obj == target and 0 < rc < 0x80000000:
                pending[key] = (target, rc)
            else:
                pending.pop(key)
        elif stage == b"provider.status" and key in pending:
            _, provider = pending.pop(key)
            if provider is not None and obj == provider and rc == 0:
                successful.add(pid)
    result["successful_provider_pids"] = sorted(successful)
    result["provider_started"] = bool(successful)
    return result


def after_arm(vita, armed_receipt: dict, output_root: Path, title_id: str, *,
              boot_timeout: float = 120, settle_seconds: float = 30,
              clock=time.monotonic, sleep=time.sleep, runtime_endpoint=None) -> dict:
    if boot_timeout <= 0 or not 0 <= settle_seconds <= 300:
        raise ValueError("Invalid time budget")
    if (armed_receipt.get("host") != HOST or armed_receipt.get("complete") is not True
            or armed_receipt.get("phase") != "armed_readback_verified"):
        raise ValueError("A completed arming receipt for the primary Vita is required")
    checks = armed_receipt.get("files", [])
    paths = [item["path"] for item in checks]
    if len(set(paths)) != len(paths) or not {KERNEL, REPORT, TRACE, *PROTECTED}.issubset(paths):
        raise ValueError("Receipt is missing required payload/protected-file checks")
    if runtime_endpoint is not None:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from vita_runtime import validate_endpoint
        runtime_endpoint = validate_endpoint(runtime_endpoint)
        provider_hash = runtime_endpoint.get("provider_sha256")
        if not provider_hash or not any(item["path"] == "/ur0:/tai/tls_fixer_startdiag.suprx"
                                       and item["sha256"] == provider_hash for item in checks):
            raise ValueError("Runtime endpoint is not pinned to the armed diagnostic provider")
    identity = digest(json.dumps(armed_receipt, sort_keys=True).encode())
    claims = output_root / "consumed-arm-receipts"
    claims.mkdir(parents=True, mode=0o700, exist_ok=True)
    claim = claims / (identity + ".json")
    if claim.exists():
        raise ValueError("This arming receipt already requested a reboot; it cannot be replayed")
    config = stable_read(vita, CONFIG, LOG_LIMIT)
    if digest(config) != armed_receipt.get("armed_config_sha256"):
        raise ValueError("Device is not in the exact verified armed state")
    marker = b"ux0:/data/tls_fixer-one-shot/tls_fixer.skprx"
    offset = armed_receipt.get("changed_offset")
    if (not isinstance(offset, int) or config.count(marker) != 1 or config.count(b"tls_fixer.skprx") != 1
            or config.find(marker) != offset or (offset != 0 and config[offset - 1:offset] != b"\n")):
        raise ValueError("Not the single expected tls_fixer boot entry")
    disabled = config[:offset] + b"#" + config[offset + 1:]
    if digest(disabled) != armed_receipt.get("expected_disarmed_sha256"):
        raise ValueError("The expected rollback is not the exact one-byte self-disable")
    require_no_alternate(vita)
    for item in checks:
        if item["path"] == CONFIG:
            if item["bytes"] != len(disabled) or item["sha256"] != digest(disabled):
                raise ValueError("Receipt has an inconsistent disabled configuration identity")
            continue
        data = stable_read(vita, item["path"])
        if len(data) != item["bytes"] or digest(data) != item["sha256"]:
            raise ValueError("Armed payload/protected-file mismatch: " + item["path"])
    title = check_title(vita, title_id)
    destination = fresh_directory(output_root, "146-cycle")
    outcome = {"host": HOST, "armed_receipt_sha256": identity, "title": title,
               "reboot_requested": False, "boot_verified": False, "launch_acknowledged": False,
               "cycle_complete": False, "browser_provider_started": False,
               "browser_ui_pending": False, "cycle_directory": str(destination),
               "tls13_established": False, "interpretation": "Kernel startup is not visual LiveArea or TLS proof"}
    if runtime_endpoint is not None:
        outcome.update(runtime_observed=False, runtime_complete=False, runtime_endpoint=runtime_endpoint)
    old_trace = stable_read(vita, TRACE, LOG_LIMIT)
    capture(vita, destination / "before")
    if stable_read(vita, CONFIG, LOG_LIMIT) != config:
        raise ValueError("Configuration changed during final preflight")
    with claim.open("x", encoding="utf-8") as stream:
        json.dump({"capture": str(destination), "state": "command_may_be_sent"}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        outcome["reboot_requested"] = True
        save_json(destination / "cycle.json", outcome)
        request_reboot(vita, outcome, boot_timeout, prefix="reboot_", clock=clock, sleep=sleep)
        require_clean_boot(vita, old_trace, disabled, checks)
        outcome["boot_verified"] = True
        evidence = capture(vita, destination / "boot")
        if not evidence["complete"] or any(not item.get("stable_read") for item in evidence["files"]):
            raise ValueError("Boot checkpoint was not captured completely and stably")
        outcome["capture"] = evidence["snapshot"]
        trace_relative = TRACE.lstrip("/").replace(":", "")
        outcome["boot_trace_sha256"] = digest((destination / "boot" / trace_relative).read_bytes())
        outcome["expected_disarmed_sha256"] = digest(disabled)
        if stable_read(vita, CONFIG, LOG_LIMIT) != disabled:
            raise ValueError("Configuration changed while saving the boot checkpoint")
        outcome["browser_ui_pending"] = True
        outcome["next_action"] = "Verify the screen, use browser icon/Start, and collect with observe-ui; do not re-arm"
        return outcome
    except BaseException as exc:
        outcome["error"] = type(exc).__name__ + ": " + str(exc)
        try:
            capture(vita, destination / "failure")
        except Exception as capture_error:
            outcome["failure_capture_error"] = str(capture_error)
        raise
    finally:
        save_json(destination / "cycle.json", outcome)


def read_saved_json(path: Path, limit: int = LOG_LIMIT) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Oversized saved checkpoint")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("Invalid saved checkpoint")
    return result


def observe_browser_ui(vita, armed_receipt: dict, cycle_directory: Path, *,
                       settle_seconds: float = 30, sleep=time.sleep,
                       runtime_endpoint=None, runtime_factory=None, on_ready=None) -> dict:
    if not 0 <= settle_seconds <= 300:
        raise ValueError("Invalid UI observation time budget")
    cycle_directory = cycle_directory.resolve(strict=True)
    saved = read_saved_json(cycle_directory / "cycle.json")
    identity = digest(json.dumps(armed_receipt, sort_keys=True).encode())
    if (saved.get("host") != HOST or saved.get("boot_verified") is not True
            or saved.get("browser_ui_pending") is not True
            or saved.get("armed_receipt_sha256") != identity):
        raise ValueError("UI observation requires the matching verified boot/arming receipt")
    boot = cycle_directory / "boot"
    checkpoint = read_saved_json(boot / "receipt.json")
    relative = TRACE.lstrip("/").replace(":", "")
    with (boot / relative).open("rb") as stream:
        boot_trace = stream.read(LOG_LIMIT + 1)
    trace_entries = [item for item in checkpoint.get("files", []) if item.get("path") == TRACE]
    if (len(boot_trace) > LOG_LIMIT or not boot_trace or checkpoint.get("complete") is not True
            or len(trace_entries) != 1 or trace_entries[0].get("stable_read") is not True
            or trace_entries[0].get("bytes") != len(boot_trace)
            or trace_entries[0].get("sha256") != digest(boot_trace)
            or saved.get("boot_trace_sha256") != digest(boot_trace)):
        raise ValueError("Saved boot checkpoint differs from its verified identity")
    checks = armed_receipt.get("files", [])
    paths = [item["path"] for item in checks]
    if len(set(paths)) != len(paths) or not {KERNEL, *PROTECTED}.issubset(paths):
        raise ValueError("Missing payload/protected-file checks in arming receipt")
    if saved.get("expected_disarmed_sha256") != armed_receipt.get("expected_disarmed_sha256"):
        raise ValueError("Saved disabled configuration differs from arming receipt")
    required_endpoint = saved.get("runtime_endpoint")
    if required_endpoint is not None:
        if runtime_endpoint is not None and runtime_endpoint != required_endpoint:
            raise ValueError("Runtime endpoint differs from the saved boot checkpoint")
        runtime_endpoint = required_endpoint

    def verify_state():
        if digest(stable_read(vita, CONFIG, LOG_LIMIT)) != saved["expected_disarmed_sha256"]:
            raise ValueError("Configuration is no longer in the verified disabled state")
        require_no_alternate(vita)
        for item in checks:
            if item["path"] in (TRACE, REPORT):
                continue
            raw = stable_read(vita, item["path"])
            if len(raw) != item["bytes"] or digest(raw) != item["sha256"]:
                raise ValueError("Payload/protected file changed before UI observation: " + item["path"])
        if not stable_read(vita, TRACE, LOG_LIMIT).startswith(boot_trace):
            raise ValueError("Current trace is not from the saved boot; no browser input was sent")

    if runtime_endpoint is not None:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from vita_runtime import RuntimeCapture, validate_endpoint
        runtime_endpoint = validate_endpoint(runtime_endpoint)
        if not runtime_endpoint.get("provider_sha256") or not any(
                item["path"] == "/ur0:/tai/tls_fixer_startdiag.suprx"
                and item["sha256"] == runtime_endpoint["provider_sha256"] for item in checks):
            raise ValueError("Runtime endpoint is not pinned to the armed diagnostic provider")
        if runtime_factory is None:
            runtime_factory = RuntimeCapture
    verify_state()
    destination = fresh_directory(cycle_directory, "ui-observation")
    outcome = {"host": HOST, "armed_receipt_sha256": identity, "cycle_directory": str(cycle_directory),
               "boot_verified": True, "boot_trace_sha256": digest(boot_trace),
               "reboot_requested": False, "configuration_written": False, "ui_input_sent": False,
               "launch_acknowledged": False, "browser_ui_pending": True,
               "cycle_complete": False, "browser_provider_started": False, "tls13_established": False,
               "observation_ready": False, "observation_finished": False,
               "interpretation": "Provider startup is not a completed page load or TLS negotiation"}
    if runtime_endpoint is not None:
        outcome.update(runtime_observed=False, runtime_complete=False)
    runtime = None
    def record_runtime_summary():
        if runtime is not None and getattr(runtime, "summary", None) is not None:
            outcome["runtime"] = runtime.summary
            accepted = runtime.summary.get("accepted", 0)
            outcome["runtime_observed"] = isinstance(accepted, int) and accepted > 0
            outcome["runtime_complete"] = (runtime.summary.get("complete") is True
                                           and not runtime.summary.get("error")
                                           and outcome["runtime_observed"])
    try:
        runtime = runtime_factory(runtime_endpoint, destination / "runtime.jsonl",
                                  duration=settle_seconds + 30) if runtime_endpoint is not None else None
        with runtime if runtime is not None else nullcontext():
            outcome["observation_ready"] = True
            save_json(destination / "observation.json", outcome)
            if on_ready is not None:
                on_ready(destination)
            sleep(settle_seconds)
            evidence = capture(vita, destination / "browser")
        record_runtime_summary()
        outcome["capture"] = evidence["snapshot"]
        activity = browser_start_evidence(boot_trace, (destination / "browser" / relative).read_bytes())
        outcome["browser_activity"] = activity
        outcome["browser_provider_started"] = activity["provider_started"]
        outcome["browser_ui_pending"] = not activity["provider_started"]
        outcome["cycle_complete"] = (evidence["complete"]
                                     and all(item.get("stable_read") for item in evidence["files"])
                                     and outcome["browser_provider_started"]
                                     and outcome.get("runtime_complete", True))
        verify_state()
        return outcome
    except BaseException as exc:
        outcome["cycle_complete"] = False
        outcome["error"] = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        record_runtime_summary()
        outcome["observation_finished"] = True
        save_json(destination / "observation.json", outcome)


def reboot_disabled(vita, armed_receipt: dict, output_root: Path, *, timeout: float = 120,
                    clock=time.monotonic, sleep=time.sleep) -> dict:
    if timeout <= 0 or armed_receipt.get("host") != HOST or armed_receipt.get("complete") is not True:
        raise ValueError("A completed receipt and a positive time budget are required")
    config = stable_read(vita, CONFIG, LOG_LIMIT)
    if (digest(config) != armed_receipt.get("expected_disarmed_sha256")
            or config.count(b"#x0:/data/tls_fixer-one-shot/tls_fixer.skprx") != 1
            or config.count(b"tls_fixer.skprx") != 1):
        raise ValueError("The exact self-disabled configuration is required for an unarmed reboot")
    require_no_alternate(vita)
    checks = armed_receipt.get("files", [])
    paths = [item["path"] for item in checks]
    if len(set(paths)) != len(paths) or not {KERNEL, *PROTECTED}.issubset(paths):
        raise ValueError("Missing protected-file checks")
    checks = [item for item in checks if item["path"] not in (TRACE, REPORT)]
    for item in checks:
        data = stable_read(vita, item["path"])
        if digest(data) != item["sha256"] or len(data) != item["bytes"]:
            raise ValueError("Changed protected file: " + item["path"])
    destination = fresh_directory(output_root, "146-unarmed-reboot")
    outcome = {"host": HOST, "reboot_requested": False, "disabled_readback_verified": False,
               "configuration_written": False, "browser_launched": False,
               "interpretation": "A commanded disconnect/reconnect is not a visual LiveArea observation"}
    capture(vita, destination / "before")
    if stable_read(vita, CONFIG, LOG_LIMIT) != config:
        raise ValueError("Configuration changed before the unarmed reboot")
    try:
        outcome["reboot_requested"] = True
        save_json(destination / "reboot.json", outcome)
        request_reboot(vita, outcome, timeout, clock=clock, sleep=sleep)
        if stable_read(vita, CONFIG, LOG_LIMIT) != config:
            raise ValueError("Configuration changed across unarmed reboot")
        require_no_alternate(vita)
        for item in checks:
            if digest(stable_read(vita, item["path"])) != item["sha256"]:
                raise ValueError("Protected file changed across unarmed reboot")
        evidence = capture(vita, destination / "after")
        outcome["capture"] = evidence["snapshot"]
        outcome["disabled_readback_verified"] = True
        return outcome
    except BaseException as exc:
        outcome["error"] = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        save_json(destination / "reboot.json", outcome)


def stage_arm_and_test(vita, stage: Path, arm: Path, receipt: Path, output_root: Path,
                       title_id: str, *, project_root: Path = ROOT, runner=subprocess.run,
                       boot_timeout: float = 120, settle_seconds: float = 30,
                       runtime_endpoint=None) -> dict:
    if runtime_endpoint is not None:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from vita_runtime import validate_endpoint
        runtime_endpoint = validate_endpoint(runtime_endpoint)
        if not runtime_endpoint.get("provider_sha256"):
            raise ValueError("Runtime endpoint must identify the verified diagnostic provider")
    project_root = project_root.resolve()
    scripts = []
    for path in (stage, arm):
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or resolved.suffix != ".py" or not resolved.is_relative_to(project_root / "build"):
            raise ValueError("Select an existing, reviewed Python helper under this worktree's build directory")
        scripts.append(resolved)
    receipt = receipt.resolve()
    if not receipt.is_relative_to(project_root / "build"):
        raise ValueError("Arming receipt must be under this worktree's build directory")
    previous = None
    if receipt.exists():
        if receipt.stat().st_size > LOG_LIMIT:
            raise ValueError("Oversized previous arming receipt")
        previous = receipt.read_bytes()
    check_title(vita, title_id)
    destination = fresh_directory(output_root, "146-transfer-cycle")
    outcome = {"host": HOST, "stage": str(scripts[0]), "arm": str(scripts[1]),
               "helper_sha256": [digest(path.read_bytes()) for path in scripts],
               "stage_complete": False, "arm_complete": False, "cycle_complete": False}
    try:
        save_json(destination / "transfer.json", outcome)
        for index, script in enumerate(scripts):
            if digest(script.read_bytes()) != outcome["helper_sha256"][index]:
                raise ValueError("Selected helper changed during this cycle")
            result = runner([sys.executable, str(script)], cwd=project_root, check=True, timeout=600)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, str(script))
            outcome["stage_complete" if index == 0 else "arm_complete"] = True
            save_json(destination / "transfer.json", outcome)
        if receipt.stat().st_size > LOG_LIMIT:
            raise ValueError("Oversized arming receipt")
        raw = receipt.read_bytes()
        if raw == previous:
            raise ValueError("Helpers did not publish a new arming receipt")
        result = after_arm(vita, json.loads(raw), output_root, title_id,
                           boot_timeout=boot_timeout, settle_seconds=settle_seconds,
                           runtime_endpoint=runtime_endpoint)
        outcome["cycle"] = result
        outcome["cycle_complete"] = result["cycle_complete"]
        return result
    except BaseException as exc:
        outcome["error"] = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        save_json(destination / "transfer.json", outcome)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    collect = commands.add_parser("collect", help="Read logs and inventory cores; never upload or reboot")
    collect.add_argument("--output", type=Path)
    after = commands.add_parser("after-arm", help="Verify one armed boot and save a checkpoint; never launch the browser")
    after.add_argument("receipt", type=Path)
    after.add_argument("--browser-title-id", required=True)
    after.add_argument("--boot-timeout", type=float, default=120)
    after.add_argument("--settle-seconds", type=float, default=30)
    after.add_argument("--runtime-endpoint", type=Path)
    observe = commands.add_parser("observe-ui", help="Observe a normal browser UI test in a saved boot; no input or reboot")
    observe.add_argument("receipt", type=Path)
    observe.add_argument("cycle_directory", type=Path)
    observe.add_argument("--settle-seconds", type=float, default=30)
    observe.add_argument("--runtime-endpoint", type=Path)
    reset = commands.add_parser("reboot-disabled", help="Preserve evidence and reboot once without arming or launching")
    reset.add_argument("receipt", type=Path)
    reset.add_argument("--boot-timeout", type=float, default=120)
    run = commands.add_parser("run", help="Stage/arm once, verify one boot and stop before normal browser UI input")
    run.add_argument("--stage", type=Path, required=True)
    run.add_argument("--arm", type=Path, required=True)
    run.add_argument("--receipt", type=Path, required=True)
    run.add_argument("--browser-title-id", required=True)
    run.add_argument("--boot-timeout", type=float, default=120)
    run.add_argument("--settle-seconds", type=float, default=30)
    run.add_argument("--runtime-endpoint", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    vita = Vita()
    output_root = ROOT / "build/device-evidence"
    try:
        runtime_endpoint = None
        if getattr(args, "runtime_endpoint", None) is not None:
            if args.runtime_endpoint.stat().st_size > 4096:
                raise ValueError("Oversized runtime endpoint")
            runtime_endpoint = json.loads(args.runtime_endpoint.read_text())
        if args.action == "collect":
            destination = args.output
            if destination is None:
                parent = fresh_directory(output_root, "146-log-capture")
                destination = parent / "files"
            result = capture(vita, destination)
        elif args.action == "run":
            result = stage_arm_and_test(vita, args.stage, args.arm, args.receipt, output_root,
                                        args.browser_title_id, boot_timeout=args.boot_timeout,
                                        settle_seconds=args.settle_seconds, runtime_endpoint=runtime_endpoint)
        else:
            if args.receipt.stat().st_size > LOG_LIMIT:
                raise ValueError("Oversized arming receipt")
            receipt = json.loads(args.receipt.read_text())
            if args.action == "after-arm":
                result = after_arm(vita, receipt, output_root, args.browser_title_id,
                                   boot_timeout=args.boot_timeout, settle_seconds=args.settle_seconds,
                                   runtime_endpoint=runtime_endpoint)
            elif args.action == "observe-ui":
                result = observe_browser_ui(vita, receipt, args.cycle_directory,
                                            settle_seconds=args.settle_seconds, runtime_endpoint=runtime_endpoint,
                                            on_ready=lambda directory: print(
                                                "BROWSER_UI_OBSERVATION_READY " + str(directory), flush=True))
            else:
                result = reboot_disabled(vita, receipt, output_root, timeout=args.boot_timeout)
        print(json.dumps(result, indent=2))
        if args.action in ("after-arm", "run") and result.get("browser_ui_pending"):
            print("BOOT_VERIFIED_WAITING_FOR_BROWSER_UI: use the visible browser icon and Start tile, "
                  "then observe-ui with this cycle directory. Do not rerun stage/arm.", file=sys.stderr)
        if args.action in ("after-arm", "run") and not result["cycle_complete"]:
            return 3
        if args.action == "observe-ui" and not result["cycle_complete"]:
            return 3
        if args.action == "collect" and not result["complete"]:
            return 3
        return 0
    except (OSError, EOFError, ValueError, KeyError, TypeError, RuntimeError, ftplib.Error, subprocess.SubprocessError) as exc:
        print("Stopped: " + str(exc), file=sys.stderr)
        print("No retry, re-arm or additional reboot will be performed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
