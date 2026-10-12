import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import threading

MODULE_PATH = Path(__file__).resolve().parents[1] / "vita_tls_cycle.py"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def trace(extra="", hook=7):
    rows = [("trace.open", 0, 0), ("startup.providers", 2, 0),
            ("hook.install.return", 10, hook)]
    if extra:
        rows.append((extra, 0, 0))
    return b"".join(
        (f"tls_fixer-trace1 seq={i:08x} tid=00000001 pid=00000002 obj={obj:08x} "
         f"rc={rc:08x} sp=00001000 free=00001000 us={i:016x} stage={stage}\n").encode()
        for i, (stage, obj, rc) in enumerate(rows))


def browser_trace(status=0, provider=9, status_pid=2, status_id=None):
    rows = [("provider.start.enter", 2, 88, 188),
            ("provider.start.return", 2, 88, provider),
            ("provider.status", status_pid, provider if status_id is None else status_id, status)]
    return trace() + b"".join(
        (f"tls_fixer-trace1 seq={i:08x} tid=00000001 pid={pid:08x} obj={obj:08x} "
         f"rc={rc:08x} sp=00001000 free=00001000 us={i:016x} stage={stage}\n").encode()
        for i, (stage, pid, obj, rc) in enumerate(rows, 3))


def report(error=0):
    data = ("TLS_FIXER-DISARM-RESULT v1\noutcome=00000000\nstage=gate.complete\n"
            "writes=00000001\nverified=00000001\ntrace_setup=00000000\n"
            f"err={error:08x}\nop=00000000\nm=1\n").encode()
    return data.ljust(252, b" ") + b"END\n"


def sfo(title_id):
    keys = b"TITLE_ID\0TITLE\0"
    values = [title_id.encode() + b"\0", b"Browser\0"]
    header = struct.pack("<5I", 0x46535000, 0x101, 52, 52 + len(keys), 2)
    entries = struct.pack("<HHIII", 0, 0x204, len(values[0]), len(values[0]), 0)
    entries += struct.pack("<HHIII", 9, 0x204, len(values[1]), len(values[1]), len(values[0]))
    return header + entries + keys + b"".join(values)


class FakeVita:
    def __init__(self, module):
        self.m = module
        self.disabled = b"*KERNEL\n#x0:/data/tls_fixer-one-shot/tls_fixer.skprx\n"
        self.armed = self.disabled.replace(b"#x0:", b"ux0:")
        self.files = {
            module.CONFIG: self.armed,
            module.KERNEL: b"kernel",
            module.REPORT: b"PENDING".ljust(256, b" "),
            module.TRACE: trace("prior.boot"),
            "/vs0:/app/NPXS10003/sce_sys/param.sfo": sfo("NPXS10003"),
        }
        self.files.update({path: path.encode() for path in module.PROTECTED})
        self.commands = []
        self.down = 0
        self.no_disconnect = False
        self.no_disarm = False
        self.bad_report = False
        self.stale_trace = False
        self.launch_trace = browser_trace()
        self.inventory = []

    def read(self, path, limit):
        if self.down:
            self.down -= 1
            raise OSError("offline")
        if path not in self.files:
            raise self.m.MissingFile(path)
        data = self.files[path]
        if len(data) > limit:
            raise ValueError("too large")
        return data

    def names(self, path):
        return self.inventory

    def command(self, command, *, on_sent=None):
        self.commands.append(command)
        if command == "reboot":
            self.down = 0 if self.no_disconnect else 1
            if not self.no_disarm:
                self.files[self.m.CONFIG] = self.disabled
            self.files[self.m.REPORT] = report(1 if self.bad_report else 0)
            if not self.stale_trace:
                self.files[self.m.TRACE] = trace()
            if on_sent is not None:
                on_sent()
            return "Rebooting...\n"
        raise AssertionError("The cycle must not send a browser launch or UI command")


class CycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not MODULE_PATH.exists():
            raise AssertionError("The guarded after-arm runner has not been implemented")
        spec = importlib.util.spec_from_file_location("vita_tls_cycle", MODULE_PATH)
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.v = FakeVita(self.m)
        self.receipt = {
            "host": "192.168.1.146", "complete": True, "phase": "armed_readback_verified",
            "armed_config_sha256": digest(self.v.armed),
            "expected_disarmed_sha256": digest(self.v.disabled),
            "changed_offset": self.v.armed.index(b"ux0:"),
            "files": [{"path": path, "bytes": len(data), "sha256": digest(data)}
                      for path, data in self.v.files.items() if path != self.m.CONFIG],
        }
        self.tick = 0.0

    def tearDown(self):
        self.temp.cleanup()

    def now(self):
        return self.tick

    def sleep(self, seconds):
        self.tick += seconds

    def run_cycle(self):
        ready = self.m.after_arm(self.v, self.receipt, self.root, "NPXS10003",
                                 boot_timeout=5, settle_seconds=0, clock=self.now, sleep=self.sleep)
        return self.m.observe_browser_ui(self.v, self.receipt, Path(ready["cycle_directory"]),
                                         settle_seconds=0, sleep=self.simulate_ui)

    def simulate_ui(self, seconds):
        self.sleep(seconds)
        if self.v.launch_trace is not None:
            self.v.files[self.m.TRACE] = self.v.launch_trace

    def test_verified_boot_waits_for_normal_browser_ui_without_uri_launch(self):
        result = self.m.after_arm(self.v, self.receipt, self.root, "NPXS10003",
                                  boot_timeout=5, settle_seconds=0, clock=self.now, sleep=self.sleep)
        self.assertEqual(self.v.commands, ["reboot"])
        self.assertTrue(result["boot_verified"])
        self.assertTrue(result["browser_ui_pending"])
        self.assertFalse(result["cycle_complete"])
        self.assertFalse(result["browser_provider_started"])
        self.assertFalse(result["launch_acknowledged"])
        self.assertEqual(result["boot_trace_sha256"], digest(trace()))
        self.assertTrue((Path(result["cycle_directory"]) / "boot/receipt.json").is_file())

    def test_armed_preflight_accepts_disabled_config_identity_in_receipt(self):
        self.receipt["files"].append({
            "path": self.m.CONFIG,
            "bytes": len(self.v.disabled),
            "sha256": digest(self.v.disabled),
        })
        result = self.m.after_arm(self.v, self.receipt, self.root, "NPXS10003",
                                  boot_timeout=5, settle_seconds=0, clock=self.now, sleep=self.sleep)
        self.assertEqual(self.v.commands, ["reboot"])
        self.assertTrue(result["boot_verified"])

    def test_command_interface_refuses_title_launch_without_opening_a_socket(self):
        with patch.object(self.m.socket, "create_connection",
                          side_effect=AssertionError("Title launch reached the socket")) as connect:
            with self.assertRaisesRegex(ValueError, "normal.*UI"):
                self.m.Vita().command("launch NPXS10003")
            connect.assert_not_called()

    def ready_for_ui(self):
        result = self.m.after_arm(self.v, self.receipt, self.root, "NPXS10003",
                                  boot_timeout=5, settle_seconds=0, clock=self.now, sleep=self.sleep)
        return Path(result["cycle_directory"])

    def test_ui_observation_is_read_only_and_requires_provider_evidence(self):
        cycle = self.ready_for_ui()
        result = self.m.observe_browser_ui(self.v, self.receipt, cycle,
                                           settle_seconds=0, sleep=self.sleep)
        self.assertTrue(result["browser_ui_pending"])
        self.assertFalse(result["cycle_complete"])
        self.assertEqual(self.v.commands, ["reboot"])
        self.v.files[self.m.TRACE] = browser_trace()
        result = self.m.observe_browser_ui(self.v, self.receipt, cycle,
                                           settle_seconds=0, sleep=self.sleep)
        self.assertTrue(result["browser_provider_started"])
        self.assertTrue(result["cycle_complete"])
        self.assertFalse(result["tls13_established"])
        self.assertEqual(self.v.commands, ["reboot"])

    def test_ui_observation_rejects_another_boot_before_waiting(self):
        cycle = self.ready_for_ui()
        self.v.files[self.m.TRACE] = trace("another.boot").replace(b"tid=00000001", b"tid=00000003")
        with patch.object(self, "sleep") as sleep:
            with self.assertRaisesRegex(ValueError, "boot"):
                self.m.observe_browser_ui(self.v, self.receipt, cycle, settle_seconds=0, sleep=sleep)
            sleep.assert_not_called()
        self.assertEqual(self.v.commands, ["reboot"])

    def test_ui_observation_refuses_changed_config_or_payload(self):
        cycle = self.ready_for_ui()
        for path in (self.m.CONFIG, self.m.KERNEL, *self.m.PROTECTED):
            old = self.v.files[path]
            with self.subTest(path=path):
                self.v.files[path] += b"changed"
                with self.assertRaises(ValueError):
                    self.m.observe_browser_ui(self.v, self.receipt, cycle, settle_seconds=0, sleep=self.sleep)
                self.assertEqual(self.v.commands, ["reboot"])
            self.v.files[path] = old

    def test_ui_observation_rejects_changed_saved_boot_checkpoint(self):
        cycle = self.ready_for_ui()
        path = cycle / "boot/ur0/tai/tls_fixer-startup.log"
        path.write_bytes(browser_trace())
        with self.assertRaisesRegex(ValueError, "checkpoint"):
            self.m.observe_browser_ui(self.v, self.receipt, cycle, settle_seconds=0, sleep=self.sleep)
        self.assertEqual(self.v.commands, ["reboot"])

    def test_ui_observation_rejects_different_arming_receipt(self):
        cycle = self.ready_for_ui()
        self.receipt["unexpected"] = 1
        with self.assertRaisesRegex(ValueError, "receipt"):
            self.m.observe_browser_ui(self.v, self.receipt, cycle, settle_seconds=0, sleep=self.sleep)
        self.assertEqual(self.v.commands, ["reboot"])

    def test_ui_readiness_is_published_after_receiver_binding(self):
        endpoint = self.runtime_endpoint()
        cycle = self.ready_for_ui()
        state = {"bound": False, "notified": False}
        class Receiver:
            def __init__(self, *args, **kwargs):
                self.summary = None
            def __enter__(self):
                state["bound"] = True
                return self
            def __exit__(self, *args):
                state["bound"] = False
                self.summary = {"accepted": 1, "complete": True}
        def ready(directory):
            self.assertTrue(state["bound"])
            self.assertEqual(self.v.commands, ["reboot"])
            saved = json.loads((directory / "observation.json").read_text())
            self.assertTrue(saved["observation_ready"])
            self.assertFalse(saved["observation_finished"])
            state["notified"] = True
        result = self.m.observe_browser_ui(self.v, self.receipt, cycle, settle_seconds=0,
                                           sleep=self.simulate_ui, runtime_endpoint=endpoint,
                                           runtime_factory=Receiver, on_ready=ready)
        self.assertTrue(state["notified"])
        self.assertFalse(state["bound"])
        self.assertTrue(result["observation_finished"])
        self.assertTrue(result["cycle_complete"])

    def test_ui_readiness_failure_preserves_closed_receiver_and_failure_record(self):
        endpoint = self.runtime_endpoint()
        cycle = self.ready_for_ui()
        state = {"closed": False}
        class Receiver:
            def __init__(self, *args, **kwargs):
                self.summary = None
            def __enter__(self):
                return self
            def __exit__(self, *args):
                state["closed"] = True
                self.summary = {"accepted": 0, "complete": True}
        def failed_ready(directory):
            raise OSError("Readiness notification failed")
        with patch.object(self, "simulate_ui") as ui:
            with self.assertRaises(OSError):
                self.m.observe_browser_ui(self.v, self.receipt, cycle, settle_seconds=0,
                                           sleep=ui, runtime_endpoint=endpoint,
                                           runtime_factory=Receiver, on_ready=failed_ready)
            ui.assert_not_called()
        self.assertTrue(state["closed"])
        records = list(cycle.glob("ui-observation-*/observation.json"))
        self.assertEqual(len(records), 1)
        saved = json.loads(records[0].read_text())
        self.assertTrue(saved["observation_finished"])
        self.assertFalse(saved["cycle_complete"])
        self.assertIn("Readiness notification failed", saved["error"])
        self.assertEqual(self.v.commands, ["reboot"])

    def test_success_reboots_once_then_observes_separately_operated_ui(self):
        outcome = self.run_cycle()
        self.assertEqual(self.v.commands, ["reboot"])
        self.assertTrue(outcome["boot_verified"])
        self.assertTrue(outcome["cycle_complete"])
        self.assertTrue(outcome["browser_provider_started"])
        self.assertFalse(outcome["tls13_established"])
        self.assertTrue((Path(outcome["capture"]) / "receipt.json").is_file())

    def test_no_ui_activity_is_not_a_completed_cycle(self):
        self.v.launch_trace = None
        outcome = self.run_cycle()
        self.assertFalse(outcome["launch_acknowledged"])
        self.assertTrue(outcome["boot_verified"])
        self.assertFalse(outcome["cycle_complete"])
        self.assertFalse(outcome["browser_provider_started"])
        self.assertEqual(self.v.commands, ["reboot"])
        self.assertTrue((Path(outcome["capture"]) / "receipt.json").is_file())

    def test_provider_start_requires_a_correlated_successful_result(self):
        cases = (browser_trace(status=2), browser_trace(status=0x49030000),
                 browser_trace(provider=0x8002d000), browser_trace(status_pid=3),
                 browser_trace(status_id=17), browser_trace()[:-1],
                 browser_trace().replace(b"provider.start.enter", b"unrelated.enter"),
                 browser_trace().replace(b"prior.boot", b"other.boot"),
                 browser_trace().replace(b"hook.install.return", b"unrelated.return"))
        for index, raw in enumerate(cases):
            if index == 7:
                continue
            with self.subTest(index=index):
                v = FakeVita(self.m)
                v.launch_trace = raw
                ready = self.m.after_arm(v, self.receipt, self.root / str(index), "NPXS10003",
                                         boot_timeout=5, settle_seconds=0, clock=self.now, sleep=self.sleep)
                def simulate_ui(seconds):
                    self.sleep(seconds)
                    v.files[self.m.TRACE] = raw
                if index == 8:
                    with self.assertRaisesRegex(ValueError, "saved boot"):
                        self.m.observe_browser_ui(v, self.receipt, Path(ready["cycle_directory"]),
                                                   settle_seconds=0, sleep=simulate_ui)
                    self.assertEqual(v.commands, ["reboot"])
                    continue
                outcome = self.m.observe_browser_ui(v, self.receipt, Path(ready["cycle_directory"]),
                                                    settle_seconds=0, sleep=simulate_ui)
                self.assertFalse(outcome["cycle_complete"])
                self.assertFalse(outcome["browser_provider_started"])
                self.assertEqual(v.commands, ["reboot"])

    def test_changed_file_prevents_reboot(self):
        self.v.files[self.m.KERNEL] = b"different"
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.assertEqual(self.v.commands, [])

    def test_incomplete_receipt_prevents_reboot(self):
        self.receipt["complete"] = False
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.assertEqual(self.v.commands, [])

    def test_missing_required_check_prevents_reboot(self):
        self.receipt["files"] = [f for f in self.receipt["files"] if f["path"] != self.m.KERNEL]
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.assertEqual(self.v.commands, [])

    def test_already_disarmed_receipt_cannot_reboot(self):
        self.v.files[self.m.CONFIG] = self.v.disabled
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.assertEqual(self.v.commands, [])

    def test_alternate_configuration_prevents_reboot(self):
        self.v.files[self.m.ALTERNATE_CONFIG] = b"*KERNEL\n"
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.assertEqual(self.v.commands, [])

    def test_wrong_title_prevents_reboot(self):
        self.v.files["/vs0:/app/NPXS10003/sce_sys/param.sfo"] = sfo("NPXS10015")
        for entry in self.receipt["files"]:
            entry["sha256"] = digest(self.v.files[entry["path"]])
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.assertEqual(self.v.commands, [])

    def test_unchanged_ftp_liveness_is_not_a_boot(self):
        self.v.no_disconnect = True
        with self.assertRaises(TimeoutError):
            self.run_cycle()
        self.assertEqual(self.v.commands, ["reboot"])

    def test_missing_self_disarm_prevents_launch(self):
        self.v.no_disarm = True
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.assertEqual(self.v.commands, ["reboot"])

    def test_failed_recorder_prevents_launch(self):
        self.v.bad_report = True
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.assertEqual(self.v.commands, ["reboot"])

    def test_stale_trace_prevents_launch(self):
        self.v.stale_trace = True
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.assertEqual(self.v.commands, ["reboot"])

    def test_absent_ui_input_still_preserves_evidence(self):
        self.v.launch_trace = None
        outcome = self.run_cycle()
        self.assertFalse(outcome["launch_acknowledged"])
        self.assertFalse(outcome["cycle_complete"])
        self.assertEqual(len(self.v.commands), 1)
        self.assertTrue(Path(outcome["capture"]).is_dir())

    def test_receipt_cannot_be_replayed_after_a_command(self):
        self.run_cycle()
        self.v.files[self.m.CONFIG] = self.v.armed
        with self.assertRaises(ValueError):
            self.run_cycle()
        self.assertEqual(len(self.v.commands), 1)

    def test_collect_is_read_only_and_inventories_without_reading_cores(self):
        self.v.files[self.m.CONFIG] = self.v.disabled
        self.v.inventory = ["/ux0:/data/psp2core-private.psp2dmp", "tls_fixer-browser-00000002.log"]
        self.v.files["/ux0:/data/tls_fixer-browser-00000002.log"] = b"test log\n"
        result = self.m.capture(self.v, self.root / "capture")
        self.assertEqual(result["core_names"], ["psp2core-private.psp2dmp"])
        self.assertEqual(self.v.commands, [])
        self.assertNotIn("psp2core-private.psp2dmp", [Path(x["local"]).name for x in result["files"]])

    def test_hostile_listing_cannot_escape_capture_or_issue_commands(self):
        self.v.inventory = ["../tls_fixer-browser-escape.log", "tls_fixer-browser-a.log\r\nDELE x"]
        with self.assertRaises(ValueError):
            self.m.capture(self.v, self.root / "capture")
        self.assertEqual(self.v.commands, [])
        saved = json.loads((self.root / "capture/receipt.json").read_text())
        self.assertTrue(any(f["path"] == self.m.TRACE for f in saved["files"]))

    def test_collect_inventories_encrypted_vita_cores_without_downloading_them(self):
        self.v.files[self.m.CONFIG] = self.v.disabled
        self.v.inventory = ["/ux0:/data/psp2core-SceWebKitProcess.spsp2dmp",
                            "other.SPSP2DMP", "not-a-core.spsp2dmp.tmp"]
        result = self.m.capture(self.v, self.root / "encrypted-capture")
        self.assertEqual(result["core_names"], ["other.SPSP2DMP", "psp2core-SceWebKitProcess.spsp2dmp"])
        self.assertEqual(self.v.commands, [])
        self.assertTrue(result["complete"])
        self.assertFalse(any(Path(item["local"]).suffix.lower() == ".spsp2dmp" for item in result["files"]))

    def test_many_core_names_do_not_prevent_primary_evidence_capture(self):
        self.v.inventory = [f"core-{i:03d}.psp2dmp" for i in range(200)]
        saved = self.m.capture(self.v, self.root / "capture")
        self.assertTrue(saved["complete"])
        self.assertEqual(len(saved["core_names"]), 200)
        self.assertEqual(self.v.commands, [])

    def test_unarmed_reboot_does_not_launch_or_change_configuration(self):
        self.v.files[self.m.CONFIG] = self.v.disabled
        result = self.m.reboot_disabled(self.v, self.receipt, self.root,
                                       timeout=5, clock=self.now, sleep=self.sleep)
        self.assertEqual(self.v.commands, ["reboot"])
        self.assertTrue(result["disabled_readback_verified"])

    def test_unarmed_reboot_refuses_armed_entry(self):
        with self.assertRaises(ValueError):
            self.m.reboot_disabled(self.v, self.receipt, self.root,
                                  timeout=5, clock=self.now, sleep=self.sleep)
        self.assertEqual(self.v.commands, [])

    def slow_reboot_reply(self):
        observed = threading.Event()
        original_read, original_command = self.v.read, self.v.command
        state = {"down": False, "requested": False}

        def read(path, limit):
            try:
                value = original_read(path, limit)
            except OSError:
                if state["requested"] and path == self.m.CONFIG:
                    state["down"] = True
                raise
            if state["down"]:
                observed.set()
            return value

        def command(text, *, on_sent=None):
            if text == "reboot":
                state["requested"] = True
            reply = original_command(text, on_sent=on_sent)
            if text == "reboot" and not observed.wait(1):
                raise AssertionError("Reboot observation waited for the control reply")
            return reply

        self.v.read, self.v.command = read, command

    def test_reboot_observation_runs_while_reply_is_pending(self):
        self.slow_reboot_reply()
        outcome = self.run_cycle()
        self.assertTrue(outcome["boot_verified"])
        self.assertEqual(self.v.commands, ["reboot"])

    def test_unarmed_observation_runs_while_reply_is_pending(self):
        self.v.files[self.m.CONFIG] = self.v.disabled
        self.slow_reboot_reply()
        outcome = self.m.reboot_disabled(self.v, self.receipt, self.root,
                                        timeout=5, clock=self.now, sleep=self.sleep)
        self.assertTrue(outcome["disabled_readback_verified"])
        self.assertEqual(self.v.commands, ["reboot"])

    def test_rejected_reboot_joins_observer_without_launch(self):
        def rejected(command, *, on_sent=None):
            self.v.commands.append(command)
            if on_sent is not None:
                on_sent()
            return "Error: reboot rejected"
        self.v.command = rejected
        with self.assertRaisesRegex(ValueError, "rejected"):
            self.run_cycle()
        self.assertEqual(self.v.commands, ["reboot"])
        self.assertFalse(any(thread.name == "tls_fixer-reboot-observer" for thread in threading.enumerate()))

    def test_reply_timeout_does_not_discard_an_observed_reboot(self):
        original = self.v.command
        def command(text, *, on_sent=None):
            result = original(text, on_sent=on_sent)
            if text == "reboot":
                raise TimeoutError("reply timed out")
            return result
        self.v.command = command
        outcome = self.m.after_arm(self.v, self.receipt, self.root, "NPXS10003",
                                   boot_timeout=5, settle_seconds=0, clock=self.now, sleep=self.sleep)
        self.assertTrue(outcome["boot_verified"])
        self.assertEqual(outcome["reboot_transport_error"], "reply timed out")
        self.assertEqual(self.v.commands, ["reboot"])

    def test_unconfirmed_send_cannot_launch_or_retry(self):
        def command(text, *, on_sent=None):
            self.v.commands.append(text)
            raise OSError("send failed")
        self.v.command = command
        with self.assertRaisesRegex(RuntimeError, "delivery was not confirmed"):
            self.run_cycle()
        self.assertEqual(self.v.commands, ["reboot"])
        self.assertFalse(any(thread.name == "tls_fixer-reboot-observer" for thread in threading.enumerate()))

    def test_control_read_allows_twenty_seconds_without_changing_connect_timeout(self):
        outer = self
        class Connection:
            def __init__(self):
                self.timeouts = []
                self.reads = 0
            def __enter__(self):
                return self
            def __exit__(self, *unused):
                pass
            def settimeout(self, timeout):
                self.timeouts.append(timeout)
            def sendall(self, data):
                outer.assertEqual(data, b"reboot\n")
            def shutdown(self, direction):
                outer.assertEqual(direction, outer.m.socket.SHUT_WR)
            def recv(self, size):
                if self.timeouts[-1] < 10:
                    raise TimeoutError("Reply is available after ten seconds")
                self.reads += 1
                return b"Rebooting...\n" if self.reads == 1 else b""
        connection = Connection()
        with patch.object(self.m.socket, "create_connection", return_value=connection) as connect:
            self.assertEqual(self.m.Vita().command("reboot"), "Rebooting...\n")
        connect.assert_called_once_with(("192.168.1.146", 1338), timeout=5)
        self.assertEqual(connection.timeouts[0], 20)

    def test_reboot_reply_keeps_writer_open_and_finishes_at_newline(self):
        outer = self
        class Connection:
            def __init__(self):
                self.parts = iter((b"Reboot", b"ing...\n"))
            def __enter__(self):
                return self
            def __exit__(self, *unused):
                pass
            def settimeout(self, timeout):
                pass
            def sendall(self, data):
                outer.assertEqual(data, b"reboot\n")
            def shutdown(self, direction):
                raise AssertionError("vitacompanion requires an open command writer")
            def recv(self, size):
                try:
                    return next(self.parts)
                except StopIteration:
                    raise TimeoutError("The command connection remains open after its reply")
        sent = []
        with patch.object(self.m.socket, "create_connection", return_value=Connection()):
            self.assertEqual(self.m.Vita().command("reboot", on_sent=lambda: sent.append(True)),
                             "Rebooting...\n")
        self.assertEqual(sent, [True])

    def test_sfo_parser_rejects_truncation(self):
        with self.assertRaises(ValueError):
            self.m.sfo_strings(sfo("NPXS10003")[:40])

    def helper_paths(self):
        directory = self.root / "build"
        directory.mkdir()
        stage = directory / "stage.py"
        arm = directory / "arm.py"
        receipt = directory / "armed.json"
        for path in (stage, arm):
            path.write_text("pass\n")
        return stage.resolve(), arm.resolve(), receipt.resolve()

    def test_helper_chain_finishes_with_guarded_reboot(self):
        stage, arm, receipt = self.helper_paths()
        calls = []
        def runner(command, **kwargs):
            calls.append(Path(command[1]))
            if Path(command[1]) == arm:
                receipt.write_text(json.dumps(self.receipt))
            return subprocess.CompletedProcess(command, 0)
        with patch.object(self.m, "after_arm", return_value={"cycle_complete": True}) as finish:
            result = self.m.stage_arm_and_test(self.v, stage, arm, receipt, self.root / "output",
                                              "NPXS10003", project_root=self.root, runner=runner)
        self.assertEqual(calls, [stage, arm])
        finish.assert_called_once()
        self.assertTrue(result["cycle_complete"])

    def test_helper_failure_does_not_reboot(self):
        stage, arm, receipt = self.helper_paths()
        calls = []
        def runner(command, **kwargs):
            calls.append(Path(command[1]))
            raise subprocess.CalledProcessError(1, command)
        with patch.object(self.m, "after_arm") as finish:
            with self.assertRaises(subprocess.CalledProcessError):
                self.m.stage_arm_and_test(self.v, stage, arm, receipt, self.root / "output",
                                         "NPXS10003", project_root=self.root, runner=runner)
        self.assertEqual(calls, [stage])
        finish.assert_not_called()
        self.assertEqual(self.v.commands, [])

    def test_helper_chain_rejects_stale_success_receipt(self):
        stage, arm, receipt = self.helper_paths()
        receipt.write_text(json.dumps(self.receipt))
        with patch.object(self.m, "after_arm") as finish:
            with self.assertRaises(ValueError):
                self.m.stage_arm_and_test(self.v, stage, arm, receipt, self.root / "output", "NPXS10003",
                                         project_root=self.root,
                                         runner=lambda command, **kwargs: subprocess.CompletedProcess(command, 0))
        finish.assert_not_called()

    def test_helper_chain_checks_browser_before_staging(self):
        stage, arm, receipt = self.helper_paths()
        self.v.files["/vs0:/app/NPXS10003/sce_sys/param.sfo"] = sfo("NPXS10015")
        calls = []
        with self.assertRaises(ValueError):
            self.m.stage_arm_and_test(self.v, stage, arm, receipt, self.root / "output", "NPXS10003",
                                     project_root=self.root, runner=lambda *args, **kwargs: calls.append(args))
        self.assertEqual(calls, [])

    def runtime_endpoint(self):
        data = b"runtime diagnostic"
        path = "/ur0:/tai/tls_fixer_startdiag.suprx"
        self.v.files[path] = data
        self.receipt["files"].append({"path": path, "bytes": len(data), "sha256": digest(data)})
        return {"host": "192.168.1.249", "port": 52154, "nonce": "00" * 16,
                "expected_peer": "192.168.1.146", "provider_sha256": digest(data)}

    def test_runtime_receiver_is_bound_before_ui_window_and_stopped_after_capture(self):
        endpoint = self.runtime_endpoint()
        cycle = self.ready_for_ui()
        outer = self
        class Receiver:
            def __init__(self, *args, **kwargs):
                self.summary = None
            def __enter__(self):
                outer.assertEqual(outer.v.commands, ["reboot"])
                return self
            def __exit__(self, *args):
                outer.assertEqual(outer.v.commands, ["reboot"])
                self.summary = {"accepted": 1, "complete": True}
        result = self.m.observe_browser_ui(self.v, self.receipt, cycle, settle_seconds=0,
                                           sleep=self.simulate_ui, runtime_endpoint=endpoint,
                                           runtime_factory=Receiver)
        self.assertEqual(result["runtime"]["accepted"], 1)
        self.assertTrue(result["cycle_complete"])

    def run_incomplete_runtime(self, summary):
        endpoint = self.runtime_endpoint()
        cycle = self.ready_for_ui()
        class Receiver:
            def __init__(self, *args, **kwargs):
                self.summary = None
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.summary = summary
        result = self.m.observe_browser_ui(self.v, self.receipt, cycle, settle_seconds=0,
                                           sleep=self.simulate_ui, runtime_endpoint=endpoint,
                                           runtime_factory=Receiver)
        self.assertFalse(result["cycle_complete"])
        self.assertFalse(result["runtime_complete"])
        self.assertEqual(result["runtime_observed"], summary["accepted"] > 0)
        self.assertEqual(result["runtime"], summary)
        self.assertEqual(self.v.commands, ["reboot"])
        self.assertEqual(self.v.files[self.m.CONFIG], self.v.disabled)
        self.assertTrue((Path(result["capture"]) / "receipt.json").exists())

    def test_no_runtime_packets_is_not_a_successful_diagnostic(self):
        self.run_incomplete_runtime({"accepted": 0, "complete": True, "error": None})

    def test_runtime_receiver_error_is_not_a_successful_diagnostic(self):
        self.run_incomplete_runtime({"accepted": 1, "complete": False, "error": "OSError: receive failed"})

    def test_runtime_endpoint_must_match_armed_provider(self):
        endpoint = self.runtime_endpoint()
        endpoint["provider_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            self.m.after_arm(self.v, self.receipt, self.root, "NPXS10003",
                              runtime_endpoint=endpoint)
        self.assertEqual(self.v.commands, [])

    def test_ui_observation_cannot_silently_drop_required_runtime_capture(self):
        endpoint = self.runtime_endpoint()
        ready = self.m.after_arm(self.v, self.receipt, self.root, "NPXS10003",
                                 boot_timeout=5, settle_seconds=0, clock=self.now, sleep=self.sleep,
                                 runtime_endpoint=endpoint)
        outer = self
        class Receiver:
            def __init__(self, selected, *args, **kwargs):
                outer.assertEqual(selected, endpoint)
                self.summary = None
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.summary = {"accepted": 0, "complete": True}
        result = self.m.observe_browser_ui(self.v, self.receipt, Path(ready["cycle_directory"]),
                                           settle_seconds=0, sleep=self.simulate_ui, runtime_factory=Receiver)
        self.assertFalse(result["cycle_complete"])
        self.assertFalse(result["runtime_observed"])
        self.assertEqual(self.v.commands, ["reboot"])

    def test_ui_observation_rejects_changed_runtime_endpoint_before_waiting(self):
        endpoint = self.runtime_endpoint()
        ready = self.m.after_arm(self.v, self.receipt, self.root, "NPXS10003",
                                 boot_timeout=5, settle_seconds=0, clock=self.now, sleep=self.sleep,
                                 runtime_endpoint=endpoint)
        changed = dict(endpoint, nonce="11" * 16)
        def unexpected_receiver(*args, **kwargs):
            self.fail("A changed endpoint reached receiver construction")
        with patch.object(self, "simulate_ui") as ui:
            with self.assertRaisesRegex(ValueError, "endpoint"):
                self.m.observe_browser_ui(self.v, self.receipt, Path(ready["cycle_directory"]),
                                           settle_seconds=0, sleep=ui, runtime_endpoint=changed,
                                           runtime_factory=unexpected_receiver)
            ui.assert_not_called()
        self.assertEqual(self.v.commands, ["reboot"])

    def test_runtime_bind_failure_prevents_browser_launch(self):
        endpoint = self.runtime_endpoint()
        cycle = self.ready_for_ui()
        class Receiver:
            def __init__(self, *args, **kwargs):
                pass
            def __enter__(self):
                raise OSError("port busy")
            def __exit__(self, *args):
                pass
        with patch.object(self, "simulate_ui") as ui:
            with self.assertRaises(OSError):
                self.m.observe_browser_ui(self.v, self.receipt, cycle, settle_seconds=0,
                                           sleep=ui, runtime_endpoint=endpoint, runtime_factory=Receiver)
            ui.assert_not_called()
        self.assertEqual(self.v.commands, ["reboot"])
        self.assertEqual(self.v.files[self.m.CONFIG], self.v.disabled)


if __name__ == "__main__":
    unittest.main()
