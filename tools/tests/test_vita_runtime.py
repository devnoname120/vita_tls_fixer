import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import tempfile
import socket
import threading
import unittest

MODULE = Path(__file__).resolve().parents[1] / "vita_runtime.py"
NONCE = bytes(range(16))


class FakeSocket:
    def __init__(self, packets=(), bind_failure=False):
        self.packets = list(packets)
        self.bind_failure = bind_failure
        self.closed = False
        self.bound = None
        self.quiet = threading.Event()

    def setsockopt(self, *args):
        pass

    def settimeout(self, timeout):
        self.timeout = timeout

    def bind(self, endpoint):
        if self.bind_failure:
            raise OSError("address in use")
        self.bound = endpoint

    def recvfrom(self, size):
        if self.packets:
            value = self.packets.pop(0)
            if isinstance(value, Exception):
                raise value
            return value
        self.quiet.wait(0.01)
        raise socket.timeout()

    def close(self):
        self.closed = True
        self.quiet.set()


def packet(sequence=0, pid=12, tid=34, stage=1, result=-7, nonce=NONCE):
    return struct.pack("!4s16sIIIIiQ", b"ITR1", nonce, sequence, pid, tid, stage, result, 123456)


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not MODULE.exists():
            raise AssertionError("The private runtime receiver has not been implemented")
        spec = importlib.util.spec_from_file_location("vita_runtime", MODULE)
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)

    def setUp(self):
        self.stream = io.StringIO()
        self.log = self.m.RuntimeLog(NONCE, self.stream)

    def test_scalar_packet_is_decoded_without_application_data(self):
        self.assertTrue(self.log.accept(packet(), ("192.168.1.146", 12345)))
        row = json.loads(self.stream.getvalue())
        self.assertEqual(row["stage"], "connect.enter")
        self.assertEqual((row["pid"], row["tid"], row["result"], row["sequence"], row["device_us"]),
                         (12, 34, -7, 0, 123456))
        self.assertEqual(self.log.accepted, 1)

    def test_wrong_peer_nonce_size_and_magic_are_not_saved(self):
        bad = [(packet(), "192.168.1.1"), (packet(nonce=b"x" * 16), "192.168.1.146"),
               (packet()[:-1], "192.168.1.146"), (b"NOPE" + packet()[4:], "192.168.1.146")]
        for data, peer in bad:
            self.assertFalse(self.log.accept(data, (peer, 5)))
        self.assertEqual(self.stream.getvalue(), "")
        self.assertEqual(self.log.rejected, 4)

    def test_out_of_order_is_preserved_but_duplicate_is_not(self):
        for number in (2, 0, 1):
            self.assertTrue(self.log.accept(packet(sequence=number), ("192.168.1.146", 5)))
        self.assertFalse(self.log.accept(packet(sequence=1), ("192.168.1.146", 5)))
        self.assertEqual([json.loads(line)["sequence"] for line in self.stream.getvalue().splitlines()], [2, 0, 1])
        self.assertEqual(self.log.duplicates, 1)

    def test_invalid_fields_do_not_expand_saved_state(self):
        for values in ({"pid": 0}, {"tid": 0}, {"pid": 0xffffffff}, {"stage": 0},
                       {"stage": 39}, {"sequence": 128}):
            self.assertFalse(self.log.accept(packet(**values), ("192.168.1.146", 5)))
        self.assertEqual(self.log.accepted, 0)
        self.assertEqual(self.stream.getvalue(), "")

    def test_legacy_reason_stages_append_without_changing_existing_ids(self):
        self.assertEqual(self.m.STAGES[33], "check.return")
        for sequence, stage, result in ((0, 35, 680), (1, 36, 1)):
            self.assertTrue(self.log.accept(packet(sequence=sequence, stage=stage, result=result),
                                            ("192.168.1.146", 12345)))
        rows = [json.loads(line) for line in self.stream.getvalue().splitlines()]
        self.assertEqual([(row["stage"], row["result"]) for row in rows],
                         [("legacy.option", 680), ("legacy.value", 1)])

    def test_callback_reason_stages_preserve_existing_wire_ids(self):
        for sequence, stage, result in ((0, 37, 9), (1, 38, 4)):
            self.assertTrue(self.log.accept(packet(sequence=sequence, stage=stage, result=result),
                                            ("192.168.1.146", 12345)))
        rows = [json.loads(line) for line in self.stream.getvalue().splitlines()]
        self.assertEqual([(row["stage"], row["result"]) for row in rows],
                         [("callback.reject", 9), ("callback.policy", 4)])

    def test_packet_and_process_caps_are_explicit(self):
        self.log = self.m.RuntimeLog(NONCE, self.stream, max_records=2, max_processes=1)
        self.assertTrue(self.log.accept(packet(), ("192.168.1.146", 5)))
        self.assertFalse(self.log.accept(packet(pid=13), ("192.168.1.146", 5)))
        self.assertTrue(self.log.accept(packet(sequence=1), ("192.168.1.146", 5)))
        self.assertFalse(self.log.accept(packet(sequence=2), ("192.168.1.146", 5)))
        self.assertTrue(self.log.summary()["at_limit"])
        self.assertEqual(self.log.accepted, 2)

    def test_endpoint_rejects_public_or_unpinned_sources(self):
        endpoint = {"host": "192.168.1.249", "port": 52154, "nonce": NONCE.hex(),
                    "expected_peer": "192.168.1.146"}
        self.assertEqual(self.m.validate_endpoint(endpoint)["nonce"], NONCE.hex())
        for change in ({"host": "8.8.8.8"}, {"host": "127.0.0.1"}, {"port": 80},
                       {"port": True}, {"nonce": "0" * 31}, {"expected_peer": "192.168.1.250"}):
            with self.assertRaises(ValueError):
                self.m.validate_endpoint(dict(endpoint, **change))

    def test_wire_stage_names_match_the_c_header(self):
        header = (MODULE.parents[1] / "tls13/browser/runtime_udp.h").read_text()
        names = re.findall(r"\bTLS_FIXER_RT_([A-Z_]+)\b", header.split("enum TlsFixerRuntimeStage {")[1].split("};")[0])
        names = [name.lower().replace("_", ".") for name in names if name != "STAGE_LIMIT"]
        self.assertEqual(names, list(self.m.STAGES))
        self.assertEqual(self.m.PACKET.size, 48)

    def test_receiver_binds_before_use_and_joins_on_exit(self):
        endpoint = {"host": "192.168.1.249", "port": 52154, "nonce": NONCE.hex(), "expected_peer": "192.168.1.146"}
        transport = FakeSocket([(packet(), ("192.168.1.146", 5))])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runtime.jsonl"
            with self.m.RuntimeCapture(endpoint, output, duration=0.05,
                                       socket_factory=lambda *args: transport) as capture:
                self.assertEqual(transport.bound, (endpoint["host"], endpoint["port"]))
                capture.stop_event.wait(1)
            self.assertFalse(capture.worker.is_alive())
            self.assertTrue(transport.closed)
            self.assertTrue(capture.stream.closed)
            self.assertEqual(capture.summary["accepted"], 1)
            self.assertTrue(capture.summary["complete"])
            self.assertEqual(json.loads(output.read_text())["stage"], "connect.enter")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_receiver_bind_failure_preserves_no_partial_capture(self):
        endpoint = {"host": "192.168.1.249", "port": 52154, "nonce": NONCE.hex(), "expected_peer": "192.168.1.146"}
        transport = FakeSocket(bind_failure=True)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runtime.jsonl"
            with self.assertRaises(OSError):
                with self.m.RuntimeCapture(endpoint, output, socket_factory=lambda *args: transport):
                    self.fail("A failed bind must not reach the controlled browser launch")
            self.assertFalse(output.exists())
            self.assertTrue(transport.closed)

    def test_receiver_preserves_packets_when_receive_fails(self):
        endpoint = {"host": "192.168.1.249", "port": 52154, "nonce": NONCE.hex(), "expected_peer": "192.168.1.146"}
        transport = FakeSocket([(packet(), ("192.168.1.146", 5)), OSError("receiver failure")])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runtime.jsonl"
            with self.m.RuntimeCapture(endpoint, output, socket_factory=lambda *args: transport) as capture:
                capture.stop_event.wait(1)
            self.assertFalse(capture.summary["complete"])
            self.assertEqual(capture.summary["accepted"], 1)
            self.assertIn("receiver failure", capture.summary["error"])
            self.assertEqual(len(output.read_text().splitlines()), 1)

    def test_receiver_refuses_overwriting_previous_data(self):
        endpoint = {"host": "192.168.1.249", "port": 52154, "nonce": NONCE.hex(), "expected_peer": "192.168.1.146"}
        transport = FakeSocket()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runtime.jsonl"
            output.write_text("previous evidence")
            with self.assertRaises(FileExistsError):
                with self.m.RuntimeCapture(endpoint, output, socket_factory=lambda *args: transport):
                    pass
            self.assertEqual(output.read_text(), "previous evidence")
            self.assertTrue(transport.closed)


if __name__ == "__main__":
    unittest.main()
