import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "analyze_boot_trace", Path(__file__).resolve().parents[1] / "analyze_boot_trace.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def event(seq, stage, *, tid=1, pid=2, obj=3, rc=0, sp=0x1000, free=None, us=None):
    headroom = "" if free is None else f" free={free:08x}"
    return (f"tls_fixer-trace1 seq={seq:08x} tid={tid:08x} pid={pid:08x} obj={obj:08x} "
            f"rc={rc & 0xffffffff:08x} sp={sp:08x}{headroom} "
            f"us={(seq * 10 if us is None else us):016x} stage={stage}\n").encode("ascii")


class BootTraceAnalysisTests(unittest.TestCase):
    def test_module_paths_remain_data_not_forged_records(self):
        path = b"opaque:/webcore/ScePsp2Compat.suprx\n \xff"
        first = event(0, "load.enter", rc=0x1000)[:-1]
        first += f" pathlen={len(path):08x} path={path.hex()}\n".encode("ascii")
        result = module.analyze_trace(first + event(1, "load.return", obj=88))
        observation = result["module_paths"][0]
        self.assertEqual(observation["path_hex"], path.hex())
        self.assertFalse(observation["truncated"])
        self.assertEqual(result["records"], 2)
        self.assertEqual(result["boot_outcome"], "not established by trace")

    def test_module_path_truncation_and_null_are_explicit(self):
        prefix = (b"x" * 128).hex()
        data = event(0, "load.enter")[:-1] + f" pathlen=000000c8 path={prefix}\n".encode("ascii")
        data += event(1, "load.enter")[:-1] + b" pathlen=ffffffff path=\n"
        observations = module.analyze_trace(data)["module_paths"]
        self.assertTrue(observations[0]["truncated"])
        self.assertEqual(observations[0]["reported_length"], 200)
        self.assertIsNone(observations[1]["path_hex"])

    def test_module_path_lengths_must_match_encoding(self):
        for suffix in [b" pathlen=00000002 path=61\n", b" pathlen=ffffffff path=61\n",
                       b" pathlen=00000001 path=f\n", b" pathlen=00000001 path=zz\n"]:
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                module.analyze_trace(event(0, "load.enter")[:-1] + suffix)

    def test_accepts_both_record_layouts_without_claiming_boot_success(self):
        result = module.analyze_trace(event(0, "trace.open") + event(1, "hook.return", free=3000))
        self.assertEqual(result.get("records"), 2)
        self.assertEqual(result["last_event"]["stage"], "hook.return")
        self.assertEqual(result["boot_outcome"], "not established by trace")
        self.assertEqual(result["threads"][0]["minimum_positive_headroom_bytes"], 3000)
        self.assertEqual(result["threads"][0]["missing_headroom_samples"], 1)

    def test_partial_tail_is_retained_not_mistaken_for_completed_operation(self):
        tail = event(1, "prepare.return")[:-12]
        result = module.analyze_trace(event(0, "prepare.enter") + tail)
        self.assertEqual(result["records"], 1)
        self.assertEqual(result["trailing_partial_bytes"], len(tail))
        self.assertEqual(result["trailing_partial_hex"], tail.hex())
        self.assertEqual(result["open_operations"][0]["operation"], "prepare")
        self.assertEqual(result["completed_operations"], [])

    def test_empty_invalid_and_noncontiguous_records_are_rejected(self):
        invalid = [b"", b"anything\n", event(1, "trace.open"),
                   event(0, "trace.open") + event(0, "trace.open"),
                   event(0, "trace.open") + event(2, "load.enter"),
                   event(0, "bad-stage"), event(0, "a" * 32)]
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(ValueError):
                module.analyze_trace(data)

    def test_backwards_time_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "time"):
            module.analyze_trace(event(0, "a.enter", us=100) + event(1, "a.return", us=99))

    def test_pairs_calls_by_thread_and_nesting_not_object_value(self):
        data = b"".join([event(0, "scan.enter", tid=1, obj=1),
                         event(1, "scan.enter", tid=2),
                         event(2, "scan.enter", tid=1),
                         event(3, "scan.return", tid=1),
                         event(4, "scan.return", tid=2),
                         event(5, "scan.return", tid=1, obj=99)])
        result = module.analyze_trace(data)
        pairs = [(x["enter_sequence"], x["return_sequence"], x["duration_us"])
                 for x in result["completed_operations"]]
        self.assertEqual(pairs, [(2, 3, 10), (1, 4, 30), (0, 5, 50)])
        self.assertEqual(result["open_operations"], [])

    def test_zero_headroom_is_not_reported_as_proven_overflow(self):
        result = module.analyze_trace(event(0, "a.enter", free=0) + event(1, "a.return", free=512))
        thread = result["threads"][0]
        self.assertEqual(thread["zero_headroom_samples"], 1)
        self.assertEqual(thread["minimum_positive_headroom_bytes"], 512)

    def test_negative_enter_sentinel_is_not_a_negative_return(self):
        result = module.analyze_trace(event(0, "query.free.enter", rc=-1)
                                      + event(1, "query.free.return", rc=0)
                                      + event(2, "reserve.enter") + event(3, "reserve.failed", rc=-5))
        self.assertEqual(len(result["negative_return_codes"]), 1)
        self.assertEqual(result["negative_return_codes"][0]["signed_result"], -5)
        self.assertEqual(result["open_operations"], [])

    def test_loader_interval_reports_native_module_id_not_route_kind(self):
        result = module.analyze_trace(event(0, "load.enter", obj=3, rc=0x1000)
                                      + event(1, "load.return", obj=0x40010267, rc=3))
        interval = result["completed_operations"][0]
        self.assertEqual(interval["result"], 0x40010267)
        self.assertEqual(interval["result_field"], "obj")
        self.assertEqual(result["negative_return_codes"], [])
        self.assertEqual(result["last_event"]["rc"], 3)

    def test_loader_and_hook_failures_are_not_hidden_by_positive_route_kind(self):
        error = 0x80010002
        result = module.analyze_trace(event(0, "load.enter", obj=3, rc=0x1000)
                                      + event(1, "load.return", obj=error, rc=3)
                                      + event(2, "hook.return", obj=error, rc=3))
        failures = result["negative_return_codes"]
        self.assertEqual([item["stage"] for item in failures], ["load.return", "hook.return"])
        for item in failures:
            self.assertEqual(item["signed_result"], error - 0x100000000)
            self.assertEqual(item["result"], error)
            self.assertEqual(item["result_field"], "obj")
            self.assertEqual(item["rc"], 3)
        self.assertEqual(result["completed_operations"][0]["result"], error)
        self.assertEqual(len(result["completed_operations"]), 1)
        self.assertEqual(result["unmatched_returns"], [])

    def test_loader_zero_result_is_not_replaced_with_route_kind(self):
        result = module.analyze_trace(event(0, "load.enter", obj=1)
                                      + event(1, "load.return", obj=0, rc=1))
        self.assertEqual(result["completed_operations"][0]["result"], 0)
        self.assertEqual(result["negative_return_codes"], [])

    def test_other_operations_keep_rc_semantics_even_with_high_bit_object(self):
        result = module.analyze_trace(event(0, "module.info.enter", obj=0x80001000)
                                      + event(1, "module.info.return", obj=0x80001000, rc=0)
                                      + event(2, "prepare.enter", obj=0x40010267)
                                      + event(3, "prepare.return", obj=0x40010267, rc=-5))
        intervals = result["completed_operations"]
        self.assertEqual([item["result"] for item in intervals], [0, 0xfffffffb])
        self.assertEqual([item["result_field"] for item in intervals], ["rc", "rc"])
        self.assertEqual(len(result["negative_return_codes"]), 1)
        failure = result["negative_return_codes"][0]
        self.assertEqual(failure["stage"], "prepare.return")
        self.assertEqual(failure["result_field"], "rc")
        self.assertEqual(failure["signed_result"], -5)

    def test_native_stack_return_records_only_observed_sp_equality(self):
        result = module.analyze_trace(event(0, "stack.extend.enter", sp=0x1000)
                                      + event(1, "stack.callback.enter", sp=0x9000)
                                      + event(2, "stack.callback.return", sp=0x9000)
                                      + event(3, "stack.extend.return", sp=0x1000))
        self.assertTrue(result["native_stack_returns"][0]["same_sampled_sp"])
        self.assertEqual(result["boot_outcome"], "not established by trace")

    def test_skipped_queries_remain_distinct_from_executed_queries(self):
        result = module.analyze_trace(event(0, "scan.skipped") + event(1, "target.skipped"))
        self.assertEqual(result["stage_counts"]["scan.skipped"], 1)
        self.assertNotIn("module.list.enter", result["stage_counts"])

    def test_limit_and_unmatched_return_are_not_reported_as_completion(self):
        result = module.analyze_trace(b"".join(event(i, "hook.return") for i in range(512)))
        self.assertTrue(result["record_limit_reached"])
        self.assertEqual(result["completed_operations"], [])
        with self.assertRaises(ValueError):
            module.analyze_trace(b"".join(event(i, "hook.return") for i in range(513)))
        result = module.analyze_trace(event(0, "prepare.return"))
        self.assertEqual(result["unmatched_returns"][0]["stage"], "prepare.return")


if __name__ == "__main__":
    unittest.main()
