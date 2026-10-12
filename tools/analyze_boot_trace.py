#!/usr/bin/env python3

"""Analyze saved tls_fixer startup records without interpreting them as a boot result."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys


MAX_RECORDS = 512
MAX_RECORD_BYTES = 512
MAX_PATH_BYTES = 128
MAX_TRACE_BYTES = MAX_RECORDS * MAX_RECORD_BYTES
RESULT_FIELDS = {"load.return": "obj", "hook.return": "obj"}
RECORD = re.compile(
    rb"tls_fixer-trace1 seq=(?P<seq>[0-9a-f]{8}) tid=(?P<tid>[0-9a-f]{8}) "
    rb"pid=(?P<pid>[0-9a-f]{8}) obj=(?P<obj>[0-9a-f]{8}) "
    rb"rc=(?P<rc>[0-9a-f]{8}) sp=(?P<sp>[0-9a-f]{8})"
    rb"(?: free=(?P<free>[0-9a-f]{8}))? us=(?P<us>[0-9a-f]{16}) "
    rb"stage=(?P<stage>[a-z0-9._]{1,31})"
    rb"(?: pathlen=(?P<pathlen>[0-9a-f]{8}) path=(?P<path>[0-9a-f]{0,256}))?\n"
)


def analyze_trace(data: bytes) -> dict[str, object]:
    if not isinstance(data, bytes):
        raise TypeError("Trace input must be bytes")
    if not data or len(data) > MAX_TRACE_BYTES:
        raise ValueError("Empty or oversized trace")

    events = []
    module_paths = []
    end = data.rfind(b"\n") + 1
    tail = data[end:]
    if len(tail) >= MAX_RECORD_BYTES:
        raise ValueError("Incomplete record exceeds the recorder's size limit")
    for line_number, line in enumerate(data[:end].splitlines(keepends=True), 1):
        match = RECORD.fullmatch(line)
        if match is None or len(line) > MAX_RECORD_BYTES:
            raise ValueError(f"Invalid record on line {line_number}")
        fields = match.groupdict()
        item = {key: int(value, 16) if value is not None else None
                for key, value in fields.items() if key not in ("stage", "path", "pathlen")}
        item["stage"] = fields["stage"].decode("ascii")
        if fields["pathlen"] is not None:
            length = int(fields["pathlen"], 16)
            encoded = fields["path"].decode("ascii")
            captured = bytes.fromhex(encoded)
            expected = 0 if length == 0xffffffff else min(length, MAX_PATH_BYTES)
            if (length > 1024 and length != 0xffffffff) or len(captured) != expected:
                raise ValueError(f"Inconsistent path length on line {line_number}")
            module_paths.append({
                "sequence": item["seq"], "thread_id": item["tid"], "pid": item["pid"],
                "stage": item["stage"], "route_kind": item["obj"], "flags": item["rc"],
                "reported_length": None if length == 0xffffffff else length,
                "path_hex": None if length == 0xffffffff else encoded,
                "path": None if length == 0xffffffff else captured.decode("ascii", "backslashreplace"),
                "truncated": length != 0xffffffff and length > len(captured),
                "length_is_lower_bound": length == 1024,
            })
        elif len(line) > 192:
            raise ValueError(f"Oversized scalar record on line {line_number}")
        if item["seq"] != len(events) or len(events) >= MAX_RECORDS:
            raise ValueError(f"Noncontiguous or excessive record sequence on line {line_number}")
        if events and item["us"] < events[-1]["us"]:
            raise ValueError(f"Nonmonotonic time on line {line_number}")
        events.append(item)
    if not events:
        raise ValueError("Trace contains no complete records")

    pending = defaultdict(list)
    completed = []
    unmatched = []
    negative = []
    stack_returns = []
    threads = {}
    for item in events:
        tid = item["tid"]
        thread = threads.setdefault(tid, {
            "thread_id": tid, "records": 0, "minimum_positive_headroom_bytes": None,
            "zero_headroom_samples": 0, "missing_headroom_samples": 0,
            "unavailable_headroom_samples": 0, "last_event": None,
        })
        thread["records"] += 1
        thread["last_event"] = item
        free = item["free"]
        if free is None:
            thread["missing_headroom_samples"] += 1
        elif free == 0:
            thread["zero_headroom_samples"] += 1
        elif free == 0xffffffff:
            thread["unavailable_headroom_samples"] += 1
        else:
            previous = thread["minimum_positive_headroom_bytes"]
            thread["minimum_positive_headroom_bytes"] = free if previous is None else min(previous, free)

        operation, _, suffix = item["stage"].rpartition(".")
        key = (tid, operation)
        if suffix == "enter":
            pending[key].append(item)
        elif suffix in ("return", "failed"):
            result_field = RESULT_FIELDS.get(item["stage"], "rc")
            result = item[result_field]
            if result & 0x80000000:
                negative.append({**item, "result": result, "result_field": result_field,
                                 "signed_result": result - 0x100000000})
            if not pending[key]:
                if item["stage"] != "hook.return":
                    unmatched.append(item)
                continue
            start = pending[key].pop()
            interval = {
                "operation": operation, "thread_id": tid,
                "enter_sequence": start["seq"], "return_sequence": item["seq"],
                "duration_us": item["us"] - start["us"],
                "return_stage": item["stage"], "result": result, "result_field": result_field,
            }
            completed.append(interval)
            if operation == "stack.extend":
                stack_returns.append({**interval, "enter_sp": start["sp"], "return_sp": item["sp"],
                                      "same_sampled_sp": start["sp"] == item["sp"]})

    opened = [{"thread_id": tid, "operation": operation, "enter_event": item}
              for (tid, operation), entries in pending.items() for item in entries]
    opened.sort(key=lambda item: item["enter_event"]["seq"])
    return {
        "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "records": len(events),
        "trailing_partial_bytes": len(tail), "trailing_partial_hex": tail.hex(),
        "record_limit_reached": len(events) == MAX_RECORDS,
        "boot_outcome": "not established by trace",
        "duration_us": events[-1]["us"] - events[0]["us"],
        "stage_counts": dict(sorted(Counter(item["stage"] for item in events).items())),
        "last_event": events[-1], "threads": list(threads.values()),
        "completed_operations": completed, "open_operations": opened,
        "unmatched_returns": unmatched, "negative_return_codes": negative,
        "native_stack_returns": stack_returns, "module_paths": module_paths,
        "interpretation_limits": [
            "A returned marker precedes the hook or function epilogue; it is not a fault address.",
            "An unclosed interval may reflect logging failure or a partial trace, not a hung call.",
            "Durations include synchronous diagnostic I/O and are not uninstrumented performance.",
            "Headroom values are point samples, not high-water measurements; zero can mean invalid context.",
            "The log does not identify a build or final boot outcome without independent evidence.",
            "Module-path capture is bounded; a truncated path or saturated log cannot establish absence.",
            "load.return and hook.return put native results in obj, not rc; both may record the same failure.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="An already saved tls_fixer-startup.log")
    args = parser.parse_args()
    try:
        with args.trace.open("rb") as stream:
            result = analyze_trace(stream.read(MAX_TRACE_BYTES + 1))
    except (OSError, ValueError) as exc:
        print(f"Trace analysis failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
