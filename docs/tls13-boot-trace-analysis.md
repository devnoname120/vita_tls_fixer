# Offline startup-trace analysis

Analyze a saved copy of `ur0:tai/tls_fixer-startup.log` with:

```sh
python3 tools/analyze_boot_trace.py /path/to/tls_fixer-startup.log > analysis.json
```

The analyzer only reads the supplied local file. It does not contact a Vita,
modify a configuration, load a module, or request a reboot. Keep its output and
the original bytes with the relevant device receipt; neither belongs in the
two-file diagnostic download.

## What is checked

Complete records must match the recorder's exact field layout, have contiguous
sequence numbers beginning at zero, and contain nondecreasing timestamps. Both
the original layout and the optional `free=` layout are accepted. The input and
record count are bounded by the recorder's 512-record/192-byte limits. Invalid
complete records cause an error and a nonzero exit status rather than being
silently skipped.

An incomplete final record is retained as a byte count and hexadecimal data.
It never completes an operation. Enter/return pairs are matched by thread and
operation, with separate nested instances; object values are not required to
match because native return records can deliberately change their meaning.
Unclosed calls and unmatched return records are reported separately.

Output includes the input digest, stage counts, last complete event, per-thread
headroom samples, observed operation intervals, negative return-code records,
and stack-extension entry/return SP comparisons. `scan.skipped` and
`target.skipped` remain distinct from actual query calls. A negative value on an
entry event can be a sentinel, so it is not classified as a negative return.

## Interpretation limits

`hook.return` is written before the native hook epilogue. It is not evidence
that the epilogue or subsequent caller completed, and it is not a fault PC.
Similarly, an unclosed operation may be caused by logger failure, truncation,
or the record limit rather than a hung native call.

Interval durations include synchronous logging and filesystem synchronization.
Headroom values are point samples, not stack high-water measurements. Zero can
mean an invalid/out-of-range context; `ffffffff` is an unavailable measurement,
not nearly 4 GiB of free kernel stack. SP equality establishes only the equality
of the recorded samples, not correctness of every restored register.

The analyzer intentionally does not infer whether the Vita reached LiveArea or
which binary produced the log. Pair the capture with its actual test identity,
configuration/report reads, and the user's first-boot observation. A currently
installed kernel and a generic completed report alone do not identify the
producer of an older log.
