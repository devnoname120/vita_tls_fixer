#!/bin/sh
set -eu

cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
receipt=build/passthrough-control-user-armed.json
if [ -e "$receipt" ]; then
    printf '%s\n' 'This selected test already has an arming receipt. Review its result and select a new test before iterating.' >&2
    exit 2
fi
if ! mkdir build/.iterate.lock 2>/dev/null; then
    printf '%s\n' 'An iteration is already running, or its lock requires review.' >&2
    exit 2
fi
trap 'rmdir build/.iterate.lock' 0
trap 'exit 130' INT
trap 'exit 143' TERM

python3 tools/vita_tls_cycle.py run \
    --stage build/stage_passthrough_control_files_only.py \
    --arm build/arm_passthrough_control_once.py \
    --receipt "$receipt" \
    --browser-title-id NPXS10003 \
    --settle-seconds 30
