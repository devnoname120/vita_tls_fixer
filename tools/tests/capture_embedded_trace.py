#!/usr/bin/env python3
"""Receive an explicitly selected embedded diagnostic session from the primary Vita."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vita_runtime import validate_endpoint


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('endpoint', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--duration', type=float, default=90)
    args = parser.parse_args()
    endpoint = validate_endpoint(json.loads(args.endpoint.read_text()))
    if not 0 < args.duration <= 600:
        parser.error('Duration must be between zero and 600 seconds')
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    summary_path = args.output.with_suffix('.summary.json')
    if args.output.exists() or summary_path.exists():
        raise FileExistsError('Preserve the previous capture')
    prefix = ('ETF1 ' + endpoint['nonce'] + ' ').encode()
    header = re.compile(rb'seq=(\d+) pid=([0-9A-F]{8}) tid=([0-9A-F]{8}) t=(\d+) dropped=(\d+) ')
    accepted = rejected = 0
    ending = 'deadline'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512 * 1024)
        receiver.bind((endpoint['host'], endpoint['port']))
        receiver.settimeout(.5)
        with args.output.open('x', encoding='utf-8') as stream:
            os.chmod(args.output, 0o600)
            print(json.dumps({'ready': True, 'host': endpoint['host'], 'port': endpoint['port'],
                              'pid': os.getpid(), 'duration': args.duration}), flush=True)
            deadline = time.monotonic() + args.duration
            try:
                while time.monotonic() < deadline and accepted < 32768:
                    try:
                        data, peer = receiver.recvfrom(513)
                    except socket.timeout:
                        continue
                    match = header.match(data[len(prefix):]) if data.startswith(prefix) else None
                    if peer[0] != endpoint['expected_peer'] or len(data) > 512 or match is None:
                        rejected += 1
                        continue
                    sequence, pid, tid, timestamp, dropped = match.groups()
                    row = {'received': time.time(), 'sequence': int(sequence), 'pid': int(pid, 16),
                           'tid': int(tid, 16), 'device_us': int(timestamp), 'dropped': int(dropped),
                           'message': data[len(prefix) + match.end():].decode('utf-8', errors='replace').rstrip('\n')}
                    stream.write(json.dumps(row) + '\n')
                    stream.flush()
                    accepted += 1
            except KeyboardInterrupt:
                ending = 'interrupted'
    summary = {'accepted': accepted, 'rejected': rejected, 'ending': ending,
               'interpretation': 'UDP may lose or reorder messages; absence is not proof of non-execution.'}
    summary_path.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
