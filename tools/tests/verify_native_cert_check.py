#!/usr/bin/env python3
"""Verify fixture metadata and retained-name bytes, not merely API return codes."""
import argparse
import json
from pathlib import Path
import re


def verify(log, expected):
    assert log.endswith('end passed=1\n'), 'diagnostic did not finish successfully'
    fixtures = {row['file'][:-4]: row for row in expected}
    labels = {'2.5.4.3': 'commonName', '2.5.4.10': 'organizationName',
              '2.5.4.11': 'organizationalUnitName'}
    rows, seen, pools = [], set(), []
    for block in log.split('cert.begin fixture=')[1:]:
        name, rest = block.split(' ', 1)
        round_number = int(re.search(r'round=(\d+)', rest)[1])
        key = name, round_number
        assert key not in seen and name in fixtures, 'unexpected or duplicate fixture'
        seen.add(key)
        expected = fixtures[name]
        assert 'cert.convert=00000000 count=1 facade=1\n' in block, key
        assert f'cert.serial={expected["serial"]}\n' in block, key
        times = (f'cert.time before={expected["not_before_tick"]} after={expected["not_after_tick"]}'
                 ' rc_before=00000000 rc_after=00000000\n')
        assert times in block, key
        for kind in (0, 1):
            assert f'cert.name kind={kind} count={len(expected["name_entries"])} after_release=1\n' in block, key
            for i, entry in enumerate(expected['name_entries']):
                line = (f'cert.name.entry kind={kind} index={i} oid={labels[entry["oid"]]}'
                        f' value={entry["value_hex"]}\n')
                assert line in block, (key, 'retained name bytes do not match', kind, i)
        pool = re.search(r'cert.pool round=\d+ fixture=\S+ current=(\d+) peak=(\d+)', block)
        assert pool, key
        pools.append(int(pool[1]))
        rows.append({'fixture': name, 'round': round_number, 'metadata_matches': True,
                     'names_survive_source_overwrite_and_context_release': True,
                     'ssl_heap_current': int(pool[1]), 'ssl_heap_peak': int(pool[2])})
    assert seen == {(name, i) for name in fixtures for i in (0, 1)}, 'missing fixture/round'
    assert len(set(pools)) == 1, 'SSL heap use grew between fixture checks'
    return {'passed': True, 'cases': rows, 'ssl_heap_current_stable': pools[0],
            'scope': 'certificate metadata facade and native name ownership; no TLS handshake'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('log', type=Path)
    p.add_argument('expected', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    result = verify(args.log.read_text(), json.loads(args.expected.read_text()))
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f"{len(result['cases'])} certificate metadata/ownership cases passed; stable SSL heap use {result['ssl_heap_current_stable']} bytes")


if __name__ == '__main__':
    main()
