#!/usr/bin/env python3
"""Verify the isolated embedded HTTP test's protocol and lifecycle evidence."""
import argparse
import json
from pathlib import Path
import re


def verify(text, shared):
    assert text.endswith('end passed=1\n'), 'incomplete or failed test'
    assert f'begin module control shared={int(shared)} tls=1;' in text
    assert 'embedded.library rc=00000000 nid=7F10B001' in text
    for index in range(3):
        assert f'tls.send.return index={index} rc=00000000 http=200' in text
    assert re.search(r'tls.body index=1[^\n]*trace_tls13=1', text)
    assert 'creates=3 fallbacks=0 callbacks=1' in text
    assert 'tls.http.term=00000000 state=0 error=00000000 capacity=0 used=0' in text
    assert text.count('embedded.marker version=2 state=0 error=00000000 capacity=0 used=0') == 2
    assert 'stop.return rc=00000000 result=00000000' in text
    assert 'final_stop rc=00000000 result=00000000' in text
    names = re.findall(r'tls.retained_name digest=([0-9A-F]+) expected=\1 release=([01])', text)
    assert len(names) == 2 and names[0][0] == names[1][0] and [v[1] for v in names] == ['0', '1']
    assert 'tls.ssl.term=00000000' in text
    addresses = [int(s, 16) for s in re.findall(r'segment=0 base=([0-9A-F]+)', text)]
    assert len(addresses) == 2 and all((a >= 0xe0000000) == shared for a in addresses)
    peak = int(re.search(r'tls.backend.final[^\n]*peak=(\d+)', text)[1])
    return {'passed': True, 'shared': shared, 'tls12': True, 'tls13': True,
            'full_verification': 'tls.verify.enable=00000000 flags=0000003D' in text,
            'native_fallbacks': 0, 'heap_peak': peak, 'heap_released': True,
            'retained_name_survives_http_unload_reload': True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('log', type=Path)
    p.add_argument('output', type=Path)
    p.add_argument('--shared', action='store_true')
    args = p.parse_args()
    result = verify(args.log.read_text(), args.shared)
    assert result['full_verification']
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
