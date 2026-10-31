#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from firmware_matrix import bundled_module
module=bundled_module(Path(__file__).resolve().parents[2]/'misc/lssl.suprx')
with tempfile.TemporaryDirectory(prefix='tls-fixer-ssl-pool-') as temporary:
    path=Path(temporary)/'ssl-text.bin';path.write_bytes(module.text)
    subprocess.run([sys.argv[1],str(path)],check=True)
