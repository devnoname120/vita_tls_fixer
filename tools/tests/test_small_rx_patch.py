"""The receive-buffer patch must fail closed on a different dependency tree."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
CRYPTO=ROOT/'tls13/crypto'


class SmallReceivePatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archive=ROOT/'build/deps/mbedtls-4.2.0.tar.bz2'
        if not archive.exists():
            raise unittest.SkipTest('Fetch the checksum-pinned Mbed TLS archive first')
        manifests=[json.loads((CRYPTO/'patches'/name).read_text())
                   for name in ('rsa-client-4.2.json','small-rx-4.2.json')]
        cls.manifest=manifests[1]
        cls.sources={}
        with tarfile.open(archive) as source:
            for name in manifests[0].keys() | manifests[1].keys():
                members=[m for m in source.getmembers() if m.name=='mbedtls-4.2.0/'+name]
                if len(members)!=1:
                    raise AssertionError(name)
                cls.sources[name]=source.extractfile(members[0]).read()

    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source=Path(self.temporary.name)
        for name,data in self.sources.items():
            path=self.source/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(data)
        self.apply('apply_rsa_client.py',True)

    def apply(self,script,success):
        result=subprocess.run([sys.executable,str(CRYPTO/script),str(self.source)],
                              capture_output=True,text=True)
        self.assertEqual(result.returncode==0,success,result.stdout+result.stderr)

    def digest(self):
        return {name:hashlib.sha256((self.source/name).read_bytes()).hexdigest()
                for name in self.manifest}

    def test_pinned_patch_and_second_application(self):
        self.assertEqual(self.digest(),{n:v['before'] for n,v in self.manifest.items()})
        self.apply('apply_small_rx.py',True)
        self.assertEqual(self.digest(),{n:v['after'] for n,v in self.manifest.items()})
        self.apply('apply_small_rx.py',True)
        self.assertEqual(self.digest(),{n:v['after'] for n,v in self.manifest.items()})

    def test_unknown_source_is_untouched(self):
        path=self.source/'library/ssl_msg.c'
        path.write_bytes(path.read_bytes()+b'\n/* different source */\n')
        before=self.digest()
        self.apply('apply_small_rx.py',False)
        self.assertEqual(self.digest(),before)

    def test_partial_patch_is_untouched(self):
        original=(self.source/'library/ssl_misc.h').read_bytes()
        self.apply('apply_small_rx.py',True)
        (self.source/'library/ssl_misc.h').write_bytes(original)
        before=self.digest()
        self.apply('apply_small_rx.py',False)
        self.assertEqual(self.digest(),before)


if __name__=='__main__':
    unittest.main()
