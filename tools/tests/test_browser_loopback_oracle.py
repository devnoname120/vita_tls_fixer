from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import ssl
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tls13/tests/browser"))
from run_browser_loopback import certificates, run_case


class BrowserLoopbackOracleTests(unittest.TestCase):
    def test_negative_case_does_not_suppress_pre_wire_assertion(self):
        with tempfile.TemporaryDirectory(prefix="tls_fixer-oracle-") as temporary:
            directory = Path(temporary)
            certificates(directory)
            client = directory / "invalid-client"
            client.write_text(
                "#!/usr/bin/env python3\n"
                "import socket, sys\n"
                "with socket.create_connection(('127.0.0.1', int(sys.argv[2]))) as sock:\n"
                "    sock.sendall(b'unexpected provider bytes')\n"
            )
            client.chmod(0o700)
            with redirect_stdout(StringIO()), self.assertRaisesRegex(
                AssertionError, "legacy fallback sent provider data"
            ):
                run_case(client, directory, "legacy-callback", ssl.TLSVersion.TLSv1_3)


if __name__ == "__main__":
    unittest.main()
