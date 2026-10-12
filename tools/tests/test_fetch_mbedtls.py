import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fetch_mbedtls as dependency


class FetchMbedTlsTests(unittest.TestCase):
    payload = b"fixture release archive"
    digest = hashlib.sha256(payload).hexdigest()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cache = Path(self.directory.name).resolve()
        self.sha_patch = patch.object(dependency, "ARCHIVE_SHA256", self.digest)
        self.sha_patch.start()
        self.addCleanup(self.sha_patch.stop)

    def download_valid(self, destination):
        destination.write_bytes(self.payload)

    def test_valid_cached_archive_never_downloaded(self):
        archive = self.cache / dependency.ARCHIVE_NAME
        archive.write_bytes(self.payload)
        with patch.object(dependency, "download_archive") as download:
            self.assertEqual(dependency.ensure_archive(self.cache), archive.resolve())
        download.assert_not_called()

    def test_corrupt_cached_archive_is_rejected_without_overwrite(self):
        archive = self.cache / dependency.ARCHIVE_NAME
        archive.write_bytes(b"corrupt")
        with patch.object(dependency, "download_archive") as download:
            with self.assertRaisesRegex(dependency.DependencyError, "SHA-256"):
                dependency.ensure_archive(self.cache)
        download.assert_not_called()
        self.assertEqual(archive.read_bytes(), b"corrupt")

    def test_new_download_verified_before_publication(self):
        with patch.object(dependency, "download_archive", self.download_valid):
            archive = dependency.ensure_archive(self.cache)
        self.assertEqual(archive.read_bytes(), self.payload)
        self.assertEqual(list(self.cache.iterdir()), [archive])

    def test_invalid_download_never_published(self):
        with patch.object(dependency, "download_archive", lambda path: path.write_bytes(b"wrong")):
            with self.assertRaisesRegex(dependency.DependencyError, "SHA-256"):
                dependency.ensure_archive(self.cache)
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_interrupted_download_is_cleaned(self):
        def interrupted(path):
            path.write_bytes(b"partial")
            raise dependency.DependencyError("download failed")
        with patch.object(dependency, "download_archive", interrupted):
            with self.assertRaisesRegex(dependency.DependencyError, "download failed"):
                dependency.ensure_archive(self.cache)
        self.assertEqual(list(self.cache.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
