import os
import sys
import tempfile
import unittest
from unittest import mock

from proxy_skitchen.compat import bundle_dir, resource_path


class TestResourcePath(unittest.TestCase):
    def test_finds_packaged_icon(self):
        path = resource_path("icon.png")
        self.assertTrue(os.path.exists(path), path)
        self.assertTrue(path.endswith("icon.png"))

    def test_missing_file_returns_candidate_path(self):
        path = resource_path("definitely-missing-12345.bin")
        self.assertTrue(path.endswith("definitely-missing-12345.bin"))

    def test_bundle_dir_exists(self):
        self.assertTrue(os.path.isdir(bundle_dir()))

    def test_frozen_layout_is_found(self):
        # Onefile builds unpack data under sys._MEIPASS/proxy_skitchen.
        with tempfile.TemporaryDirectory() as tmp:
            pkg = os.path.join(tmp, "proxy_skitchen")
            os.makedirs(pkg)
            icon = os.path.join(pkg, "icon.png")
            with open(icon, "wb") as fh:
                fh.write(b"png")
            with mock.patch.object(sys, "_MEIPASS", tmp, create=True):
                self.assertEqual(resource_path("icon.png"), icon)


if __name__ == "__main__":
    unittest.main()
