#!/usr/bin/env python3
"""Run with python3 -m unittest discover -s contrib/networkd."""
import unittest
import subprocess
import sys
import tempfile
from pathlib import Path
from install import ufw_hook

BASE = "*filter\n:ufw-before-input - [0:0]\n:ufw-before-output - [0:0]\n-A ufw-before-input -i lo -j ACCEPT\nCOMMIT\n"


class InstallTests(unittest.TestCase):
    def test_package_configuration_preserves_package_owned_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "etc/ufw/before.rules"
            before.parent.mkdir(parents=True)
            before.write_text(BASE)
            binary = root / "usr/lib/waycast/waycast-networkd"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"package-owned binary")
            command = [sys.executable, str(Path(__file__).with_name("install.py")),
                       "--destdir", directory, "--configure-only"]
            for _ in range(2):
                subprocess.run(command, check=True, capture_output=True)
                self.assertEqual(before.read_text(), ufw_hook(BASE))
            subprocess.run(command + ["--uninstall"], check=True, capture_output=True)
            self.assertEqual(before.read_text(), BASE)
            self.assertEqual(binary.read_bytes(), b"package-owned binary")

    def test_preserves_rules_is_idempotent_and_reversible(self):
        installed = ufw_hook(BASE)
        self.assertEqual(ufw_hook(installed), installed)
        self.assertEqual(ufw_hook(installed, remove=True), BASE)
        self.assertLess(installed.index("-j waycast-input"), installed.index("-i lo"))
        self.assertIn("-F waycast-input", installed)

    def test_refuses_collisions_and_unrecognized_tables(self):
        for text in ["*filter\nCOMMIT\n", BASE.replace("COMMIT", ":waycast-input - [0:0]\nCOMMIT"),
                     BASE + "# BEGIN WAYCAST HOOK\n"]:
            with self.assertRaises(ValueError):
                ufw_hook(text)


if __name__ == "__main__":
    unittest.main()
