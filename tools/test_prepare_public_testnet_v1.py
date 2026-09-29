"""Focused first-join preflight/no-overwrite checks; never mount or start a node."""
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("prepare", Path(__file__).with_name("prepare-public-testnet-v1.py"))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PreparationTests(unittest.TestCase):
    def test_existing_file_and_symlink_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "original"
            original.write_bytes(b"preserve")
            link = Path(tmp) / "link"
            link.symlink_to(original)
            for path in (original, link):
                with self.assertRaises(FileExistsError):
                    prepare.create_file(path, b"replacement")
            self.assertEqual(original.read_bytes(), b"preserve")

    def test_regular_input_is_bounded_and_nofollow(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "input"
            original.write_bytes(b"abc")
            link = Path(tmp) / "link"
            link.symlink_to(original)
            self.assertEqual(prepare.regular_bytes(original, 3), b"abc")
            for path in (original, Path(tmp), link):
                with self.assertRaises((ValueError, OSError)):
                    prepare.regular_bytes(path, 2)

    def test_root_existing_and_relative_destinations_refuse(self):
        for path in (Path("/"), Path("/var/tmp"), Path("relative"), Path("/var/tmp/../node")):
            with self.assertRaises(ValueError):
                prepare.fresh_destination(path)

    def test_explicit_acceptance_precedes_mutation(self):
        with patch.object(prepare.sys, "platform", "linux"), patch.object(prepare.os, "geteuid", return_value=0), \
             patch.object(prepare.Path, "mkdir") as mkdir, patch.object(prepare.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "accept-public-zero-value"):
                prepare.prepare(SimpleNamespace(accept_public_zero_value=False))
            mkdir.assert_not_called()
            run.assert_not_called()

    def test_printed_runtime_is_unprivileged_capped_and_nonlistening(self):
        command = prepare.run_command(Path("/var/tmp/node/public/silk-f04-testnet"), Path("/var/tmp/node/config.json"),
                                      Path("/var/tmp/node/data"), SimpleNamespace(pw_uid=1234, pw_gid=1235), "sync")
        for required in ("--uid=1234", "--gid=1235", "MemoryMax=4G", "MemorySwapMax=0", "TasksMax=4",
                         "CPUQuota=100%", "RuntimeMaxSec=900", "Restart=no", "SocketBindDeny=any",
                         "NoNewPrivileges=yes", "ProtectSystem=strict"):
            self.assertIn(required, command)
        self.assertEqual(command[-3:], ["sync", "--config", "/var/tmp/node/config.json"])


if __name__ == "__main__":
    unittest.main()
