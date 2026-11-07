"""Adding a server: each way it fails has its own stage and its own fix.

The classification is what tells a user whether to fix the name, the port, the key or the host key.
Getting it wrong sends someone editing the wrong thing, which is worse than saying nothing.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import diagnose  # noqa: E402


def result(code: int, stderr: str = "", stdout: str = ""):
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=stdout, stderr=stderr)


class Stages(unittest.TestCase):
    CASES = [
        (result(255, "ssh: Could not resolve hostname nowhere.invalid: Name or service not known"),
         "dns"),
        (result(255, "ssh: connect to host 10.0.0.9 port 22: Connection refused"), "tcp"),
        (result(255, "ssh: connect to host 10.0.0.9 port 22: Connection timed out"), "tcp"),
        (result(255, "debian@10.0.0.9: Permission denied (publickey)."), "auth"),
        (result(255, "root@10.0.0.9: Permission denied (publickey,password)."), "auth"),
        (result(255, "Host key verification failed."), "hostkey"),
        (result(255, "bash: not found"), "shell"),
        (result(0), "ok"),
    ]

    def test_each_ssh_message_maps_to_the_right_stage(self):
        for proc, expected in self.CASES:
            with self.subTest(stage=expected, stderr=proc.stderr):
                with mock.patch.object(diagnose.subprocess, "run", return_value=proc):
                    self.assertEqual(diagnose.diagnose("debian@10.0.0.9")["stage"], expected)

    def test_the_port_is_passed_as_a_flag_not_inside_the_hostname(self):
        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            return result(0)

        with mock.patch.object(diagnose.subprocess, "run", side_effect=fake_run):
            diagnose.diagnose("debian@10.0.0.9:2223")
        argv = seen["argv"]
        self.assertIn("-p", argv)
        self.assertEqual(argv[argv.index("-p") + 1], "2223")
        self.assertIn("debian@10.0.0.9", argv)
        self.assertNotIn("debian@10.0.0.9:2223", argv)

    def test_this_machine_is_not_diagnosed_over_ssh(self):
        with mock.patch.object(diagnose.subprocess, "run") as run:
            self.assertTrue(diagnose.diagnose(None)["ok"])
        run.assert_not_called()


class Fixes(unittest.TestCase):
    def test_auth_points_at_ssh_copy_id_with_the_key_and_the_port(self):
        fix = diagnose._fix_for("auth", "debian@10.0.0.9:2223")
        self.assertIn("ssh-copy-id", fix)
        self.assertIn("-p 2223", fix)
        self.assertIn("debian@10.0.0.9", fix)

    def test_a_host_key_failure_points_at_ssh_keygen(self):
        self.assertIn("ssh-keygen -R", diagnose._fix_for("hostkey", "root@10.0.0.9"))

    def test_a_name_that_does_not_resolve_gets_a_plain_retry(self):
        self.assertEqual(diagnose._fix_for("dns", "vps.example"), "ssh vps.example true")

    def test_no_suggestion_ever_names_a_private_key(self):
        # a suggestion may point at ~/.ssh/id_ed25519.pub, never at the private half
        for stage in ("auth", "dns", "tcp", "hostkey", "shell"):
            with self.subTest(stage=stage):
                fix = diagnose._fix_for(stage, "a@b")
                if "~/.ssh/" in fix:
                    # whatever key this machine has, the suggestion names the .pub half
                    self.assertRegex(fix, r"~/\.ssh/[\w.-]+\.pub")

    def test_the_command_uses_the_key_that_exists(self):
        import tempfile
        from pathlib import Path as P
        from unittest import mock
        with tempfile.TemporaryDirectory() as home:
            ssh = P(home) / ".ssh"
            ssh.mkdir()
            (ssh / "id_ed25519_patchlab.pub").write_text("ssh-ed25519 AAAA lab\n", encoding="utf-8")
            with mock.patch.object(diagnose.Path, "home", return_value=P(home)):
                fix = diagnose._fix_for("auth", "debian@10.0.0.9")
                self.assertIn("ssh-copy-id", fix)
                self.assertIn("id_ed25519_patchlab.pub", fix)


if __name__ == "__main__":
    unittest.main()
