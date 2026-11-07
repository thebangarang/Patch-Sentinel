"""Is the patch in effect? Reboot flags, needrestart and needs-restarting.

The failure this guards against is the plugin's own first rule applied to userland: `dpkg` says the
package is installed, the process is still running the old library. And the second failure is the
opposite — a host where none of the three tools exist must read as *unmeasured*, not as "nothing to
restart".
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import services, shell  # noqa: E402


class Parsing(unittest.TestCase):
    def test_the_debian_reboot_flag_names_its_packages(self):
        text = (f"{services.MARK_FLAGS}\nREBOOT-REQUIRED\n/var/run/reboot-required.pkgs\n"
                f"linux-image-7.0.0-43-generic\nlibc6\n{services.MARK_NEEDRESTART}\n"
                f"{services.MARK_NEEDS_RESTARTING}\n")
        state = services.parse(text)
        self.assertTrue(state["reboot_required"])
        self.assertEqual(state["reboot_packages"], ["linux-image-7.0.0-43-generic", "libc6"])

    def test_needrestart_services_are_the_point(self):
        text = (f"{services.MARK_FLAGS}\n{services.MARK_NEEDRESTART}\nNEEDRESTART-VER: 3.11\n"
                f"NEEDRESTART-KCUR: 7.0.0-43-generic\nNEEDRESTART-KEXP: 7.0.0-43-generic\n"
                f"NEEDRESTART-KSTA: 1\nNEEDRESTART-SVC: ssh.service\nNEEDRESTART-SVC: cron.service\n"
                f"{services.MARK_NEEDS_RESTARTING}\n")
        state = services.parse(text)
        self.assertEqual(state["services"], ["ssh.service", "cron.service"])
        self.assertEqual(state["kernel_state"], "current")
        self.assertFalse(state["reboot_required"])
        self.assertEqual(state["outcome"], "ok")

    def test_a_new_kernel_from_needrestart_is_a_reboot_owed(self):
        text = (f"{services.MARK_FLAGS}\n{services.MARK_NEEDRESTART}\nNEEDRESTART-KSTA: 2\n"
                f"{services.MARK_NEEDS_RESTARTING}\n")
        state = services.parse(text)
        self.assertTrue(state["reboot_required"])

    def test_needs_restarting_exit_code_one_means_reboot(self):
        text = (f"{services.MARK_FLAGS}\n{services.MARK_NEEDRESTART}\nNO-NEEDRESTART\n"
                f"{services.MARK_NEEDS_RESTARTING}\nNEEDSRC=1\n")
        state = services.parse(text)
        self.assertTrue(state["reboot_required"])
        self.assertEqual(state["needs_restarting"], "ok")

    def test_a_clean_host_is_false_not_none(self):
        text = (f"{services.MARK_FLAGS}\n{services.MARK_NEEDRESTART}\nNEEDRESTART-KSTA: 1\n"
                f"{services.MARK_NEEDS_RESTARTING}\nNEEDSRC=0\n")
        with mock.patch.object(shell, "run", return_value=(0, text)):
            state = services.collect(None, timeout=5)
        self.assertFalse(state["reboot_required"])
        self.assertEqual(state["services"], [])
        self.assertEqual(state["outcome"], "ok")

    def test_no_tool_at_all_is_unmeasured(self):
        text = (f"{services.MARK_FLAGS}\n{services.MARK_NEEDRESTART}\nNO-NEEDRESTART\n"
                f"{services.MARK_NEEDS_RESTARTING}\nNO-NEEDS-RESTARTING\n")
        with mock.patch.object(shell, "run", return_value=(0, text)):
            state = services.collect(None, timeout=5)
        self.assertEqual(state["outcome"], "unavailable")
        self.assertIn("unmeasured", state["why"])
        self.assertIsNone(state["reboot_required"])

    def test_the_probe_is_one_round_trip(self):
        self.assertEqual(services.PROBE.count("echo --nr--"), 1)
        self.assertIn("reboot-required", services.PROBE)
        self.assertIn("needrestart -b", services.PROBE)
        self.assertIn("needs-restarting -r", services.PROBE)


if __name__ == "__main__":
    unittest.main()
