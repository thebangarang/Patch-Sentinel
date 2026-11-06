"""The adapter layer: which package manager answered, and whether its answer was readable.

The fixtures are real output, captured from real root filesystems: ``fedora45_dnf.txt`` is the
whole probe run inside ``fedora:latest`` (Fedora 45), ``debian12_apt.txt`` inside ``debian:12``,
``beelink_ubuntu2604.txt`` on this machine. They are the evidence that the adapter reads that
distro — not that the adapter exists.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import dispatch          # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def split_fixture(name: str) -> tuple[str, str]:
    """A captured probe output -> (family, body), the way ``dispatch.probe`` splits it."""
    text = (FIXTURES / name).read_text(encoding="utf-8")
    _, rest = text.split(dispatch.FAMILY_MARK, 1)
    family, _, body = rest.partition("\n")
    return family.strip(), body


class FamilySelection(unittest.TestCase):
    def test_ubuntu_and_debian_are_the_apt_adapter(self):
        self.assertEqual(dispatch.family_for("ubuntu"), "apt")
        self.assertEqual(dispatch.family_for("debian"), "apt")
        self.assertEqual(dispatch.family_for("LMDE"), "none")   # not claimed: no evidence yet

    def test_the_rpm_family(self):
        for os_id in ("fedora", "rhel", "rocky", "almalinux", "centos"):
            self.assertEqual(dispatch.family_for(os_id), "dnf", os_id)

    def test_an_unclaimed_os_is_none_not_a_guess(self):
        for os_id in ("gentoo", "void", "windows", "darwin", "", None):
            self.assertEqual(dispatch.family_for(os_id), "none", os_id)


class FedoraAdapter(unittest.TestCase):
    def setUp(self):
        self.family, self.body = split_fixture("fedora45_dnf.txt")
        self.facts = dispatch.parse_dnf(self.body)

    def test_the_family_mark_names_the_adapter_that_answered(self):
        self.assertEqual(self.family, "dnf")

    def test_pending_updates_are_read_from_the_real_table(self):
        # Fedora 45's base image really had 11 updates pending when this was captured
        self.assertEqual(len(self.facts["pending"]), 11, self.facts["pending"])
        packages = {p["package"] for p in self.facts["pending"]}
        self.assertIn("curl", packages)
        self.assertIn("libcurl", packages)
        curl = next(p for p in self.facts["pending"] if p["package"] == "curl")
        self.assertEqual(curl["to"], "8.21.0-9.fc45")
        self.assertEqual(curl["origin"], "updates")
        self.assertEqual(curl["arch"], "x86_64")

    def test_the_available_kernel_is_read(self):
        self.assertEqual(self.facts["candidate"], "7.2.15-300.fc45")

    def test_a_container_has_no_kernel_and_says_so(self):
        # rpm -q kernel answers "package kernel is not installed" inside a container. Reading that
        # as kernel-current would be the exact false all-clear this plugin exists to prevent.
        self.assertIsNone(self.facts["newest_installed"])
        self.assertEqual(self.facts["kernel"], "kernel-unknown")
        self.assertIn("no kernel package", self.facts["kernel_reason"])

    def test_os_and_images(self):
        self.assertEqual(self.facts["os"], {"id": "fedora", "codename": "45"})
        self.assertEqual(self.facts["images_outcome"], "not-applicable")


class FedoraVmAdapter(unittest.TestCase):
    """A real Fedora 45 machine (QEMU, 127.0.0.1:2222) — its own kernel, not the host's.

    This fixture is what a container could never give: `fedora45_dnf.txt` proves the parser, this
    one proves the kernel verdict on a host whose kernel is not ours.
    """

    def setUp(self):
        self.family, self.body = split_fixture("fedora45_vm_dnf.txt")
        self.facts = dispatch.parse_dnf(self.body)

    def test_the_vm_runs_its_own_fedora_kernel(self):
        self.assertEqual(self.facts["running"], "7.2.11-300.fc45.x86_64")
        self.assertEqual(self.facts["newest_installed"], "7.2.11-300.fc45")

    def test_kernel_core_is_read_as_the_kernel(self):
        # Fedora's cloud image has kernel-core + kernel-modules-core, and no `kernel` metapackage:
        # asking rpm for `kernel` alone reported "not installed" on a machine running one.
        self.assertIn("7.2.11-300.fc45", self.facts["installed_packages"])
        self.assertNotIn("modules-core", self.facts["installed_packages"])

    def test_a_newer_kernel_is_a_finding_on_dnf_too(self):
        self.assertEqual(self.facts["candidate"], "7.2.15-300.fc45")
        self.assertEqual(self.facts["kernel"], "kernel-update-available")

    def test_the_pending_list_is_a_real_fedora_list(self):
        self.assertGreater(len(self.facts["pending"]), 50)
        curl = next(p for p in self.facts["pending"] if p["package"] == "curl")
        self.assertTrue(curl["to"].endswith(".fc45"))
        self.assertEqual(self.facts["os"]["id"], "fedora")


class DebianAdapter(unittest.TestCase):
    def setUp(self):
        self.family, self.body = split_fixture("debian12_apt.txt")
        self.facts = dispatch.PARSERS["apt"](self.body)

    def test_the_apt_adapter_answers_on_debian(self):
        self.assertEqual(self.family, "apt")
        self.assertEqual(self.facts["os"]["id"], "debian")
        self.assertEqual(self.facts["pending"], [])

    def test_a_kernel_less_apt_host_is_unmeasured_not_current(self):
        self.assertEqual(self.facts["kernel"], "kernel-unknown")


class RpmNames(unittest.TestCase):
    def test_kernel_package_names_become_comparable_versions(self):
        self.assertEqual(dispatch._rpm_kernel_version("kernel-7.2.15-300.fc45.x86_64"),
                         "7.2.15-300.fc45")
        self.assertEqual(dispatch._rpm_kernel_version("kernel-6.8.0-45.el9.aarch64"),
                         "6.8.0-45.el9")
        self.assertIsNone(dispatch._rpm_kernel_version("package kernel is not installed"))

    def test_a_dnf_row_split_keeps_the_repo(self):
        rows = dispatch._dnf_rows("Upgrades\ncurl.x86_64 8.21.0-9.fc45 updates\n"
                                  "Last metadata expiration check: whatever\n")
        self.assertEqual(rows, [("curl.x86_64", "8.21.0-9.fc45", "updates")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
