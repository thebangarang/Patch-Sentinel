"""The ported selftest, as stdlib unittest.

These assertions are the rules in executable form and come from ``cve-watch.py --selftest``:
they are ported unchanged (same inputs, same expected values, same messages), because the
routine on the beelink still runs them and this plugin must answer identically. Anything here
that starts failing means the two have diverged, not that a test is out of date.

Run:  python3 -m unittest discover -s tests -t .      (from the repository root)
"""
from __future__ import annotations

import datetime as dt
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel import verdict  # noqa: E402  (path bootstrap must come first)


# a real apt simulation, as today's VPS printed it before the 7.0.0-43 upgrade
SIM = (
    "Inst base-files [14ubuntu6.2] (14ubuntu6.3 Ubuntu:26.04/resolute-updates [amd64])\n"
    "Inst linux-image-generic [7.0.0-42.42] (7.0.0-43.43 Ubuntu:26.04/resolute-updates [amd64])\n"
    "Inst containerd [2.2.2-0ubuntu1.1] (2.2.2-0ubuntu1.2 Ubuntu:26.04/resolute-updates [amd64])\n"
    "Inst newpkg (1.2.3-1 Ubuntu:26.04/resolute-security [amd64])\n"
    "Conf base-files (14ubuntu6.3 Ubuntu:26.04/resolute-updates [amd64])\n"
)

NOTICES = [
    {"id": "USN-9999-1", "published": "2026-11-05T10:00:00",
     "release_packages": {"resolute": [{"name": "openssl", "version": "3.5.5-1ubuntu3.8"},
                                       {"name": "linux", "version": "7.0.0-43.43"}]}},
    {"id": "USN-OLD-1", "published": "2026-01-01T10:00:00",
     "release_packages": {"resolute": [{"name": "zlib", "version": "1:1.3-1"}]}},
]
NOW = dt.datetime(2026, 11, 6, tzinfo=dt.timezone.utc)
DIGEST = "sha256:" + "a" * 64


class ParseInst(unittest.TestCase):
    def test_inst_lines_become_package_and_versions(self):
        got = verdict.parse_inst(SIM)
        self.assertEqual(len(got), 4, got)
        self.assertEqual((got[1]["package"], got[1]["to"]),
                         ("linux-image-generic", "7.0.0-43.43"))
        self.assertIsNone(got[3]["from"])
        self.assertTrue(got[3]["origin"].endswith("resolute-security"), got[3])


class UsnIndex(unittest.TestCase):
    def setUp(self):
        self.idx = verdict.usn_index(NOTICES, now=NOW)

    def test_recent_advisory_is_indexed(self):
        self.assertIn(("openssl", "3.5.5-1ubuntu3.8"), self.idx, self.idx)

    def test_old_advisory_must_not_explain_a_new_fix(self):
        self.assertNotIn(("zlib", "1:1.3-1"), self.idx,
                         "an old advisory must not explain a new fix")


class Explain(unittest.TestCase):
    def setUp(self):
        self.idx = verdict.usn_index(NOTICES, now=NOW)

    def test_source_package_advisory_explains_the_image_package(self):
        # the advisory names the source package `linux`; our package is linux-image-generic
        self.assertEqual(verdict.explain("linux-image-generic", "7.0.0-43.43", self.idx),
                         "USN-9999-1")

    def test_version_mismatch_explains_nothing(self):
        self.assertIsNone(verdict.explain("linux-image-generic", "7.0.0-99.99", self.idx))

    def test_exact_package_match(self):
        self.assertEqual(verdict.explain("openssl", "3.5.5-1ubuntu3.8", self.idx), "USN-9999-1")


class KernelVerdict(unittest.TestCase):
    def test_newer_kernel_installable(self):
        self.assertEqual(
            verdict.kernel_verdict("7.0.0-42-generic", "7.0.0-42-generic", "7.0.0-43-generic"),
            "kernel-update-available")

    def test_installed_but_not_running_needs_a_reboot(self):
        self.assertEqual(
            verdict.kernel_verdict("7.0.0-42-generic", "7.0.0-43-generic", "7.0.0-43-generic"),
            "kernel-reboot-needed",
            "installed-but-not-running must not read as 'install it again'")

    def test_installed_not_running_with_no_candidate(self):
        self.assertEqual(
            verdict.kernel_verdict("7.0.0-42-generic", "7.0.0-43-generic", None),
            "kernel-reboot-needed")

    def test_running_the_newest_is_current(self):
        self.assertEqual(
            verdict.kernel_verdict("7.0.0-43-generic", "7.0.0-43-generic", "7.0.0-43-generic"),
            "kernel-current")


class ImageState(unittest.TestCase):
    # registry digest: same = current, different = rebuilt, missing = not comparable (never a finding)
    def test_same_digest_is_current(self):
        self.assertEqual(verdict.image_state("repo@" + DIGEST, DIGEST, "repo:tag"), "current")

    def test_different_digest_is_rebuilt(self):
        self.assertEqual(
            verdict.image_state("repo@sha256:" + "b" * 64, DIGEST, "repo:tag"), "rebuilt")

    def test_no_local_digest_is_not_comparable(self):
        self.assertEqual(verdict.image_state("", DIGEST, "local-build"), "not-comparable")

    def test_no_registry_digest_is_not_comparable(self):
        self.assertEqual(verdict.image_state("repo@" + DIGEST, "", "repo:tag"), "not-comparable")

    def test_rate_limited_registry_is_unknown(self):
        self.assertEqual(
            verdict.image_state("repo@" + DIGEST,
                                "err:ERROR: unexpected status 429 Too Many Requests", "repo:tag"),
            "unknown", "a refused registry is not a clean image")

    def test_other_registry_error_is_not_current(self):
        self.assertNotEqual(verdict.image_state("repo@" + DIGEST, "err:ERROR: x", "repo:tag"),
                            "current")

    def test_locally_built_image_is_not_a_blind_spot(self):
        self.assertEqual(verdict.image_state("", "err:no-such-image", "social-pilot:latest"),
                         "not-comparable", "a locally built image is not a blind spot")

    def test_rate_limited_code_is_unknown(self):
        self.assertEqual(verdict.image_state("", "err:rate-limited", "postgres:16-alpine"),
                         "unknown")

    def test_other_code_is_unknown(self):
        self.assertEqual(verdict.image_state("", "err:other", "postgres:16-alpine"), "unknown")


class KernelAbi(unittest.TestCase):
    def test_newer_abi_sorts_higher(self):
        self.assertGreater(verdict.abi("7.0.0-43-generic"), verdict.abi("7.0.0-42-generic"))


class Proposal(unittest.TestCase):
    def test_full_upgrade_and_reboot(self):
        p = verdict.proposal("webasix", [{"package": "x"}], "kernel-update-available", [])
        self.assertIn("full-upgrade", p, p)
        self.assertIn("reboot", p, p)


class ReleaseLever(unittest.TestCase):
    """The one thing this port adds: the release codename, defaulted to the old behaviour.

    A plugin runs on whatever host it is installed on, so the codename cannot be a constant —
    but the default must stay `resolute` or the ported assertions above would be asserting a
    different function than the routine.
    """

    def test_default_release_is_unchanged(self):
        self.assertEqual(verdict.DEFAULT_RELEASE, "resolute")
        self.assertIn(("openssl", "3.5.5-1ubuntu3.8"), verdict.usn_index(NOTICES, now=NOW))

    def test_a_second_release_is_selectable(self):
        notices = [{"id": "USN-4242-1", "published": "2026-11-05T10:00:00",
                    "release_packages": {"noble": [{"name": "openssl", "version": "3.0.13-1"}]}}]
        self.assertEqual(verdict.usn_index(notices, now=NOW, release="noble"),
                         {("openssl", "3.0.13-1"): "USN-4242-1"})
        self.assertEqual(verdict.usn_index(notices, now=NOW, release="resolute"), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
