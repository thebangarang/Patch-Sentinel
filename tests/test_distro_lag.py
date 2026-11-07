"""Vendor lag beyond Ubuntu: OSV per release, and the Arch tracker.

The rule under test is the same one as everywhere else in this plugin: an advisory that names a fixed
version the archive does not offer is its own state, and a family with no feed says *not measured*
rather than "nothing to do". The fixtures here are real payload shapes captured from the sources
(`Debian:12`, `Alpine:v3.22`, `Rocky Linux:9`, `security.archlinux.org/all.json`).
"""
from __future__ import annotations

import json
import sys
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import distro_lag  # noqa: E402
from patch_sentinel.sources import shell  # noqa: E402


class EcosystemStrings(unittest.TestCase):
    """OSV indexes each release separately; a wrong string returns zero results, which reads as clean."""

    CASES = [
        (("debian", "12"), "Debian:12"),
        (("alpine", "3.22.6"), "Alpine:v3.22"),      # the tracker tags the minor series, not the patch
        (("rocky", "9.4"), "Rocky Linux:9"),
        (("almalinux", "9.3"), "AlmaLinux:9"),
        (("centos", "10"), "Red Hat:10"),
        (("fedora", "44"), None),                    # no OSV ecosystem: reported as unmeasured
        (("opensuse-leap", "15.6"), None),
    ]

    def test_the_release_is_in_the_string(self):
        for (os_id, version), expected in self.CASES:
            with self.subTest(os_id=os_id, version=version):
                self.assertEqual(distro_lag.ecosystem_for(os_id, version), expected)


class InstalledInventory(unittest.TestCase):
    def test_debian_rows_carry_the_source_package(self):
        rows = distro_lag.parse_installed(
            "libssl3\t3.0.11-1~deb12u2\topenssl\n"
            "curl\t8.5.0-2\tcurl (7.88.1)\n"
            "libc6\t2.36-9+deb12u4\tglibc:amd64\n", "deb")
        self.assertEqual([r["source"] for r in rows], ["openssl", "curl", "glibc"])
        self.assertEqual(rows[0]["version"], "3.0.11-1~deb12u2")

    def test_rpm_rows_strip_the_source_rpm_suffix(self):
        rows = distro_lag.parse_installed(
            "openssl-libs\t3.0.7-27.el9\topenssl-3.0.7-27.el9.src.rpm\n", "rpm")
        self.assertEqual(rows[0]["source"], "openssl")

    def test_apk_rows_split_off_the_version(self):
        rows = distro_lag.parse_installed("openssl-3.5.1-r0\nmusl-1.2.5-r9\n", "apk")
        self.assertEqual([(r["package"], r["version"]) for r in rows],
                         [("openssl", "3.5.1-r0"), ("musl", "1.2.5-r9")])


class CandidateParsing(unittest.TestCase):
    def test_apt_policy_block(self):
        text = ("libssl3:\n  Installed: 3.0.11-1~deb12u1\n"
                "  Candidate: 3.0.11-1~deb12u2\n")
        self.assertEqual(distro_lag.parse_candidates(text, "apt"),
                         {"libssl3": "3.0.11-1~deb12u2"})

    def test_pacman_si_block(self):
        text = ("Repository      : core\nName            : vim\n"
                "Version         : 9.1.2-1\n\nRepository      : core\nName            : curl\n"
                "Version         : 8.7.1-1\n")
        self.assertEqual(distro_lag.parse_candidates(text, "pacman"),
                         {"vim": "9.1.2-1", "curl": "8.7.1-1"})


class OsvAdvisories(unittest.TestCase):
    """The shape captured from api.osv.dev for Debian:12 (openssl) and Rocky Linux:9."""

    def setUp(self):
        self._post = distro_lag._post
        self._vuln = distro_lag.osv_source.vuln

    def tearDown(self):
        distro_lag._post = self._post
        distro_lag.osv_source.vuln = self._vuln

    def test_only_a_fix_for_this_release_becomes_an_advisory(self):
        # the batch answers with ids only (measured against the live API); the records are fetched after
        distro_lag._post = lambda url, payload: {"results": [{"vulns": [
            {"id": "DEBIAN-CVE-2023-5363", "modified": "x"},
            {"id": "DEBIAN-CVE-2023-9999", "modified": "x"},
            {"id": "DEBIAN-CVE-2023-0001", "modified": "x"}]}]}
        distro_lag.osv_source.vuln = lambda vid, timeout=20: {
            "DEBIAN-CVE-2023-5363": {"affected": [{"package": {"ecosystem": "Debian:12", "name": "openssl"},
                                                   "ranges": [{"events": [
                                                       {"introduced": "0"},
                                                       {"fixed": "3.0.11-1~deb12u2"}]}]}]},
            # names a fix for another release only: not this host's answer
            "DEBIAN-CVE-2023-9999": {"affected": [{"package": {"ecosystem": "Debian:11", "name": "openssl"},
                                                   "ranges": [{"events": [
                                                       {"fixed": "1.1.1n-0+deb11u5"}]}]}]},
            # still open, no fix published anywhere
            "DEBIAN-CVE-2023-0001": {"affected": [{"package": {"ecosystem": "Debian:12", "name": "openssl"},
                                                   "ranges": [{"events": [{"introduced": "0"}]}]}]},
        }.get(vid)
        advisories = distro_lag.osv_advisories("Debian:12", [("openssl", "3.0.11-1~deb12u1")])
        self.assertEqual(set(advisories), {"openssl"})
        self.assertEqual(advisories["openssl"]["version"], "3.0.11-1~deb12u2")

    def test_the_highest_fix_wins_when_several_advisories_apply(self):
        distro_lag._post = lambda url, payload: {"results": [
            {"vulns": [{"id": "CVE-A", "modified": "x"}, {"id": "CVE-B", "modified": "x"}]}]}
        distro_lag.osv_source.vuln = lambda vid, timeout=20: {
            "CVE-A": {"affected": [{"package": {"ecosystem": "Debian:12", "name": "pkg"},
                                    "ranges": [{"events": [{"fixed": "1.2.3-1"}]}]}]},
            "CVE-B": {"affected": [{"package": {"ecosystem": "Debian:12", "name": "pkg"},
                                    "ranges": [{"events": [{"fixed": "1.2.5-1"}]}]}]},
        }.get(vid)
        advisories = distro_lag.osv_advisories("Debian:12", [("pkg", "1.2.2-1")])
        self.assertEqual(advisories["pkg"]["version"], "1.2.5-1")


class ArchFeed(unittest.TestCase):
    """A captured `all.json` entry: the tracker keeps resolved advisories too, and those are not lag."""

    FEED = [
        {"name": "AVG-2843", "packages": ["vim"], "status": "Vulnerable",
         "affected": "9.0.1224-1", "fixed": "9.0.1225-1", "issues": ["CVE-2023-0433"]},
        {"name": "AVG-9999", "packages": ["vim"], "status": "Fixed",
         "affected": "9.0.1000-1", "fixed": "9.0.1001-1", "issues": ["CVE-2020-0001"]},
        {"name": "AVG-1111", "packages": ["curl"], "status": "Vulnerable",
         "affected": "8.0.0-1", "fixed": "8.0.1-1", "issues": ["CVE-2024-1111"]},
    ]

    def test_a_live_advisory_on_an_installed_package_is_reported(self):
        advisories = distro_lag.arch_advisories(json.dumps(self.FEED), {"vim": "9.0.1224-1"})
        self.assertEqual(set(advisories), {"vim"})
        self.assertEqual(advisories["vim"]["version"], "9.0.1225-1")

    def test_a_resolved_advisory_is_skipped_even_when_its_fix_is_newer(self):
        # AVG-9999 is resolved (status Fixed) with fix 9.0.1001-1, which is newer than the installed
        # 9.0.1000-1. Reporting it would invent a lag on a machine the tracker calls fixed.
        advisories = distro_lag.arch_advisories(json.dumps(self.FEED),
                                                {"vim": "9.0.1000-1", "nano": "7.2-1"})
        self.assertNotIn("9.0.1001-1", [row["version"] for row in advisories.values()] +
                         [advisories.get("vim", {}).get("version")])

    def test_a_package_that_is_not_installed_is_ignored(self):
        self.assertEqual(distro_lag.arch_advisories(json.dumps(self.FEED), {"zsh": "5.9-1"}), {})


class TheLastTwoFamilies(unittest.TestCase):
    """Fedora and openSUSE used to answer "unsupported". They now read a feed, and a feed that cannot
    be read is *unmeasured* — never unsupported, never clean."""

    def test_fedora_asks_bodhi_for_its_release(self):
        asked = {}

        def fake_advisories(version_id, **kwargs):
            asked["release"] = version_id
            return {"openssl": {"version": "3.2.5", "notice": "FEDORA-2026-a", "cves": ["CVE-1"]}}

        def fake_run(command, target=None, timeout=0, path_prefix=None):
            if command.startswith("rpm -qa"):
                return 0, "openssl\t3.2.4-1.fc45\topenssl-3.2.4-1.fc45.src.rpm\n"
            if command.startswith("dnf -q list"):
                return 0, "openssl.x86_64 3.2.4-1.fc45 updates\n"
            return 0, ""

        with mock.patch.object(distro_lag, "shell") as fake_shell, \
             mock.patch("patch_sentinel.sources.bodhi.advisories", side_effect=fake_advisories):
            fake_shell.run.side_effect = fake_run
            fake_shell.SYSTEM_PATH_PREFIX = ""
            answer = distro_lag.assess(None, "dnf", "fedora", "45", timeout=5)
        self.assertEqual(asked["release"], "45")
        self.assertEqual(answer["state"], "measured")
        self.assertEqual(answer["feed"]["product"], "F45")
        self.assertEqual(answer["counts"]["vendor_lag"], 1)
        self.assertEqual(answer["vendor_lag"][0]["fixed_version"], "3.2.5")

    def test_opensuse_asks_the_oval_for_its_product(self):
        def fake_run(command, target=None, timeout=0, path_prefix=None):
            if command.startswith("rpm -qa"):
                return 0, "libopenssl-3-0\t3.1.4-150600.5.1\topenssl-3-3.1.4-150600.5.1.src.rpm\n"
            return 0, "<stream><update-list><update name=\"libopenssl-3-0\" edition=\"3.1.4-150600.5.1\"/></update-list></stream>"

        index = {"libopenssl-3-0": {"version": "3.1.5-150600.6.1", "notice": "CVE-2026-1",
                                    "cves": ["CVE-2026-1"], "cve_count": 1}}
        meta = {"product": "opensuse.leap.15.6.xml.gz", "feed_date": "Thu, 25 Jun 2026 15:58:48 GMT",
                "age_days": 135.0, "stale": True, "source_url": "https://example/oval"}
        with mock.patch.object(distro_lag, "shell") as fake_shell, \
             mock.patch("patch_sentinel.sources.suse_oval.advisories", return_value=(index, meta)):
            fake_shell.run.side_effect = fake_run
            fake_shell.SYSTEM_PATH_PREFIX = ""
            answer = distro_lag.assess(None, "zypper", "opensuse-leap", "15.6", timeout=5)
        self.assertEqual(answer["state"], "measured")
        self.assertTrue(answer["feed"]["stale"])
        self.assertEqual(answer["counts"]["vendor_lag"], 1)
        self.assertIn("libopenssl-3-0", answer["vendor_lag"][0]["package"])

    def test_a_feed_that_cannot_be_read_is_unmeasured_not_unsupported(self):
        def fake_run(command, target=None, timeout=0, path_prefix=None):
            return 0, "openssl\t3.2.4-1.fc45\topenssl-3.2.4-1.fc45.src.rpm\n"

        with mock.patch.object(distro_lag, "shell") as fake_shell, \
             mock.patch("patch_sentinel.sources.bodhi.advisories", side_effect=OSError("no route")):
            fake_shell.run.side_effect = fake_run
            fake_shell.SYSTEM_PATH_PREFIX = ""
            answer = distro_lag.assess(None, "dnf", "fedora", "45", timeout=5)
        self.assertEqual(answer["state"], "unmeasured")
        self.assertIn("Bodhi", answer["reason"])


class AssessmentEndToEnd(unittest.TestCase):
    """One Debian host, start to finish, with the shell and the network stubbed."""

    def setUp(self):
        self._run = shell.run
        self._get = distro_lag._get
        self._post = distro_lag._post

    def tearDown(self):
        shell.run, distro_lag._get, distro_lag._post = self._run, self._get, self._post

    def test_a_fix_the_archive_does_not_offer_is_lag(self):
        calls = []

        def fake_run(command, target=None, timeout=0, path_prefix=None):
            calls.append(command)
            if "dpkg-query" in command:
                return 0, ("libssl3\t3.0.11-1~deb12u1\topenssl\n"
                           "curl\t8.5.0-2\tcurl\n")
            if "apt-cache policy" in command:
                # the archive's candidate is older than the advisory's fix
                return 0, ("libssl3:\n  Installed: 3.0.11-1~deb12u1\n"
                           "  Candidate: 3.0.11-1~deb12u1\n")
            return 0, ""

        shell.run = fake_run

        def fake_post(url, payload):
            # the batch is sorted by package name: answer by name, not by position
            results = []
            for query in payload["queries"]:
                name = query["package"]["name"]
                vuln = {"id": "DEBIAN-CVE-2023-5363",
                        "affected": [{"package": {"ecosystem": "Debian:12", "name": "openssl"},
                                      "ranges": [{"events": [{"fixed": "3.0.11-1~deb12u2"}]}]}]}
                results.append({"vulns": [vuln] if name == "openssl" else []})
            return {"results": results}

        distro_lag._post = fake_post

        answer = distro_lag.assess(None, "apt", "debian", "12", timeout=10)
        self.assertEqual(answer["state"], "measured")
        self.assertEqual([row["package"] for row in answer["vendor_lag"]], ["libssl3"])
        self.assertEqual(answer["vendor_lag"][0]["fixed_version"], "3.0.11-1~deb12u2")
        self.assertIn("apt-cache policy", " ".join(calls))

    def test_an_archive_that_offers_the_fix_is_not_lag(self):
        shell.run = lambda command, target=None, timeout=0, path_prefix=None: (
            (0, "libssl3\t3.0.11-1~deb12u1\topenssl\n") if "dpkg-query" in command
            else (0, "libssl3:\n  Candidate: 3.0.11-1~deb12u2\n"))
        distro_lag._post = lambda url, payload: {"results": [
            {"vulns": [{"id": "DEBIAN-CVE-2023-5363",
                        "affected": [{"package": {"ecosystem": "Debian:12", "name": "openssl"},
                                      "ranges": [{"events": [{"fixed": "3.0.11-1~deb12u2"}]}]}]}]}]}
        answer = distro_lag.assess(None, "apt", "debian", "12", timeout=10)
        self.assertEqual(answer["vendor_lag"], [])
        self.assertEqual(answer["counts"]["fix_available"], 1)

    def test_a_machine_that_cannot_be_listed_is_unmeasured_not_clean(self):
        shell.run = lambda *a, **k: (1, "")
        answer = distro_lag.assess(None, "apt", "debian", "12", timeout=5)
        self.assertEqual(answer["state"], "unmeasured")
        self.assertIn("unmeasured", answer["reason"])


if __name__ == "__main__":
    unittest.main()
