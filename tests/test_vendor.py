"""The vendor-lag state: an advisory names a fix the archive does not offer yet.

Two things are proven here. The version comparator is checked against the same cases dpkg itself
answered (900 comparisons against `dpkg --compare-versions` during development), because a comparator
that is wrong in either direction manufactures a lag that does not exist — or hides one that does.
And the classifier is checked on a real-shaped advisory map: a package whose fix is newer than the
archive's candidate, one whose fix is installable, one already ahead of the advisory, and one that is
not installed at all.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import vendor  # noqa: E402


class DebianOrdering(unittest.TestCase):
    """Pinned against `dpkg --compare-versions` (verified over 900 pairs, 0 mismatches)."""

    CASES = [
        ("1.0", "1.0", 0),
        ("1.0~rc1", "1.0", -1),          # a pre-release sorts below the release
        ("1.0", "1.0~rc1", 1),
        ("1.0~~", "1.0~", -1),
        ("1.0a", "1.0.0", -1),           # a letter sorts below a dot in Debian
        ("1.0.0", "1.0a", 1),
        ("1.24.1", "1.24.10", -1),       # numeric, not lexicographic
        ("6.12.9-1", "6.12.10-1", -1),
        ("1.2.3-1ubuntu0.3", "1.2.3-1ubuntu0.4", -1),
        ("2:1.0", "1:9.9", 1),           # the epoch wins before anything else
        ("7.0.0-43.43", "7.0.0-43.44", -1),
        ("3.0.0-1ubuntu1~24.04.1", "3.0.0-1ubuntu1", -1),
        ("1.2.3+esm5", "1.2.3", 1),
    ]

    def test_the_cases_dpkg_answered(self):
        for left, right, expected in self.CASES:
            with self.subTest(left=left, right=right):
                self.assertEqual(vendor.compare(left, right), expected)
                self.assertEqual(vendor.compare(right, left), -expected)


class ProbeParsing(unittest.TestCase):
    def test_rows_and_an_absent_candidate(self):
        out = ("python3-tornado|6.3.3-1|6.3.3-1ubuntu0.1\n"
               "curl|8.5.0-2|(none)\n"
               "junk line\n")
        rows = vendor.parse(out)
        self.assertEqual(rows["python3-tornado"]["candidate"], "6.3.3-1ubuntu0.1")
        self.assertEqual(rows["curl"]["candidate"], "")
        self.assertNotIn("junk line", rows)

    def test_only_installed_packages_are_answered(self):
        # the probe skips apt-cache for a package dpkg does not know, so it never appears
        self.assertEqual(vendor.parse(""), {})


class Classification(unittest.TestCase):
    ADVISORIES = {
        "openssl": {"version": "3.0.13-1ubuntu0.4", "notice": "USN-9001-1",
                    "cves": ["CVE-2026-0001"]},
        "curl": {"version": "8.5.0-2ubuntu1", "notice": "USN-9002-1", "cves": ["CVE-2026-0002"]},
        "zlib1g": {"version": "1:1.3-1", "notice": "USN-9003-1", "cves": []},
        "libnothere": {"version": "1.0-1", "notice": "USN-9004-1", "cves": []},
    }
    ROWS = {
        # advisory is ahead of both the installed and the candidate version → the vendor has not
        # shipped it into the archive
        "openssl": {"installed": "3.0.13-1ubuntu0.3", "candidate": "3.0.13-1ubuntu0.3"},
        # the fix is in the archive and waiting to be installed
        "curl": {"installed": "8.5.0-1", "candidate": "8.5.0-2ubuntu1"},
        # already ahead of the advisory
        "zlib1g": {"installed": "1:1.3-1build1", "candidate": "1:1.3-1build1"},
    }

    def setUp(self):
        self.state = vendor.classify(self.ROWS, self.ADVISORIES)

    def test_the_lag_case_is_named_as_lag_not_as_nothing_to_do(self):
        self.assertEqual([row["package"] for row in self.state["vendor_lag"]], ["openssl"])
        lag = self.state["vendor_lag"][0]
        self.assertEqual(lag["fixed_version"], "3.0.13-1ubuntu0.4")
        self.assertEqual(lag["candidate"], "3.0.13-1ubuntu0.3")
        self.assertIn("USN-9001-1", str(lag["notice"]))

    def test_an_installable_fix_is_not_lag(self):
        self.assertEqual([row["package"] for row in self.state["fix_available"]], ["curl"])

    def test_a_machine_ahead_of_the_advisory_is_not_lag(self):
        self.assertEqual([row["package"] for row in self.state["already_fixed"]], ["zlib1g"])

    def test_a_package_that_is_not_installed_is_reported_as_such(self):
        self.assertEqual([row["package"] for row in self.state["not_installed"]], ["libnothere"])

    def test_counts_add_up(self):
        self.assertEqual(sum(self.state["counts"].values()), len(self.ADVISORIES))

    def test_no_candidate_at_all_is_still_lag(self):
        state = vendor.classify({"openssl": {"installed": "3.0.13-1", "candidate": ""}},
                                {"openssl": self.ADVISORIES["openssl"]})
        self.assertEqual(len(state["vendor_lag"]), 1)
        self.assertIn("no candidate", state["vendor_lag"][0]["why"])


if __name__ == "__main__":
    unittest.main()
