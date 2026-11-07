"""KEV and EPSS: does a finding have evidence of exploitation behind it?

The rule under test is the plugin's own: a feed that could not be read is *unmeasured*, never "nothing
is exploited". The rest is the join — OSV record → CVE id → CISA KEV entry and EPSS score — which is
the difference between "8 advisories" and "one of these is being used in ransomware campaigns today".
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel import store  # noqa: E402
from patch_sentinel.sources import threat  # noqa: E402

KEV_FIXTURE = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.06",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
         "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
         "knownRansomwareCampaignUse": "Known",
         "requiredAction": "Apply updates per vendor instructions.",
         "shortDescription": "JNDI features do not protect against attacker-controlled LDAP paths."},
        {"cveID": "CVE-2021-45046", "vendorProject": "Apache", "product": "Log4j2",
         "vulnerabilityName": "Apache Log4j2 Denial of Service", "dateAdded": "2021-12-15",
         "knownRansomwareCampaignUse": "Unknown", "requiredAction": "Apply updates.",
         "shortDescription": "Incomplete fix for CVE-2021-44228."},
    ],
}

EPSS_FIXTURE = {"status": "OK", "data": [
    {"cve": "CVE-2021-44228", "epss": "0.999990000", "percentile": "0.999980000", "date": "2026-11-06"},
    {"cve": "CVE-2021-45046", "epss": "0.999770000", "percentile": "0.999700000", "date": "2026-11-06"},
]}


class KevParsing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # a data dir of its own: the KEV cache is a file on disk, and a leftover from another test
        # would answer for the network and make the "unmeasured" case pass for the wrong reason
        os.environ["PATCH_SENTINEL_DATA"] = self.tmp.name
        store.configure({"data_dir": self.tmp.name})
        self._get = threat._get

    def tearDown(self):
        threat._get = self._get
        threat._EPSS_CACHE.clear()
        os.environ.pop("PATCH_SENTINEL_DATA", None)
        self.tmp.cleanup()

    def test_entries_are_keyed_by_cve_with_the_fields_that_matter(self):
        threat._get = lambda url, timeout=0: json.dumps(KEV_FIXTURE).encode()
        known = threat.kev(force=True)
        self.assertEqual(set(known), {"CVE-2021-44228", "CVE-2021-45046"})
        self.assertTrue(known["CVE-2021-44228"]["ransomware"])
        self.assertFalse(known["CVE-2021-45046"]["ransomware"])
        self.assertEqual(known["CVE-2021-44228"]["due"], "2021-12-24")

    def test_a_feed_that_cannot_be_read_is_unmeasured_not_empty(self):
        def boom(*a, **k):
            raise OSError("network down")
        threat._get = boom
        self.assertEqual(threat.kev(force=True), {})
        summary = threat.annotate([{"id": "CVE-2021-44228", "package": "x"}])
        self.assertEqual(summary["kev_state"], "unmeasured")
        self.assertEqual(summary["kev_count"], 0)
        # and the finding must NOT be marked "not exploited" — it is simply not known either way
        self.assertNotIn("kev", summary)

    def test_a_fresh_cache_is_used_without_touching_the_network(self):
        threat._get = lambda url, timeout=0: json.dumps(KEV_FIXTURE).encode()
        threat.kev(force=True)
        calls = []
        threat._get = lambda url, timeout=0: calls.append(url) or b"{}"
        known = threat.kev()
        self.assertEqual(len(known), 2)
        self.assertEqual(calls, [], "a 12 h cache must not re-download a 1.8 MB feed on every scan")


class CveIds(unittest.TestCase):
    CASES = [
        ({"id": "CVE-2021-44228"}, ["CVE-2021-44228"]),
        ({"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"]}, ["CVE-2021-44228"]),
        # distro records keep the CVE inside their own namespace
        ({"id": "DEBIAN-CVE-2023-5363"}, ["CVE-2023-5363"]),
        ({"id": "UBUNTU-CVE-2024-3094"}, ["CVE-2024-3094"]),
        # an advisory with no CVE at all is not an error: it simply has no KEV entry
        ({"id": "GHSA-8489-44mv-ggj8", "aliases": []}, []),
    ]

    def test_ids_are_found_wherever_they_hide(self):
        for finding, expected in self.CASES:
            with self.subTest(finding=finding):
                self.assertEqual(threat.cve_ids(finding), expected)


class Annotate(unittest.TestCase):
    def setUp(self):
        store.configure({"data_dir": tempfile.mkdtemp()})
        threat._EPSS_CACHE.clear()
        self._get = threat._get

        def fake_get(url, timeout=0):
            if "epss" in url:
                return json.dumps(EPSS_FIXTURE).encode()
            return json.dumps(KEV_FIXTURE).encode()
        threat._get = fake_get

    def tearDown(self):
        threat._get = self._get
        threat._EPSS_CACHE.clear()

    def test_an_exploited_finding_is_marked_with_the_kev_facts(self):
        findings = [{"id": "GHSA-jfh8-c2jp-5v3q", "package": "log4j-core",
                     "aliases": ["CVE-2021-44228"]}]
        summary = threat.annotate(findings)
        self.assertEqual(summary["kev_state"], "measured")
        self.assertEqual(summary["exploited"], ["CVE-2021-44228"])
        self.assertTrue(findings[0]["kev"]["ransomware"])
        self.assertAlmostEqual(findings[0]["epss"], 0.99999, places=5)
        self.assertEqual(summary["kev_count"], 1)

    def test_a_clean_finding_gets_no_kev_key_and_still_gets_a_score(self):
        findings = [{"id": "GHSA-8489-44mv-ggj8", "package": "log4j-core"}]
        summary = threat.annotate(findings)
        self.assertNotIn("kev", findings[0])
        self.assertEqual(summary["kev_count"], 0)
        self.assertEqual(summary["kev_state"], "measured")

    def test_rows_that_carry_cve_lists_are_annotated_too(self):
        rows = [{"package": "openssl", "cves": ["CVE-2021-44228"]},
                {"package": "bash", "cves": ["CVE-2014-6271"]}]
        summary = threat.annotate_rows(rows)
        self.assertTrue(rows[0].get("kev"))
        self.assertNotIn("kev", rows[1])          # not in this fixture
        self.assertEqual(summary["exploited"], ["CVE-2021-44228"])


if __name__ == "__main__":
    unittest.main()
