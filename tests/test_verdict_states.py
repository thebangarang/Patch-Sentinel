"""The four states of a fix, the pockets a host is subscribed to, and the SBOM export.

Each of these exists because two facts used to be indistinguishable in the output:

* a vendor **refusal** read the same as a vendor **delay** (fix_state);
* "no archive has it" read the same as "this host is not subscribed to the pocket that has it"
  (repos);
* a release that **stopped receiving fixes** looked like a healthy host with nothing pending
  (support);
* and the inventory was locked in a private store, so nobody could re-check it (sbom).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import osv, repos, sbom, support  # noqa: E402


class FixState(unittest.TestCase):
    def test_a_published_fix_is_fixed(self):
        record = {"id": "X", "affected": [{"package": {"ecosystem": "PyPI", "name": "pillow"},
                                           "ranges": [{"events": [{"fixed": "13.0.0"}]}]}]}
        self.assertEqual(osv.fix_state(record, "PyPI", "pillow"), "fixed")

    def test_no_fix_event_is_not_fixed(self):
        record = {"id": "Y", "affected": [{"package": {"ecosystem": "PyPI", "name": "msgpack"},
                                           "ranges": [{"events": [{"introduced": "0"}]}]}]}
        self.assertEqual(osv.fix_state(record, "PyPI", "msgpack"), "not-fixed")

    def test_a_vendor_refusal_is_its_own_state(self):
        record = {"id": "Z", "affected": [{"package": {"ecosystem": "Debian", "name": "zlib"},
                                           "ecosystem_specific": {"status": "ignored"}}]}
        self.assertEqual(osv.fix_state(record, "Debian", "zlib"), "won't-fix")

    def test_a_record_nobody_could_read_is_unknown(self):
        self.assertEqual(osv.fix_state({}, "PyPI", "anything"), "unknown")


class Pockets(unittest.TestCase):
    def test_a_standard_debian_sources_list(self):
        text = ("deb http://deb.debian.org/debian bookworm main\n"
                "deb http://security.debian.org/debian-security bookworm-security main\n"
                "deb http://deb.debian.org/debian bookworm-updates main\n"
                "# deb http://deb.debian.org/debian bookworm-backports main\n")
        pockets = repos.parse_apt(text)
        self.assertTrue(pockets["security"])
        self.assertTrue(pockets["updates"])
        self.assertFalse(pockets["backports"], "a commented-out line is not a subscription")

    def test_a_host_with_no_security_pocket_is_a_configuration_fact(self):
        text = "deb http://deb.debian.org/debian bookworm main\n"
        pockets = repos.parse_apt(text)
        self.assertFalse(pockets["security"])

    def test_ubuntu_esm_appears_as_a_pocket(self):
        text = "deb https://esm.ubuntu.com/apps/ubuntu jammy-apps-security main\n"
        self.assertTrue(repos.parse_apt(text)["security"])

    def test_deb822_suites_count_too(self):
        text = ("Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\n"
                "Suites: resolute resolute-updates resolute-security\n")
        self.assertTrue(repos.parse_apt(text)["security"])

    def test_a_rpm_repo_list(self):
        text = ("repo id            repo name\n"
                "fedora             Fedora 45 - x86_64\n"
                "fedora-updates     Fedora 45 - x86_64 - Updates\n")
        pockets = repos.parse_repos(text)
        self.assertTrue(pockets["updates"])


class Lifecycle(unittest.TestCase):
    def test_a_supported_release(self):
        state = support.state("ubuntu", "24.04", today="2026-11-07")
        self.assertEqual(state["state"], "supported")
        self.assertEqual(state["ends"], "2029-04-30")

    def test_an_end_of_life_release_says_so(self):
        state = support.state("opensuse-leap", "15.6", today="2026-11-07")
        self.assertEqual(state["state"], "end-of-life")

    def test_an_unknown_release_is_not_assumed_supported(self):
        state = support.state("arch", "rolling", today="2026-11-07")
        self.assertEqual(state["state"], "unknown")
        self.assertIn("not assumed supported", state["why"])

    def test_the_table_is_stamped(self):
        self.assertIn("compiled", support.state("debian", "12", today="2026-11-07")["why"])


class Bom(unittest.TestCase):
    def test_a_cyclonedx_document_with_purls(self):
        components = [
            {"ecosystem": "PyPI", "package": "pillow", "version": "12.3.0", "source": "env:/a/.venv"},
            {"ecosystem": "Maven", "package": "org.springframework:spring-core", "version": "6.1.0",
             "source": "jar:/opt/app.jar"},
            {"ecosystem": "PyPI", "package": "pillow", "version": "12.3.0", "source": "env:/b/.venv"},
        ]
        document = sbom.build(components, "beelink", os_label="ubuntu 26.04",
                              pending=[{"package": "openssl", "from": "3.0.1", "to": "3.0.2"}])
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(document["specVersion"], "1.5")
        # the same package in two environments is one component
        self.assertEqual(len(document["components"]), 3)
        purls = {item["purl"] for item in document["components"] if "purl" in item}
        self.assertIn("pkg:pypi/pillow@12.3.0", purls)
        self.assertIn("pkg:maven/org.springframework/spring-core@6.1.0", purls)
        self.assertTrue(document["serialNumber"].startswith("urn:uuid:"))

    def test_a_scoped_npm_package_keeps_its_scope(self):
        self.assertEqual(sbom.purl("npm", "@bitwarden/cli", "2026.7.0"),
                         "pkg:npm/%40bitwarden/cli@2026.7.0")

    def test_the_document_admits_what_it_does_not_hold(self):
        document = sbom.build([], "beelink")
        names = {prop["name"]: prop["value"] for prop in document["metadata"]["properties"]}
        self.assertEqual(names["patch-sentinel:complete"], "false")
        self.assertIn("OS package", names["patch-sentinel:not-included"])

    def test_it_is_json_serialisable(self):
        document = sbom.build([{"ecosystem": "npm", "package": "lodash", "version": "4.17.21"}], "x")
        json.dumps(document)


if __name__ == "__main__":
    unittest.main()
