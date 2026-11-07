"""Fedora's vendor-lag source: Bodhi.

The API has three traps, and each one is a test here: a release must be a Bodhi tag (``F45``), a build
NVR has to be split from the right because package names contain dashes, and an update with no ``cves``
list is still an advisory (its ``FEDORA-…`` alias is the identifier).
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import bodhi  # noqa: E402


def update(alias, nvrs, cves=None, kind="security", status="stable"):
    return {"alias": alias, "type": kind, "status": status,
            "builds": [{"nvr": nvr} for nvr in nvrs], "cves": cves}


class Releases(unittest.TestCase):
    def test_a_number_becomes_bodhis_tag(self):
        self.assertEqual(bodhi.release_tag("45"), "F45")
        self.assertEqual(bodhi.release_tag("45.1"), "F45")
        self.assertEqual(bodhi.release_tag("rawhide"), "rawhide")

    def test_a_codename_is_refused_rather_than_guessed(self):
        self.assertIsNone(bodhi.release_tag("Resolute Raccoon"))
        self.assertIsNone(bodhi.release_tag(""))

    def test_nvr_splits_from_the_right(self):
        self.assertEqual(bodhi._split_nvr("ansible-core-2.22.0~b2-1.eln159"),
                         ("ansible-core", "2.22.0~b2"))
        self.assertEqual(bodhi._split_nvr("openssl-4.0.3-1.fc45"), ("openssl", "4.0.3"))
        self.assertIsNone(bodhi._split_nvr("nonsense"))


class Index(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def serve(self, pages):
        """Stub urlopen with one payload per page request, in order."""
        remaining = list(pages)

        def fake_urlopen(request, timeout=None):
            payload = remaining.pop(0) if remaining else {"updates": []}
            return io.BytesIO(json.dumps(payload).encode())

        return mock.patch.object(bodhi.urllib.request, "urlopen", side_effect=fake_urlopen)

    def test_the_newest_security_build_wins_per_package(self):
        pages = [{"updates": [
            update("FEDORA-2026-a", ["openssl-3.2.4-1.fc45", "openssl-libs-3.2.4-1.fc45"],
                   cves=["CVE-2026-1"]),
            update("FEDORA-2026-b", ["openssl-3.2.5-2.fc45"], cves=["CVE-2026-2", "CVE-2026-3"]),
            update("FEDORA-2026-c", ["bash-5.2.0-1.fc45"], kind="bugfix"),      # not security
            update("FEDORA-2026-d", ["zlib-1.3-1.fc45"], status="testing"),      # not stable
        ]}]
        with self.serve(pages):
            index = bodhi.advisories("45", pages=1, cache_dir=self.cache)
        self.assertEqual(index["openssl"]["version"], "3.2.5")
        self.assertEqual(index["openssl"]["notice"], "FEDORA-2026-b")
        self.assertNotIn("bash", index)
        self.assertNotIn("zlib", index)
        self.assertEqual(index["openssl-libs"]["version"], "3.2.4")

    def test_an_update_without_cves_still_has_an_identifier(self):
        pages = [{"updates": [update("FEDORA-2026-x", ["curl-8.0-1.fc45"], cves=None)]}]
        with self.serve(pages):
            index = bodhi.advisories("45", pages=1, cache_dir=self.cache)
        self.assertEqual(index["curl"]["cves"], ["FEDORA-2026-x"])

    def test_the_cve_list_is_capped(self):
        many = [f"CVE-2026-{n}" for n in range(50)]
        pages = [{"updates": [update("FEDORA-2026-y", ["kernel-6.0-1.fc45"], cves=many)]}]
        with self.serve(pages):
            index = bodhi.advisories("45", pages=1, cache_dir=self.cache)
        self.assertEqual(len(index["kernel"]["cves"]), bodhi.MAX_CVES)

    def test_the_second_scan_reads_from_disk(self):
        pages = [{"updates": [update("FEDORA-2026-a", ["openssl-3.2.5-2.fc45"])]}]
        with self.serve(pages):
            first = bodhi.advisories("45", pages=1, cache_dir=self.cache)
        with mock.patch.object(bodhi.urllib.request, "urlopen",
                               side_effect=AssertionError("the network was used twice")):
            second = bodhi.advisories("45", pages=1, cache_dir=self.cache)
        self.assertEqual(first, second)

    def test_a_network_failure_raises_so_the_caller_says_unmeasured(self):
        with mock.patch.object(bodhi.urllib.request, "urlopen", side_effect=OSError("no route")):
            with self.assertRaises(OSError):
                bodhi.advisories("45", pages=1, cache_dir=self.cache)


if __name__ == "__main__":
    unittest.main()
