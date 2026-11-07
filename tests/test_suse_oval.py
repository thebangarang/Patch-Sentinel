"""openSUSE/SUSE vendor lag from the OVAL document.

The document is 12 MB compressed and past 100 MB expanded, so this is parsed with ``iterparse``; the
template in these tests is the smallest thing that exercises the same path — objects, states, tests and
definitions joined across four tables, with the CVE in the definition title.

What the tests protect: the epoch strip (``0:2.44-150000.3.3.1`` is compared as ``2.44-150000.3.3.1``),
the "definition without a CVE is not an advisory" rule, the refusal to call a broken document empty,
and the feed's own date — a stale feed is quoted, not hidden.
"""
from __future__ import annotations

import gzip
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import suse_oval  # noqa: E402

TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions>
    <definition id="def:1" class="vulnerability">
      <metadata><title>{title1}</title></metadata>
      <criteria><criterion test_ref="t:1"/></criteria>
    </definition>
    <definition id="def:2" class="vulnerability">
      <metadata><title>{title2}</title></metadata>
      <criteria><criterion test_ref="t:2"/></criteria>
    </definition>
    <definition id="def:3" class="vulnerability">
      <metadata><title>CVE-2026-0003</title></metadata>
      <criteria><criterion test_ref="t:3"/></criteria>
    </definition>
  </definitions>
  <tests>
    <rpminfo_test id="t:1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <object object_ref="o:1"/><state state_ref="s:1"/>
    </rpminfo_test>
    <rpminfo_test id="t:2" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <object object_ref="o:2"/><state state_ref="s:2"/>
    </rpminfo_test>
    <rpminfo_test id="t:3" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <object object_ref="o:1"/><state state_ref="s:3"/>
    </rpminfo_test>
  </tests>
  <objects>
    <rpminfo_object id="o:1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name>openssl-3</name>
    </rpminfo_object>
    <rpminfo_object id="o:2" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <name>nginx</name>
    </rpminfo_object>
  </objects>
  <states>
    <rpminfo_state id="s:1" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <evr datatype="evr_string" operation="less than">0:3.1.4-150600.5.1</evr>
    </rpminfo_state>
    <rpminfo_state id="s:2" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <evr datatype="evr_string" operation="less than">1.24.0-1.1</evr>
    </rpminfo_state>
    <rpminfo_state id="s:3" xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
      <evr datatype="evr_string" operation="less than">0:3.1.5-150600.6.1</evr>
    </rpminfo_state>
  </states>
</oval_definitions>
"""


class Product(unittest.TestCase):
    def test_each_maintained_release_has_its_document(self):
        self.assertEqual(suse_oval.product_file("opensuse-leap", "15.6"),
                         "opensuse.leap.15.6.xml.gz")
        self.assertEqual(suse_oval.product_file("opensuse-tumbleweed", "20261107"),
                         "opensuse.tumbleweed.xml.gz")
        self.assertEqual(suse_oval.product_file("sles", "16.0"), "suse.sle.16.0.xml.gz")

    def test_an_unpublished_product_is_refused(self):
        self.assertIsNone(suse_oval.product_file("opensuse-leap", "not-a-version"))
        self.assertIsNone(suse_oval.product_file("debian", "12"))


class Parsing(unittest.TestCase):
    def write(self, text: str) -> Path:
        handle = tempfile.NamedTemporaryFile(suffix=".xml.gz", delete=False)
        handle.close()
        path = Path(handle.name)
        with gzip.open(path, "wt", encoding="utf-8") as stream:
            stream.write(text)
        return path

    def test_fixed_versions_are_joined_and_the_epoch_is_stripped(self):
        path = self.write(TEMPLATE.format(title1="CVE-2026-0001", title2="CVE-2026-0002"))
        try:
            index = suse_oval.parse(path)
        finally:
            path.unlink()
        self.assertEqual(index["openssl-3"]["version"], "3.1.5-150600.6.1")
        self.assertEqual(index["openssl-3"]["cve_count"], 2)
        self.assertEqual(index["nginx"]["version"], "1.24.0-1.1")
        self.assertEqual(index["nginx"]["notice"], "CVE-2026-0002")

    def test_a_definition_without_a_cve_is_not_an_advisory(self):
        path = self.write(TEMPLATE.format(title1="Security update for openssl", title2="CVE-2026-2"))
        try:
            index = suse_oval.parse(path)
        finally:
            path.unlink()
        # def:1 and def:3 both point at openssl-3, but only def:3 is a CVE
        self.assertEqual(index["openssl-3"]["cve_count"], 1)

    def test_a_document_without_tests_is_not_an_empty_index(self):
        broken = ('<?xml version="1.0"?>'
                  '<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">'
                  '<definitions/><tests/><objects/><states/></oval_definitions>')
        path = self.write(broken)
        try:
            with self.assertRaises(ValueError):
                suse_oval.parse(path)
        finally:
            path.unlink()

    def test_the_feed_date_is_quoted_and_aged(self):
        path = self.write(TEMPLATE.format(title1="CVE-2026-1", title2="CVE-2026-2"))
        meta = {"last_modified": "Thu, 25 Jun 2026 15:58:48 GMT",
                "fetched_at": 0, "source_url": "https://example/leap.xml.gz"}
        try:
            with mock.patch.object(suse_oval, "fetch", return_value=(path, meta)):
                index, feed = suse_oval.advisories("opensuse-leap", "15.6")
        finally:
            path.unlink()
        self.assertTrue(index)
        self.assertTrue(feed["stale"], feed)
        self.assertGreater(feed["age_days"], suse_oval.STALE_DAYS)
        self.assertIn("25 Jun 2026", feed["feed_date"])


if __name__ == "__main__":
    unittest.main()
