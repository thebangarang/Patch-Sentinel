"""The language layer: real inventories, a real OSV answer, and the refusals.

Fixtures are captured, not written: ``npm_ls_g.json`` and ``pip_list.json`` are this machine's own
tool output, ``osv_querybatch.json`` is a real batch answer for lodash 4.17.20 (4 advisories),
requests 2.31.0 (6) and lodash 9.9.9 (0), and ``osv_vuln_lodash.json`` is the real record for one
of them, including the ``fixed: 4.17.21`` that makes a finding actionable.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel import tools                              # noqa: E402
from patch_sentinel.sources import languages, osv             # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class Inventories(unittest.TestCase):
    def test_npm_global_tree(self):
        components = languages.parse_npm((FIXTURES / "npm_ls_g.json").read_text(encoding="utf-8"))
        self.assertEqual(components, [{"package": "npm", "version": "11.20.0"}])

    def test_pip_json(self):
        components = languages.parse_pip((FIXTURES / "pip_list.json").read_text(encoding="utf-8"))
        self.assertGreater(len(components), 50)
        names = {c["package"] for c in components}
        self.assertIn("aiohttp", names)
        aiohttp = next(c for c in components if c["package"] == "aiohttp")
        self.assertEqual(aiohttp["version"], "3.14.5")

    def test_unparseable_output_is_not_an_empty_list_of_safe_packages(self):
        self.assertEqual(languages.parse_pip("not json"), [])
        self.assertEqual(languages.parse_npm("[]"), [])

    def test_the_ecosystems_are_the_osv_spellings(self):
        self.assertIn("PyPI", languages.INVENTORIES)
        self.assertIn("npm", languages.INVENTORIES)


class OsvAnswers(unittest.TestCase):
    def setUp(self):
        self.batch = fixture("osv_querybatch.json")
        self.record = fixture("osv_vuln_lodash.json")

    def test_the_batch_keeps_the_query_order(self):
        self.assertEqual([len(r.get("vulns") or []) for r in self.batch["results"]], [4, 6, 0])

    def test_a_fixed_version_is_read_from_the_range(self):
        self.assertIn("4.17.21", osv.fixed_versions(self.record, "npm", "lodash"))

    def test_fixed_versions_ignore_another_package(self):
        self.assertEqual(osv.fixed_versions(self.record, "npm", "moment"), [])

    def test_severity_is_a_band_not_a_recomputed_score(self):
        band = osv.severity(self.record)
        self.assertIsNotNone(band)
        assert band is not None
        self.assertNotIn("%", band)

    def test_a_summary_carries_the_four_things_a_person_needs(self):
        summary = osv.summarise(self.record, "npm", "lodash")
        self.assertEqual(summary["id"], self.record["id"])
        self.assertTrue(summary["summary"])
        self.assertIn("4.17.21", summary["fixed"])
        self.assertTrue(summary["url"].startswith("https://osv.dev/vulnerability/"))

    def test_a_network_failure_is_a_refusal_not_an_empty_clean(self):
        with mock.patch.object(osv.urllib.request, "urlopen", side_effect=OSError("no route")):
            answer = osv.query([{"package": "lodash", "version": "4.17.20", "ecosystem": "npm"}])
        self.assertFalse(answer["ok"])
        self.assertIn("no route", answer["why"])
        self.assertEqual(answer["results"], [])


class MoreRuntimes(unittest.TestCase):
    """PHP, Ruby, Rust and .NET — added because a machine's attack surface is not just npm and pip.

    The composer and gem fixtures are real captures from containers (2026-11-06); cargo and dotnet
    outputs are the tools' documented shapes, because no host here has those toolchains yet — a
    parser that meets an unexpected shape returns no components, which reads as "empty", never as
    clean.
    """

    def test_the_registry_and_the_parsers_agree(self):
        # a new ecosystem without a parser would silently collect nothing
        self.assertEqual(set(languages.INVENTORIES), set(languages.PARSERS))

    def test_composer_global_show(self):
        rows = languages.parse_composer((FIXTURES / "composer_global_show.json").read_text())
        self.assertIn({"package": "monolog/monolog", "version": "2.0.0"}, rows)
        self.assertIn({"package": "psr/log", "version": "1.1.4"}, rows)

    def test_gem_list_local(self):
        rows = languages.parse_gem((FIXTURES / "gem_list_local.txt").read_text())
        self.assertIn({"package": "rack", "version": "2.2.0"}, rows)
        # "benchmark (default: 0.4.0)" is a real line: OSV knows the version as 0.4.0
        self.assertIn({"package": "benchmark", "version": "0.4.0"}, rows)
        self.assertFalse([r for r in rows if "default" in r["version"]])

    def test_cargo_install_list(self):
        text = "ripgrep v13.0.0:\n    rg\ncargo-binstall v1.6.4:\n    cargo-binstall\n"
        self.assertEqual(languages.parse_cargo(text),
                         [{"package": "ripgrep", "version": "13.0.0"},
                          {"package": "cargo-binstall", "version": "1.6.4"}])

    def test_dotnet_tool_list(self):
        text = ("Package Id      Version      Commands\n"
                "----------------------------------------\n"
                "dotnetsay       2.1.4        dotnetsay\n")
        self.assertEqual(languages.parse_dotnet(text),
                         [{"package": "dotnetsay", "version": "2.1.4"}])

    def test_an_unexpected_shape_is_empty_not_clean(self):
        self.assertEqual(languages.parse_cargo("error: no such command"), [])
        self.assertEqual(languages.parse_gem("*** LOCAL GEMS ***"), [])
        self.assertEqual(languages.parse_composer("<html>proxy error</html>"), [])


class FixVersions(unittest.TestCase):
    """`fixed` must hold versions an operator can install — nothing else."""

    def test_a_git_commit_is_not_a_fix_version(self):
        # measured on urllib3 1.24.1: eleven of twenty-six matches carried commit hashes here
        record = {"affected": [{
            "package": {"name": "urllib3", "ecosystem": "PyPI"},
            "ranges": [{"events": [{"introduced": "0"},
                                   {"fixed": "01220354d389cd05474713f8c982d05c9b17aafb"},
                                   {"fixed": "2.0.6"}]}],
        }]}
        self.assertEqual(osv.fixed_versions(record, "PyPI", "urllib3"), ["2.0.6"])

    def test_a_real_record_keeps_its_version(self):
        record = json.loads((FIXTURES / "osv_vuln_lodash.json").read_text())
        self.assertIn("4.17.21", osv.fixed_versions(record, "npm", "lodash"))


class LibrariesTool(unittest.TestCase):
    """The handler, with the network and the shell replaced by their captured answers."""

    COMPONENTS = [{"package": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                  {"package": "requests", "version": "2.31.0", "ecosystem": "PyPI"}]

    def _run(self, components, query_answer, record):
        collected = {"components": components, "outcomes": {"npm": "ok", "PyPI": "ok"},
                     "details": {"npm": "npm's global tree", "PyPI": "pip3"},
                     "measured_at": "2026-11-06T15:00:00+00:00", "truncated": False,
                     "by_ecosystem": {"npm": 1, "PyPI": 1}}
        with mock.patch.object(languages, "collect", return_value=collected), \
                mock.patch.object(osv, "query", return_value=query_answer), \
                mock.patch.object(osv, "vuln", return_value=record):
            return json.loads(tools.cve_libraries({}))

    def test_a_vulnerable_package_comes_back_with_its_fix(self):
        record = fixture("osv_vuln_lodash.json")
        answer = {"ok": True, "queried": 2, "results": [[record["id"]], []]}
        payload = self._run(self.COMPONENTS, answer, record)
        self.assertEqual(payload["exit_code"], 1)
        self.assertEqual(payload["vulnerable_count"], 1)
        entry = payload["vulnerable"][0]
        self.assertEqual((entry["package"], entry["version"]), ("lodash", "4.17.20"))
        self.assertIn("4.17.21", entry["fixed"])

    def test_nothing_vulnerable_is_a_clean_zero(self):
        payload = self._run(self.COMPONENTS, {"ok": True, "queried": 2, "results": [[], []]}, None)
        self.assertEqual(payload["exit_code"], 0)
        self.assertEqual(payload["vulnerable"], [])

    def test_no_measurable_ecosystem_is_not_a_clean_zero(self):
        payload = self._run([], {"ok": True, "queried": 0, "results": []}, None)
        self.assertEqual(payload["exit_code"], 2)
        self.assertIn("not the same as clean", payload["reason"])

    def test_an_unreachable_database_is_a_refusal(self):
        answer = {"ok": False, "why": "OSV answered HTTP 503", "results": [], "queried": 2}
        payload = self._run(self.COMPONENTS, answer, None)
        self.assertEqual(payload["exit_code"], 2)
        self.assertIn("unmeasured, not clean", payload["reason"])

    def test_the_limits_are_stated_in_the_payload(self):
        payload = self._run(self.COMPONENTS, {"ok": True, "queried": 2, "results": [[], []]}, None)
        self.assertTrue(payload["limits"]["not_measured"])
        self.assertIn("container image", " ".join(payload["limits"]["not_measured"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
