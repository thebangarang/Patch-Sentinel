"""Project lockfiles: the dependencies a machine-wide scan cannot see.

Each parser is tested against the shape its tool actually writes (v1 vs v2 npm lockfiles, yarn v1 vs
berry, poetry vs Pipfile). The walker is tested for the two ways it can lie: counting a `>=` range as a
version, and reading into `node_modules`.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import projects  # noqa: E402


class Parsers(unittest.TestCase):
    def test_npm_v2_lock_uses_the_packages_map(self):
        text = json.dumps({"lockfileVersion": 2, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.4"},
            "node_modules/@scope/pkg": {"version": "2.1.0"}}})
        rows = dict(projects.parse_npm_lock(text))
        self.assertEqual(rows.get("lodash"), "4.17.4")
        self.assertNotIn("", rows)

    def test_npm_v1_lock_uses_dependencies(self):
        text = json.dumps({"lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.4"}}})
        self.assertEqual(projects.parse_npm_lock(text), [("lodash", "4.17.4")])

    def test_yarn_v1_block(self):
        text = ('lodash@^4.17.0:\n  version "4.17.4"\n  resolved "https://registry/yarn"\n'
                '"@babel/core@^7.0.0":\n  version "7.1.0"\n')
        rows = dict(projects.parse_yarn_lock(text))
        self.assertEqual(rows.get("lodash"), "4.17.4")
        self.assertEqual(rows.get("@babel/core"), "7.1.0")

    def test_requirements_only_takes_pinned_versions(self):
        text = ("jinja2==2.10\n"
                "requests>=2.0\n"
                "-r other.txt\n"
                "urllib3==1.24.1  # pinned\n")
        rows = dict(projects.parse_pip_requirements(text))
        self.assertEqual(rows, {"jinja2": "2.10", "urllib3": "1.24.1"})

    def test_poetry_lock_blocks(self):
        text = ('[[package]]\nname = "jinja2"\nversion = "2.10"\n\n[[package]]\n'
                'name = "click"\nversion = "8.1.7"\n')
        self.assertEqual(dict(projects.parse_poetry_lock(text)),
                         {"jinja2": "2.10", "click": "8.1.7"})

    def test_pipfile_lock_strips_the_equals(self):
        text = json.dumps({"default": {"jinja2": {"version": "==2.10"}}})
        self.assertEqual(projects.parse_pipfile_lock(text), [("jinja2", "2.10")])

    def test_go_sum_dedupes_and_drops_go_mod_lines(self):
        text = ("rsc.io/quote v1.5.2 h1:abc=\n"
                "rsc.io/quote v1.5.2/go.mod h1:def=\n"
                "golang.org/x/text v0.3.0 h1:ghi=\n")
        self.assertEqual(projects.parse_go_sum(text),
                         [("rsc.io/quote", "v1.5.2"), ("golang.org/x/text", "v0.3.0")])

    def test_cargo_lock_blocks(self):
        text = '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
        self.assertEqual(projects.parse_cargo_lock(text), [("serde", "1.0.0")])

    def test_composer_lock_strips_the_v(self):
        text = json.dumps({"packages": [{"name": "monolog/monolog", "version": "v2.0.0"}]})
        self.assertEqual(projects.parse_composer_lock(text), [("monolog/monolog", "2.0.0")])

    def test_gemfile_lock_reads_the_specs_block(self):
        text = ("GEM\n  remote: https://rubygems.org/\n  specs:\n"
                "    rack (2.2.0)\n    rake (13.0.1)\n\nPLATFORMS\n  ruby\n")
        self.assertEqual(dict(projects.parse_gemfile_lock(text)),
                         {"rack": "2.2.0", "rake": "13.0.1"})

    def test_pubspec_lock_pairs_name_and_version(self):
        text = ("packages:\n  http:\n    dependency: transitive\n    version: \"0.13.6\"\n")
        self.assertEqual(projects.parse_pubspec_lock(text), [("http", "0.13.6")])


class Walking(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_it_finds_lockfiles_and_reports_each_one(self):
        self.write("requirements.txt", "jinja2==2.10\n")
        self.write("front/package-lock.json", json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.4"}}}))
        out = projects.read(str(self.root))
        self.assertEqual({(c["ecosystem"], c["package"]) for c in out["components"]},
                         {("PyPI", "jinja2"), ("npm", "lodash")})
        self.assertEqual(len(out["files"]), 2)
        self.assertTrue(all(v.startswith("read") for v in out["files"].values()))

    def test_node_modules_is_never_read(self):
        self.write("node_modules/thing/package-lock.json",
                   json.dumps({"packages": {"node_modules/ignored": {"version": "1.0.0"}}}))
        self.write("requirements.txt", "jinja2==2.10\n")
        out = projects.read(str(self.root))
        self.assertEqual([c["package"] for c in out["components"]], ["jinja2"])

    def test_a_malformed_lockfile_is_an_outcome_not_a_crash(self):
        self.write("package-lock.json", "{not json")
        out = projects.read(str(self.root))
        self.assertEqual(out["components"], [])
        self.assertIn("unreadable", out["files"]["package-lock.json"])

    def test_no_lockfile_says_so_instead_of_returning_nothing(self):
        self.write("README.md", "hi")
        out = projects.read(str(self.root))
        self.assertEqual(out["components"], [])
        self.assertTrue(any("no lockfile" in value for value in out["files"].values()))

    def test_a_missing_directory_is_reported(self):
        out = projects.read(str(self.root / "nope"))
        self.assertEqual(out["components"], [])
        self.assertIn("not a directory", out["files"][str(self.root / "nope")])


if __name__ == "__main__":
    unittest.main()
