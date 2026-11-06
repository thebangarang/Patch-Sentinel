"""The advice has to be runnable on the machine that was measured.

This file exists because of a real failure: the pane told a user
``python3 -m pip install -U 'filelock>=4.2.1'`` and his ``/usr/bin/python3`` has no pip — the package
lived in a Hermes-managed toolchain, and pip could not have upgraded a pipx or uv tool anyway.

So the rules pinned here are:
  * every store the scan can read has an upgrade story — a template, or an explicit refusal;
  * a template names the tool through ``{tool}``, never a bare ``python3``/``pip``, so the command
    lands in the same environment the scan measured;
  * the resolved path comes from ``command -v`` and is absolute.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import languages  # noqa: E402
from patch_sentinel.sources import shell  # noqa: E402


class EveryStoreHasAnUpgradeStory(unittest.TestCase):
    def test_no_store_is_silently_without_advice(self):
        missing = []
        for ecosystem, spec in languages.INVENTORIES.items():
            for candidate in spec["candidates"]:
                if (ecosystem, candidate["label"]) not in languages.UPGRADE:
                    missing.append(f"{ecosystem}/{candidate['label']}")
        self.assertEqual(missing, [], "these stores would give the user no advice at all")

    def test_every_template_names_the_tool_it_resolved(self):
        for key, entry in languages.UPGRADE.items():
            if entry is None:
                continue
            tool, template = entry
            with self.subTest(store=key):
                self.assertIn("{tool}", template)
                self.assertEqual(key[1].count(tool) or tool in template.split()[0], True)
                # a placeholder we do not fill would reach the user as literal braces
                rendered = template.replace("{tool}", "/x").replace("{spec}", "s") \
                                   .replace("{pkg}", "p").replace("{ver}", "v")
                self.assertNotIn("{", rendered)

    def test_pip_advice_never_says_bare_python3(self):
        template = languages.UPGRADE[("PyPI", "python3 -m pip")][1]
        self.assertTrue(template.startswith("{tool}"))
        self.assertNotIn("python3 -m pip", template)


class ResolutionUsesTheBinaryThatAnswered(unittest.TestCase):
    def setUp(self):
        self._run = shell.run

    def tearDown(self):
        shell.run = self._run

    def test_the_absolute_path_is_used(self):
        shell.run = lambda cmd, target=None, timeout=0, path_prefix=None: (
            0, "/home/u/.hermes/tools/python/bin/pip3\n")
        resolved = languages._resolve_upgrade("PyPI", "pip3", None, 5)
        self.assertEqual(resolved["path"], "/home/u/.hermes/tools/python/bin/pip3")
        self.assertIn("{tool}", resolved["upgrade"])

    def test_an_unresolvable_tool_falls_back_to_its_name_not_to_a_wrong_path(self):
        shell.run = lambda *a, **k: (1, "")
        resolved = languages._resolve_upgrade("PyPI", "pip3", None, 5)
        self.assertEqual(resolved["path"], "pip3")

    def test_hermes_own_environment_is_never_told_to_pip_upgrade_itself(self):
        # the exact failure a user hit: packages inside the agent's venv, told to pip install them
        import sys
        shell.run = lambda *a, **k: (0, sys.prefix + "/bin/pip3\n")
        resolved = languages._resolve_upgrade("PyPI", "pip3", None, 5)
        self.assertIsNone(resolved["upgrade"])
        self.assertIn("hermes update", resolved["why"])

    def test_a_remote_hosts_pip_is_not_ours(self):
        import sys
        shell.run = lambda *a, **k: (0, sys.prefix + "/bin/pip3\n")
        # same path, but the host is remote: sys.prefix says nothing about that machine
        resolved = languages._resolve_upgrade("PyPI", "pip3", "root@vps", 5)
        self.assertIn("{tool}", resolved["upgrade"] or "")

    def test_a_build_dependency_gets_a_refusal_not_a_command(self):
        resolved = languages._resolve_upgrade("Maven", "~/.m2/repository", None, 5)
        self.assertIsNone(resolved["upgrade"])
        self.assertIn("build dependency", resolved["why"])


if __name__ == "__main__":
    unittest.main()
