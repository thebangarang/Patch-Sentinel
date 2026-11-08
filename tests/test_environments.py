"""Project environments: every virtualenv on the machine.

The first version of this walk found 485 "environments" — all of them uv's unpacked-wheel cache, whose
`*.dist-info` directories look identical to an installed environment. The tests below pin the two
guards that fixed it: the path must name a venv, and trees that are not the operator's (the agent's
own home, a backup of it, the package cache) are excluded **in the find**, because `head` runs before
Python sees a line.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import environments, shell  # noqa: E402


class Parsing(unittest.TestCase):
    def test_a_dist_info_name_is_the_package_and_the_version(self):
        rows = environments.parse(["/home/x/proj/.venv/lib/python3.12/site-packages/requests-2.31.0.dist-info"])
        self.assertEqual(rows[0]["package"], "requests")
        self.assertEqual(rows[0]["version"], "2.31.0")
        self.assertEqual(rows[0]["ecosystem"], "PyPI")

    def test_a_name_with_dashes_and_underscores_is_normalised(self):
        rows = environments.parse([
            "/srv/app/venv/lib/python3.11/site-packages/python_dateutil-2.8.2.dist-info",
            "/srv/app/venv/lib/python3.11/site-packages/zope.interface-6.0.dist-info",
        ])
        names = {row["package"] for row in rows}
        self.assertIn("python-dateutil", names)
        self.assertIn("zope.interface", names)

    def test_a_user_installed_package_is_found(self):
        """`pip install --user` puts packages in ~/.local/lib/pythonX.Y/site-packages, which is the
        only install route PEP 668 leaves on Debian and Ubuntu — it must not be invisible."""
        rows = environments.parse([os.path.expanduser(
            "~/.local/lib/python3.11/site-packages/urllib3-1.24.1.dist-info")])
        self.assertEqual(len(rows), 1, "a user-site package was not read")
        self.assertEqual(rows[0]["package"], "urllib3")
        self.assertIn("site-packages", rows[0]["source"])

    def test_the_environment_is_named_as_the_source(self):
        rows = environments.parse(["/home/x/projects/api/.venv/lib/python3.12/site-packages/flask-3.0.0.dist-info"])
        self.assertEqual(rows[0]["source"], "env:/home/x/projects/api/.venv")

    def test_the_same_package_in_two_projects_is_two_components(self):
        rows = environments.parse([
            "/home/x/projects/a/.venv/lib/python3.12/site-packages/flask-3.0.0.dist-info",
            "/home/x/projects/b/.venv/lib/python3.12/site-packages/flask-3.0.0.dist-info",
        ])
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["source"] for row in rows},
                         {"env:/home/x/projects/a/.venv", "env:/home/x/projects/b/.venv"})

    def test_a_package_cache_path_is_dropped_even_if_it_reaches_the_parser(self):
        rows = environments.parse(["/home/x/.cache/uv/archive-v0/abc/click-8.0.0.dist-info"])
        self.assertEqual(rows, [])

    def test_the_agents_own_home_is_dropped(self):
        rows = environments.parse(["/home/x/.hermes/installs/1/environments/2/venv/lib/python3.12/site-packages/aiohttp-3.9.0.dist-info"])
        self.assertEqual(rows, [])

    def test_an_egg_info_without_a_version_is_skipped(self):
        rows = environments.parse(["/home/x/proj/.venv/lib/python3.12/site-packages/mypkg.egg-info",
                                   "/home/x/proj/.venv/lib/python3.12/site-packages/numpy-1.26.0.dist-info"])
        self.assertEqual([row["package"] for row in rows], ["numpy"])


class Installers(unittest.TestCase):
    """The command has to name a binary that exists on the host — uv is usually not on a login PATH."""

    def test_a_venv_with_pip_uses_that_pip(self):
        out = "pip /home/u/p/a/.venv/bin/pip\n"
        with mock.patch.object(shell, "run", return_value=(0, out)):
            found = environments._installers(["/home/u/p/a/.venv"], None, 5)
        self.assertEqual(found["/home/u/p/a/.venv"]["path"], "/home/u/p/a/.venv/bin/pip")

    def test_a_uv_made_venv_gets_the_resolved_uv_path_not_a_bare_uv(self):
        out = ("uvbin /home/u/.hermes/bin/uv\n"
               "python /home/u/p/b/.venv/bin/python\n")
        with mock.patch.object(shell, "run", return_value=(0, out)):
            found = environments._installers(["/home/u/p/b/.venv"], None, 5)
        manager = found["/home/u/p/b/.venv"]
        self.assertEqual(manager["path"], "/home/u/.hermes/bin/uv")
        self.assertIn("{python}", manager["upgrade"])

    def test_no_pip_and_no_uv_is_admitted_not_invented(self):
        out = "python /home/u/p/c/.venv/bin/python\n"
        with mock.patch.object(shell, "run", return_value=(0, out)):
            found = environments._installers(["/home/u/p/c/.venv"], None, 5)
        manager = found["/home/u/p/c/.venv"]
        self.assertIsNone(manager["upgrade"])
        self.assertIn("uv is not installed", manager["why"])


class Collecting(unittest.TestCase):
    def test_the_find_names_environments_and_excludes_the_noise(self):
        command = environments.FIND
        self.assertIn("-name '*.dist-info'", command)
        self.assertIn("-path '*/.venv/*'", command)
        self.assertIn("-path '*/virtualenvs/*'", command)
        # excluded in the walk, not only in the parser
        self.assertIn("-not -path '*/.cache/*'", command)
        self.assertIn("-not -path '*/.hermes/*'", command)
        self.assertIn("-not -path '*/hermes-repair-backup*'", command)

    def test_an_unreadable_walk_is_an_outcome(self):
        with mock.patch.object(shell, "run", return_value=(1, "")):
            state = environments.collect(None, timeout=5)
        self.assertEqual(state["components"], [])
        self.assertIn("unreadable", state["outcomes"]["venvs"])

    def test_a_machine_with_no_environment_says_so(self):
        with mock.patch.object(shell, "run", return_value=(0, "")):
            state = environments.collect(None, timeout=5)
        self.assertIn("no environment found", state["outcomes"]["venvs"])

    def test_components_carry_their_own_count(self):
        text = ("/home/x/projects/api/.venv/lib/python3.12/site-packages/flask-3.0.0.dist-info\n"
                "/home/x/projects/api/.venv/lib/python3.12/site-packages/click-8.1.7.dist-info\n")
        with mock.patch.object(shell, "run", return_value=(0, text)):
            state = environments.collect(None, timeout=5)
        self.assertEqual(state["dirs"], 1)
        self.assertIn("2 package(s)", state["outcomes"]["venvs"])


if __name__ == "__main__":
    unittest.main()
