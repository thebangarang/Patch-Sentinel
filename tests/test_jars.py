"""Jars on disk: the Java deployments that never touch a Maven repository.

A jar is a zip, and a Maven build stamps its own coordinates into it. What the tests pin is the
distinction that matters: a jar carrying `pom.properties` has a *group id* and can be matched against
Maven advisories; a jar named by file name alone has no group, and matching it would attribute another
artifact's CVEs. Those rows are counted and named, never queried.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import jars, shell  # noqa: E402


def make_jar(path: Path, entries: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in entries.items():
            archive.writestr(name, text)


class Coordinates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pom_properties_give_group_artifact_and_version(self):
        path = self.root / "spring-core-6.1.0.jar"
        make_jar(path, {"META-INF/maven/org.springframework/spring-core/pom.properties":
                        "groupId=org.springframework\nartifactId=spring-core\nversion=6.1.0\n"})
        found = jars.coordinates(str(path))
        self.assertEqual((found["group"], found["artifact"], found["version"]),
                         ("org.springframework", "spring-core", "6.1.0"))
        self.assertEqual(found["origin"], "pom.properties")

    def test_a_jar_without_pom_properties_falls_back_to_the_file_name(self):
        path = self.root / "log4j-core-2.14.1.jar"
        make_jar(path, {"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})
        found = jars.coordinates(str(path))
        self.assertIsNone(found["group"])
        self.assertEqual(found["artifact"], "log4j-core")
        self.assertEqual(found["version"], "2.14.1")
        self.assertEqual(found["origin"], "file name")

    def test_a_classifier_is_dropped(self):
        path = self.root / "guava-32.1.3-jre-sources.jar"
        make_jar(path, {"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})
        found = jars.coordinates(str(path))
        self.assertEqual((found["artifact"], found["version"]), ("guava", "32.1.3-jre"))

    def test_a_file_that_is_not_a_zip_is_not_a_jar(self):
        path = self.root / "broken-1.0.jar"
        path.write_text("not a zip")
        self.assertIsNone(jars.coordinates(str(path)))


class Collecting(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_jars_with_a_group_are_components(self):
        good = self.root / "a" / "spring-core-6.1.0.jar"
        good.parent.mkdir(parents=True)
        make_jar(good, {"META-INF/maven/org.springframework/spring-core/pom.properties":
                        "groupId=org.springframework\nartifactId=spring-core\nversion=6.1.0\n"})
        nameless = self.root / "b" / "mystery-1.2.3.jar"
        nameless.parent.mkdir(parents=True)
        make_jar(nameless, {"x": "y"})

        with mock.patch.object(shell, "run", return_value=(0, f"{good}\n{nameless}\n")):
            state = jars.collect(None, timeout=5)
        self.assertEqual([row["package"] for row in state["components"]],
                         ["org.springframework:spring-core"])
        self.assertIn("named no group", state["outcomes"]["jars"])

    def test_the_same_jar_twice_is_one_component(self):
        path = self.root / "spring-core-6.1.0.jar"
        make_jar(path, {"META-INF/maven/g/a/pom.properties": "groupId=g\nartifactId=a\nversion=1\n"})
        with mock.patch.object(shell, "run", return_value=(0, f"{path}\n{path}\n")):
            state = jars.collect(None, timeout=5)
        self.assertEqual(len(state["components"]), 1)

    def test_a_remote_host_says_the_walk_is_not_implemented(self):
        state = jars.collect("debian@10.0.0.9:2223", timeout=5)
        self.assertEqual(state["components"], [])
        self.assertIn("remote", state["outcomes"]["jars"])


if __name__ == "__main__":
    unittest.main()
