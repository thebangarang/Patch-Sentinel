"""Container image internals, read without running the image.

The fixture is a real `docker save` shape, built in the test: an outer tar holding a layer tar, which
holds `etc/os-release` and a package database. Both database formats are covered (dpkg and apk), plus
the two ways this can be empty — an rpmdb it cannot parse, and an image with no database at all — which
must read as *unmeasured*, never as zero packages.
"""
from __future__ import annotations

import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel.sources import image_db  # noqa: E402

DEBIAN_STATUS = """Package: openssl
Status: install ok installed
Version: 3.0.11-1~deb12u2
Architecture: amd64

Package: libc6
Status: install ok installed
Version: 2.36-9+deb12u4

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0
"""

ALPINE_INSTALLED = """P:musl
V:1.2.4-r2
A:x86_64

P:busybox
V:1.36.1-r5
A:x86_64
"""


def layer_tar(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as layer:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            layer.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def image_tar(layers: list[dict[str, str]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as outer:
        manifest = b'[{"Config":"blobs/sha256/conf","Layers":[]}]'
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        outer.addfile(info, io.BytesIO(manifest))
        for index, files in enumerate(layers):
            blob = layer_tar(files)
            info = tarfile.TarInfo(f"blobs/sha256/layer{index}")
            info.size = len(blob)
            outer.addfile(info, io.BytesIO(blob))
    return buffer.getvalue()


class DpkgImages(unittest.TestCase):
    def read(self, payload: bytes) -> dict:
        handle = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
        handle.write(payload)
        handle.close()
        try:
            return image_db.read_tar(handle.name)
        finally:
            Path(handle.name).unlink()

    def test_a_debian_image_yields_its_installed_packages(self):
        state = self.read(image_tar([{"etc/os-release": 'ID=debian\nVERSION_ID="12"\n',
                                      "var/lib/dpkg/status": DEBIAN_STATUS}]))
        self.assertEqual(state["os"]["id"], "debian")
        self.assertEqual({row["package"] for row in state["packages"]}, {"openssl", "libc6"})
        self.assertEqual(image_db.ecosystem_for(state["os"]), "Debian:12")
        self.assertEqual(state["outcome"], "ok")

    def test_a_later_layer_wins(self):
        old = "Package: openssl\nStatus: install ok installed\nVersion: 3.0.10-1\n"
        new = "Package: openssl\nStatus: install ok installed\nVersion: 3.0.14-1\n"
        state = self.read(image_tar([
            {"etc/os-release": 'ID=debian\nVERSION_ID="12"\n', "var/lib/dpkg/status": old},
            {"var/lib/dpkg/status": new},
        ]))
        self.assertEqual(state["packages"][0]["version"], "3.0.14-1")

    def test_an_alpine_image_reads_apk(self):
        state = self.read(image_tar([{"etc/os-release": 'ID=alpine\nVERSION_ID=3.19.1\n',
                                      "lib/apk/db/installed": ALPINE_INSTALLED}]))
        self.assertEqual({row["package"] for row in state["packages"]}, {"musl", "busybox"})
        self.assertEqual(image_db.ecosystem_for(state["os"]), "Alpine:v3.19")

    def test_an_rpm_image_says_it_is_unmeasured(self):
        state = self.read(image_tar([{"etc/os-release": 'ID=fedora\nVERSION_ID=41\n',
                                      "var/lib/rpm/Packages": "not really a database"}]))
        self.assertEqual(state["packages"], [])
        self.assertIn("rpm-based", state["outcome"])

    def test_an_image_with_no_database_is_not_clean(self):
        state = self.read(image_tar([{"etc/os-release": 'ID=debian\nVERSION_ID="12"\n'}]))
        self.assertEqual(state["packages"], [])
        self.assertIn("unmeasured, not clean", state["outcome"])

    def test_an_unknown_distribution_has_no_ecosystem(self):
        self.assertIsNone(image_db.ecosystem_for({"id": "windows", "version_id": "11"}))
        self.assertIsNone(image_db.ecosystem_for({"id": "debian"}))


class Parsers(unittest.TestCase):
    def test_dpkg_drops_removed_packages(self):
        rows = image_db.parse_dpkg(DEBIAN_STATUS)
        self.assertNotIn("removed-pkg", [row["package"] for row in rows])

    def test_apk_pairs_name_and_version(self):
        rows = image_db.parse_apk(ALPINE_INSTALLED)
        self.assertEqual(rows[0], {"package": "musl", "version": "1.2.4-r2"})

    def test_a_failed_docker_save_is_an_outcome(self):
        with mock.patch.object(image_db, "__name__", image_db.__name__):
            from patch_sentinel.sources import shell
            with mock.patch.object(shell, "run", return_value=(1, "Cannot connect to the Docker daemon")):
                state = image_db.save_and_read(["nginx:1.27"], None, timeout=5)
        outcome = state["images"]["nginx:1.27"]["outcome"]
        self.assertIn("docker save failed", outcome)
        self.assertEqual(state["images"]["nginx:1.27"]["packages"], [])


if __name__ == "__main__":
    unittest.main()
