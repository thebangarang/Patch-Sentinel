"""The coverage report must describe the machine in front of it, not the one it was written on.

Found on the lab VMs: on Debian, Fedora and Arch the report said "Ubuntu security notices ... ok" —
because that row was hardcoded. The request behind it was `notices.json?release=bookworm`, which
answers HTTP 200 with an empty list, so the row read "advisories measured, nothing found" on a host
whose advisories had never been consulted. The row also called the package manager "apt" on Fedora.
"""
import json
import unittest


class CoverageNamesTheRightSource(unittest.TestCase):
    def coverage(self, host):
        from patch_sentinel import store, tools
        stored = {"hosts": {"lab": host}, "scan": {"usn_ok": True,
                                                   "usn_url": "https://ubuntu.com/security/notices.json?release=x"}}
        original = store.load_scan, store.scan_age_seconds
        store.load_scan = lambda: stored
        store.scan_age_seconds = lambda payload: 5.0
        try:
            return json.loads(tools.cve_coverage({}))
        finally:
            store.load_scan, store.scan_age_seconds = original

    def row(self, payload, needle):
        return next((row for row in payload["covered"] if needle in row["source"]), None)

    def test_a_debian_host_does_not_claim_ubuntu_notices(self):
        payload = self.coverage({
            "label": "lab", "adapter": "apt", "os": {"id": "debian", "version_id": "12"},
            "vendor_state": "measured", "vendor_lag": [{"package": "apt"}],
            "advisory_source": None, "vendor_feed": None,
            "outcomes": {"apt": "ok", "kernel": "ok", "images": "not-applicable"},
        })
        sources = " ".join(row["source"] for row in payload["covered"])
        self.assertNotIn("Ubuntu", sources, "a Debian host must not report Ubuntu's notice feed")
        advisories = self.row(payload, "advisories")
        self.assertIsNotNone(advisories)
        self.assertIn("debian", advisories["source"])
        self.assertEqual(advisories["outcome"], "measured")
        self.assertIsNone(advisories["url"], "no URL is claimed for a source that was not fetched")

    def test_the_package_manager_is_named_as_itself(self):
        payload = self.coverage({
            "label": "lab", "adapter": "dnf", "os": {"id": "fedora", "version_id": "45"},
            "vendor_state": "measured", "vendor_feed": {"source_url": "https://bodhi.fedoraproject.org/updates/"},
            "advisory_source": "Bodhi", "outcomes": {"apt": "ok", "kernel": "ok", "images": "not-applicable"},
        })
        self.assertTrue(any(row["source"].startswith("dnf:") for row in payload["covered"]),
                        "the report called dnf apt")
        advisories = self.row(payload, "Bodhi")
        self.assertEqual(advisories["url"], "https://bodhi.fedoraproject.org/updates/")

    def test_an_ubuntu_host_still_names_usn(self):
        payload = self.coverage({
            "label": "this", "adapter": "apt", "os": {"id": "ubuntu", "version_id": "26.04"},
            "vendor_state": "measured", "advisory_source": "USN (resolute)",
            "outcomes": {"apt": "ok", "kernel": "ok", "images": "ok"},
        })
        advisories = self.row(payload, "USN")
        self.assertIsNotNone(advisories)
        self.assertIn("ubuntu.com", advisories["url"] or "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
