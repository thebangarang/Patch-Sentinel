"""The pane's routes, mounted the way Hermes mounts them.

The plugin itself declares no Python dependency, so FastAPI lives in the host: these tests are
skipped under the project's stdlib-only venv and run wherever FastAPI is importable (the Hermes
interpreter). That is not a loophole — the dashboard backend only ever runs inside the host.

The scan route is exercised for real when ``PATCH_SENTINEL_TEST_SCAN=1`` (it costs a few seconds
and reads the real machine); otherwise the test asserts the refusal paths, which is what the pane
must never get wrong.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HAS_FASTAPI = importlib.util.find_spec("fastapi") is not None


@unittest.skipUnless(HAS_FASTAPI, "FastAPI lives in the host, not in this plugin")
class DashboardRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        spec = importlib.util.spec_from_file_location(
            "patch_sentinel_dashboard", ROOT / "dashboard" / "plugin_api.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        app = FastAPI()
        app.include_router(module.router, prefix="/api/plugins/patch-sentinel")
        cls.client = TestClient(app)
        cls.base = "/api/plugins/patch-sentinel"

    def test_health_names_the_tools(self):
        body = self.client.get(self.base + "/health").json()
        self.assertTrue(body["ok"])
        self.assertEqual(sorted(body["tools"]),
                         ["cve_coverage", "cve_explain", "cve_libraries", "cve_plan", "cve_scan"])

    def test_status_never_scans(self):
        body = self.client.get(self.base + "/status").json()
        # Either a stored measurement or an explicit "nothing measured yet" — never an invented one
        self.assertIn("hosts", body)
        if body.get("scan") is None:
            self.assertIn("note", body)
        else:
            self.assertIn("age_seconds", body)

    def test_coverage_is_never_empty_and_names_the_gaps(self):
        body = self.client.get(self.base + "/coverage").json()
        gaps = " ".join(gap["gap"] for gap in body["gaps"])
        self.assertIn("container image", gaps)
        self.assertTrue(body["gaps"])

    def test_the_gate_refuses_a_wrongly_typed_host(self):
        body = self.client.post(self.base + "/apply",
                                json={"host": "beelink", "confirm": "beelinkk"}).json()
        self.assertFalse(body["applied"])
        self.assertIn("exactly", body["reason"])

    def test_apply_is_refused_in_this_version_even_when_armed(self):
        status = self.client.get(self.base + "/status").json()
        labels = list((status.get("hosts") or {}).keys())
        if not labels:
            self.skipTest("no stored measurement to arm the gate against")
        body = self.client.post(self.base + "/apply",
                                json={"host": labels[0], "confirm": labels[0]}).json()
        self.assertFalse(body["applied"])
        self.assertIn("not enabled", body["reason"])
        self.assertIn("would_run", body)

    @unittest.skipUnless(os.environ.get("PATCH_SENTINEL_TEST_SCAN") == "1",
                         "set PATCH_SENTINEL_TEST_SCAN=1 to run a real scan")
    def test_a_real_scan_then_a_stored_status(self):
        scanned = self.client.post(self.base + "/scan", json={}).json()
        self.assertIn("hosts", scanned)
        stored = self.client.get(self.base + "/status").json()
        self.assertIn("age_seconds", stored)
        self.assertLessEqual(stored["age_seconds"], 120)


if __name__ == "__main__":
    unittest.main(verbosity=2)
