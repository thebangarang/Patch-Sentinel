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
        cls.module = module

    def test_health_names_the_tools(self):
        body = self.client.get(self.base + "/health").json()
        self.assertTrue(body["ok"])
        # pinned on purpose: a tool that quietly disappears from the pane's health is a pane that
        # silently loses a surface. cve_apply is the gate — it must be here.
        self.assertEqual(sorted(body["tools"]),
                         ["cve_apply", "cve_coverage", "cve_explain", "cve_libraries",
                          "cve_plan", "cve_scan"])

    def test_health_reports_which_build_of_the_pane_is_served(self):
        body = self.client.get(self.base + "/health").json()
        self.assertIn("sha", body["ui"]["repo"])
        self.assertIn("in_sync", body["ui"])

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

    def test_an_unknown_host_is_refused_and_the_inventory_is_named(self):
        body = self.client.post(self.base + "/apply",
                                json={"host": "no-such-host", "confirm": "no-such-host"}).json()
        self.assertFalse(body["applied"])
        # the operator typed a name from an older session; the refusal must say which names exist
        self.assertIn("there is no host called", body["reason"])
        self.assertIn("the hosts are:", body["reason"])
        self.assertTrue(body["nearest"], "a refusal must say what the choices are")

    def test_the_route_defaults_to_a_dry_run(self):
        """Omitted `dry_run` must mean "change nothing", whatever the operator typed."""
        from unittest import mock
        with mock.patch.object(self.module.tools, "cve_apply", return_value="{}") as spy:
            self.client.post(self.base + "/apply", json={"host": "beelink", "confirm": "beelink"})
        args = spy.call_args[0][0]
        self.assertTrue(args["dry_run"], "a missing dry_run flag must never authorise a change")
        self.assertEqual(args["confirm"], "beelink")

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
