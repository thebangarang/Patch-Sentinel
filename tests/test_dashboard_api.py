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

        # Point the plugin at a throwaway data directory BEFORE importing the router: the module
        # configures itself from the stored settings at import, and a route that saves the inventory
        # (POST /hosts, /hosts/remove) would otherwise rewrite the live inventory of the machine the
        # tests run on. That is exactly what happened once: a test removed a real server.
        import tempfile
        cls._data_dir = tempfile.mkdtemp(prefix="ps-test-data-")

        spec = importlib.util.spec_from_file_location(
            "patch_sentinel_dashboard", ROOT / "dashboard" / "plugin_api.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.tools.configure({"hosts": "testbox=local", "release": "resolute",
                                "data_dir": cls._data_dir, "timeout": 30})
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
                         ["cve_ack", "cve_apply", "cve_coverage", "cve_explain", "cve_image",
                          "cve_integrity", "cve_libraries", "cve_plan", "cve_rescan", "cve_sbom",
                          "cve_scan"])

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

    # ---- long jobs ---------------------------------------------------------------------------
    # `/scan` and `/apply` answer immediately and run on a thread, because the desktop bridge cuts a
    # renderer call at 30 s while a two-server scan takes 40-60 and a real apply took 105 s. These
    # helpers follow the job the way the pane does, so the tests exercise the real contract.
    def follow(self, name, seconds=20.0):
        import time
        deadline = time.time() + seconds
        while time.time() < deadline:
            jobs = self.client.get(self.base + "/jobs").json()
            job = jobs.get(name) or {}
            if not job.get("running"):
                return job
            time.sleep(0.05)
        self.fail(f"the {name} job did not finish within {seconds}s")

    def test_the_gate_refuses_a_wrongly_typed_host(self):
        # the label comes from the test's own inventory, never from this machine's
        label = self.client.get(self.base + "/hosts").json()["hosts"][0]["label"]
        started = self.client.post(self.base + "/apply",
                                   json={"host": label, "confirm": label + "k"}).json()
        self.assertTrue(started["started"])
        body = self.follow("apply")["result"]
        self.assertFalse(body["applied"])
        self.assertIn("exactly", body["reason"])

    def test_an_unknown_host_is_refused_and_the_inventory_is_named(self):
        self.client.post(self.base + "/apply",
                         json={"host": "no-such-host", "confirm": "no-such-host"})
        body = self.follow("apply")["result"]
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
            self.follow("apply")
        args = spy.call_args[0][0]
        self.assertTrue(args["dry_run"], "a missing dry_run flag must never authorise a change")
        self.assertEqual(args["confirm"], "beelink")

    def test_a_second_start_is_refused_while_one_is_running(self):
        """Never two scans at once: the second call must say so instead of starting another."""
        import time
        from unittest import mock
        with mock.patch.object(self.module.tools, "cve_scan",
                               side_effect=lambda *a, **k: (time.sleep(0.4), "{}")[1]):
            first = self.client.post(self.base + "/scan", json={}).json()
            self.assertTrue(first["started"])
            second = self.client.post(self.base + "/scan", json={}).json()
            self.assertFalse(second["started"])
            self.assertIn("already running", second["note"])
            self.follow("scan", 20)

    def test_a_job_that_raises_reports_an_error_not_a_result(self):
        from unittest import mock
        with mock.patch.object(self.module.tools, "cve_scan", side_effect=RuntimeError("boom")):
            self.client.post(self.base + "/scan", json={})
            job = self.follow("scan")
        self.assertIn("boom", job["error"])
        self.assertIsNone(job["result"])

    @unittest.skipUnless(os.environ.get("PATCH_SENTINEL_TEST_SCAN") == "1",
                         "set PATCH_SENTINEL_TEST_SCAN=1 to run a real scan")
    def test_a_real_scan_then_a_stored_status(self):
        started = self.client.post(self.base + "/scan", json={}).json()
        self.assertTrue(started["started"])
        job = self.follow("scan", 300)
        self.assertTrue(job["result"])
        stored = self.client.get(self.base + "/status").json()
        self.assertIn("age_seconds", stored)
        self.assertLessEqual(stored["age_seconds"], 120)


if __name__ == "__main__":
    unittest.main(verbosity=2)
