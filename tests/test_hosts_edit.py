"""Editing the inventory from the pane: validate, add, remove.

The rules being pinned here are the ones that keep this control safe:
  * a host is only added after a probe of it succeeded — the list never gains an unreachable row;
  * a target is only what can legitimately sit in an ssh command line, so it cannot become a second
    command;
  * removing requires the label typed exactly, and the local machine cannot be removed at all;
  * a pane edit wins over config.yaml on the next restart, instead of being silently undone.
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

from patch_sentinel import store, tools  # noqa: E402
from patch_sentinel.sources import dispatch  # noqa: E402
from patch_sentinel.sources import hosts as inventory  # noqa: E402

import importlib.util

HAVE_FASTAPI = importlib.util.find_spec("fastapi") is not None
BASE = "/api/plugins/patch-sentinel"


class HostValidation(unittest.TestCase):
    def test_a_plain_label_is_accepted(self):
        self.assertTrue(inventory.validate("vps", "root@10.0.0.1")[0])

    def test_a_label_with_a_space_is_refused(self):
        ok, reason = inventory.validate("my vps", "10.0.0.1")
        self.assertFalse(ok)
        self.assertIn("label", reason)

    def test_a_target_cannot_carry_a_second_command(self):
        for bad in ("host; rm -rf /", "host && id", "$(id)", "host`id`", "a=b", "a,b"):
            with self.subTest(target=bad):
                self.assertFalse(inventory.validate("h", bad)[0])

    def test_empty_and_local_both_mean_this_machine(self):
        for target in ("", "local", "localhost"):
            with self.subTest(target=target):
                self.assertTrue(inventory.validate("h", target)[0])

    def test_serialize_round_trips_through_parse(self):
        text = inventory.serialize([{"label": "beelink", "target": None},
                                    {"label": "vps", "target": "root@10.0.0.1"}])
        self.assertEqual(text, "beelink=local,vps=root@10.0.0.1")
        parsed = inventory.parse_inventory(text)
        self.assertEqual([row["label"] for row in parsed], ["beelink", "vps"])
        self.assertIsNone(parsed[0]["target"])


@unittest.skipUnless(HAVE_FASTAPI, "FastAPI lives in the host, not in this plugin")
class HostRoutes(unittest.TestCase):
    def setUp(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        self.tmp = tempfile.TemporaryDirectory()
        store.configure({"data_dir": self.tmp.name})
        tools.configure({"hosts": "beelink=local", "release": "resolute", "usn_limit": 20,
                         "data_dir": self.tmp.name, "timeout": 5})
        # the module is loaded the way the host loads it: a file on disk, mounted under a prefix
        spec = importlib.util.spec_from_file_location(
            "patch_sentinel_dashboard_hosts", ROOT / "dashboard" / "plugin_api.py")
        assert spec is not None and spec.loader is not None
        self.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.api)
        app = FastAPI()
        app.include_router(self.api.router, prefix="/api/plugins/patch-sentinel")
        self.client = TestClient(app)
        self._probe = dispatch.probe
        # the route checks reachability before probing; here that must not leave the machine
        from patch_sentinel.sources import diagnose
        self._diagnose = diagnose.diagnose
        diagnose.diagnose = lambda target: {"ok": True, "stage": "ok", "reason": "", "hint": "",
                                            "fix": ""}

    def tearDown(self):
        dispatch.probe = self._probe
        from patch_sentinel.sources import diagnose
        diagnose.diagnose = self._diagnose
        self.tmp.cleanup()

    def test_the_list_starts_from_the_configured_inventory(self):
        answer = self.client.get(BASE + "/hosts").json()
        self.assertEqual(answer["hosts"], [{"label": "beelink", "target": "local"}])

    def test_an_unreachable_host_reports_the_stage_it_stopped_at(self):
        from patch_sentinel.sources import diagnose
        diagnose.diagnose = lambda target: {
            "ok": False, "stage": "auth",
            "reason": "debian@10.0.0.9: Permission denied (publickey).",
            "hint": "the host answered but rejected the key",
            "fix": "ssh-copy-id -i ~/.ssh/id_ed25519.pub debian@10.0.0.9"}
        called = []
        dispatch.probe = lambda *a, **k: called.append(a) or {"ok": True}
        answer = self.client.post(BASE + "/hosts/test",
                                  json={"label": "vps", "target": "debian@10.0.0.9"}).json()
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["stage"], "auth")
        self.assertIn("ssh-copy-id", answer["fix"])
        self.assertEqual(called, [], "a host that is not reachable must not be probed")

    def test_a_bad_target_is_refused_before_any_probe(self):
        called = []
        dispatch.probe = lambda *a, **k: called.append(a) or {"ok": True}
        answer = self.client.post(BASE + "/hosts/test", json={"label": "h", "target": "x;id"}).json()
        self.assertFalse(answer["ok"])
        self.assertEqual(called, [])

    def test_a_reachable_host_is_added_and_persisted(self):
        dispatch.probe = lambda *a, **k: {"ok": True, "family": "apt", "running": "7.0.0-43",
                                          "kernel": "kernel-update-available",
                                          "os": {"id": "ubuntu", "codename": "resolute"},
                                          "pending": [{"name": "curl"}]}
        tested = self.client.post(BASE + "/hosts/test", json={"label": "vps", "target": "root@10.0.0.9"}).json()
        self.assertTrue(tested["ok"])
        self.assertEqual(tested["adapter"], "apt")
        self.assertEqual(tested["pending"], 1)

        added = self.client.post(BASE + "/hosts", json={"label": "vps", "target": "root@10.0.0.9"}).json()
        self.assertEqual(added["added"], "vps")
        self.assertEqual([row["label"] for row in added["hosts"]], ["beelink", "vps"])

        saved = json.loads((Path(self.tmp.name) / "settings.json").read_text())
        self.assertEqual(saved["hosts"], "beelink=local,vps=root@10.0.0.9")
        self.assertEqual(saved["hosts_source"], "pane")

    def test_the_same_label_twice_is_refused(self):
        dispatch.probe = lambda *a, **k: {"ok": True, "family": "apt", "os": {}, "pending": []}
        self.client.post(BASE + "/hosts", json={"label": "vps", "target": "root@10.0.0.9"})
        again = self.client.post(BASE + "/hosts", json={"label": "VPS", "target": "root@10.0.0.10"}).json()
        self.assertFalse(again["added"])
        self.assertIn("already in the inventory", again["reason"])

    def test_removal_needs_the_label_typed(self):
        dispatch.probe = lambda *a, **k: {"ok": True, "family": "apt", "os": {}, "pending": []}
        self.client.post(BASE + "/hosts", json={"label": "vps", "target": "root@10.0.0.9"})
        refused = self.client.post(BASE + "/hosts/remove", json={"label": "vps", "confirm": ""}).json()
        self.assertFalse(refused["removed"])
        self.assertIn("type the label", refused["reason"])

        removed = self.client.post(BASE + "/hosts/remove", json={"label": "vps", "confirm": "vps"}).json()
        self.assertEqual(removed["removed"], "vps")
        self.assertEqual([row["label"] for row in removed["hosts"]], ["beelink"])

    def test_the_local_machine_cannot_be_removed(self):
        answer = self.client.post(BASE + "/hosts/remove",
                                  json={"label": "beelink", "confirm": "beelink"}).json()
        self.assertFalse(answer["removed"])
        self.assertIn("cannot be removed", answer["reason"])

    def test_a_pane_edit_survives_a_register_with_the_old_config(self):
        dispatch.probe = lambda *a, **k: {"ok": True, "family": "apt", "os": {}, "pending": []}
        self.client.post(BASE + "/hosts", json={"label": "vps", "target": "root@10.0.0.9"})

        class StubCtx:
            """What the loader hands register(): config.yaml, which still says beelink only."""
            def get_config(self, key, default=None):
                return {"hosts": "beelink=local"}.get(key, default)

            def register_tool(self, **kwargs):
                pass

        # loaded the way the host loads it: this directory *is* the package
        spec = importlib.util.spec_from_file_location(
            "patch_sentinel_plugin_root", ROOT / "__init__.py",
            submodule_search_locations=[str(ROOT)])
        assert spec is not None and spec.loader is not None
        package = importlib.util.module_from_spec(spec)
        sys.modules["patch_sentinel_plugin_root"] = package
        spec.loader.exec_module(package)
        package.register(StubCtx())
        self.assertEqual(tools._settings["hosts"], "beelink=local,vps=root@10.0.0.9")


if __name__ == "__main__":
    unittest.main()
