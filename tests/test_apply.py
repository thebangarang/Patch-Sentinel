"""The gate: refusal paths, the stage-before-apply guard, and the receipt.

Nothing here touches a real machine — ``shell.run`` and the post-apply probe are replaced. The
real apply is exercised once, by hand, on the Fedora VM (see ``docs/lab.md``): a test that
installs 109 packages on every run would be a test nobody keeps running.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel import apply as apply_mod            # noqa: E402
from patch_sentinel import store                          # noqa: E402


def host_entry(**overrides) -> dict:
    entry = {"label": "fedora-lab", "adapter": "dnf", "target": "fedora@127.0.0.1:2222",
             "measured_at": "2026-11-06T15:00:00+00:00",
             "kernel": {"running": "7.2.11-300.fc45.x86_64", "installed": "7.2.11-300.fc45",
                        "installable": "7.2.15-300.fc45", "verdict": "kernel-update-available"},
             "pending_count": 109, "pending": [], "images": []}
    entry.update(overrides)
    return entry


class SudoRefusal(unittest.TestCase):
    """A host without passwordless sudo is a refusal — with the commands to run by hand."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["PATCH_SENTINEL_DATA"] = self.tmp.name

    def tearDown(self):
        os.environ.pop("PATCH_SENTINEL_DATA", None)   # do not leak the data dir into other tests
        self.tmp.cleanup()

    def test_the_refusal_hands_over_both_commands_in_order(self):
        def fake_run(command, target=None, timeout=0, path_prefix=None):
            if command.startswith("sudo -n true"):
                return 1, "sudo: a password is required"
            return 0, ""

        with mock.patch.object(apply_mod.shell, "run", side_effect=fake_run):
            result = apply_mod.apply(host_entry(adapter="apt"), "debian@10.0.0.9:2223",
                                    "fedora-lab", dry_run=True)

        self.assertFalse(result["applied"])
        self.assertIn("cannot run sudo without a password", result["reason"])
        self.assertEqual(len(result["handoff"]["commands"]), 2)
        self.assertIn("apt-get update", result["handoff"]["commands"][0])
        self.assertIn("full-upgrade", result["handoff"]["commands"][1])
        self.assertIn("never", result["handoff"]["note"])
        self.assertIn("credentials", result["handoff"]["note"])
        # where to type them: a remote handoff carries the ssh line, a local one names the account
        self.assertEqual(result["handoff"]["where"]["kind"], "remote")
        self.assertIn("ssh", result["handoff"]["where"]["ssh"])
        self.assertIn("apt-get -s dist-upgrade", result["handoff"]["verify"])
        self.assertIn("apt-get install", result["handoff"]["reversal"])

    def test_a_local_handoff_names_the_account_the_plugin_runs_as(self):
        def fake_run(command, target=None, timeout=0, path_prefix=None):
            if command.startswith("sudo -n true"):
                return 1, "sudo: a password is required"
            return 0, ""

        with mock.patch.object(apply_mod.shell, "run", side_effect=fake_run):
            result = apply_mod.apply(host_entry(adapter="apt"), None, "fedora-lab", dry_run=True)

        where = result["handoff"]["where"]
        self.assertEqual(where["kind"], "local")
        self.assertTrue(where["runs_as"])
        self.assertIn("not yours", where["note"])


class Gate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["PATCH_SENTINEL_DATA"] = self.tmp.name
        patcher = mock.patch.object(apply_mod.shell, "run", return_value=(0, "rc=0"))
        self.run_shell = patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(os.environ.pop, "PATCH_SENTINEL_DATA", None)

    def receipts(self) -> list[dict]:
        path = Path(self.tmp.name) / "receipts.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def test_a_wrongly_typed_name_runs_nothing(self):
        result = apply_mod.apply(host_entry(), "fedora@127.0.0.1:2222", "fedora-labb", dry_run=False)
        self.assertFalse(result["applied"])
        self.assertIn("exactly", result["reason"])
        self.run_shell.assert_not_called()
        self.assertEqual(self.receipts(), [])

    def test_dnf_exit_100_on_the_stage_is_success_not_failure(self):
        # the stage only runs on a real apply now, so this asserts with dry_run=false
        # measured on Fedora 45: `dnf check-upgrade` returns 100 *because* updates exist
        def run(command, target, timeout=None, path_prefix=None):
            return (100, "curl.x86_64 8.21.0-9.fc45 updates") if "check-upgrade" in command else (0, "ok")
        with mock.patch.object(apply_mod.shell, "run", side_effect=run):
            result = apply_mod.apply(host_entry(), "fedora@127.0.0.1:2222", "fedora-lab",
                                     dry_run=False)
        # rc=100 from `dnf check-upgrade` means "updates exist", not "failed": the stage must pass
        self.assertTrue(result["steps"][0]["ok"], result["steps"][0])
        self.assertIn("apply", [step["action"] for step in result["steps"]],
                      "the stage was treated as a failure and the apply never ran")
        self.assertNotIn("half-upgraded", result["reason"])

    def test_dry_run_is_the_default_and_applies_nothing(self):
        result = apply_mod.apply(host_entry(), "fedora@127.0.0.1:2222", "fedora-lab")
        self.assertFalse(result["applied"])
        self.assertTrue(result["dry_run"])
        self.assertIn("dnf", " ".join(result["would_run"]))
        commands = [step["action"] for step in result["steps"]]
        # a dry run runs nothing at all: the stage downloads packages, so "dry" must not stage either
        self.assertEqual(commands, [], "a dry run must not run the stage")
        self.assertEqual(len(result.get("would_run") or []), 2, "the dry run still says what it would do")
        self.assertEqual(len(self.receipts()), 1)
        self.assertTrue(self.receipts()[0]["dry_run"])

    def test_a_failed_stage_stops_before_anything_changes(self):
        def run(command, target, timeout=None, path_prefix=None):
            return (1, "error: cannot refresh metadata") if "check-upgrade" in command else (0, "ok")
        with mock.patch.object(apply_mod.shell, "run", side_effect=run):
            result = apply_mod.apply(host_entry(), "fedora@127.0.0.1:2222", "fedora-lab",
                                     dry_run=False)
        self.assertFalse(result["applied"])
        self.assertEqual([step["action"] for step in result["steps"]], ["stage"])
        self.assertIn("half-upgraded", result["reason"])

    def test_no_passwordless_sudo_is_a_refusal_with_a_remedy(self):
        with mock.patch.object(apply_mod.shell, "run",
                               return_value=(1, "sudo: a password is required")):
            result = apply_mod.apply(host_entry(), "fedora@127.0.0.1:2222", "fedora-lab",
                                     dry_run=False)
        self.assertFalse(result["applied"])
        self.assertIn("never asks for, holds or forwards a password", result["reason"])
        self.assertEqual(result["steps"], [])

    def test_a_real_apply_verifies_by_effect_and_records_it(self):
        calls = []

        def run(command, target, timeout=None, path_prefix=None):
            calls.append(command)
            return 0, "ok"

        after = {"ok": True, "label": "fedora-lab", "measured_at": "2026-11-06T15:10:00+00:00",
                 "running": "7.2.11-300.fc45.x86_64", "newest_installed": "7.2.15-300.fc45",
                 "kernel": "kernel-reboot-needed", "pending": [], "candidate": "7.2.15-300.fc45",
                 "images": [], "os": {"id": "fedora", "codename": "45"},
                 "installed_packages": {}, "images_outcome": "not-applicable"}
        with mock.patch.object(apply_mod.shell, "run", side_effect=run), \
                mock.patch.object(apply_mod.dispatch, "probe", return_value=after):
            result = apply_mod.apply(host_entry(), "fedora@127.0.0.1:2222", "fedora-lab",
                                     dry_run=False)
        self.assertTrue(result["applied"])
        self.assertEqual([step["action"] for step in result["steps"]], ["stage", "apply"])
        self.assertTrue(any("dnf -y upgrade" in command for command in calls))
        # installed is not running: the payload must say a reboot is still owed
        self.assertTrue(result["reboot_required"])
        receipt = self.receipts()[0]
        self.assertTrue(receipt["applied"])
        self.assertEqual(receipt["before"]["kernel_running"], "7.2.11-300.fc45.x86_64")
        self.assertEqual(receipt["after"]["kernel_verdict"], "kernel-reboot-needed")

    def test_a_host_with_nothing_pending_is_refused(self):
        clean = host_entry(pending_count=0,
                           kernel={"running": "7.2.15-300.fc45", "installed": "7.2.15-300.fc45",
                                   "verdict": "kernel-current"})
        result = apply_mod.apply(clean, "fedora@127.0.0.1:2222", "fedora-lab", dry_run=False)
        self.assertFalse(result["applied"])
        self.assertIn("nothing to apply", result["reason"])
        self.run_shell.assert_not_called()

    def test_an_adapter_without_commands_is_refused_rather_than_guessed(self):
        result = apply_mod.apply(host_entry(adapter="zypper"), "x", "fedora-lab", dry_run=False)
        self.assertFalse(result["applied"])
        self.assertIn("no apply commands", result["reason"])


class SettingsHandoff(unittest.TestCase):
    """register() has the config, the router does not: the file is how they agree."""

    def test_settings_round_trip_and_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["PATCH_SENTINEL_DATA"] = tmp
            try:
                store.save_settings({"hosts": "a=local,b=vps", "release": "noble"})
                self.assertEqual(store.load_settings(),
                                 {"hosts": "a=local,b=vps", "release": "noble"})
                mode = oct((Path(tmp) / "settings.json").stat().st_mode & 0o777)
                self.assertEqual(mode, "0o600")
            finally:
                os.environ.pop("PATCH_SENTINEL_DATA", None)

    def test_a_missing_file_is_empty_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["PATCH_SENTINEL_DATA"] = tmp
            try:
                self.assertEqual(store.load_settings(), {})
            finally:
                os.environ.pop("PATCH_SENTINEL_DATA", None)


class Receipts(unittest.TestCase):
    def test_receipts_are_append_only_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["PATCH_SENTINEL_DATA"] = tmp
            try:
                store.append_receipt({"host": "a", "action": "full-upgrade"})
                store.append_receipt({"host": "b", "action": "full-upgrade"})
                rows = store.load_receipts()
                self.assertEqual([row["host"] for row in rows], ["a", "b"])
                mode = oct((Path(tmp) / "receipts.jsonl").stat().st_mode & 0o777)
                self.assertEqual(mode, "0o600")
            finally:
                os.environ.pop("PATCH_SENTINEL_DATA", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
