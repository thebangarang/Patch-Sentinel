"""The sources, tested against captured payloads.

Every source in this plugin ships with a fixture that proves it parses a real answer, and one
that proves its failure mode. The fixtures are real: ``probe_2026-11-06_beelink.txt`` is this
machine's own probe output; ``cve-2026-98432_resolute.json`` is a trimmed copy of Ubuntu's CVE
tracker record for the CVE that started the project. ``probe_2026-11-06_before_upgrade.txt`` is
reconstructed from the incident (running 7.0.0-42, candidate 7.0.0-43) because by the time the
plugin was written the host had already been patched — the apt lines are the routine's own
selftest fixture.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patch_sentinel import plan, verdict                       # noqa: E402
from patch_sentinel.sources import cve_tracker, hostprobe, registry, usn   # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def host_payload(facts: dict) -> dict:
    """The shape ``tools.cve_scan`` hands to ``plan`` — kept in one place so a drift shows up."""
    return {"label": "beelink", "adapter": "apt", "measured_at": "2026-11-06T10:00:00+00:00",
            "kernel": {"running": facts["running"], "installed": facts["newest_installed"],
                       "installable": facts["candidate"],
                       "installed_packages": facts["installed_packages"],
                       "verdict": facts["kernel"]},
            "pending": facts["pending"], "images": facts["images"],
            "images_outcome": facts["images_outcome"]}


class RegistryClassification(unittest.TestCase):
    def test_a_digest_is_a_digest(self):
        digest = "sha256:" + "a" * 64
        self.assertEqual(registry.classify(digest), digest)

    def test_rate_limit_becomes_a_code(self):
        self.assertEqual(registry.classify("ERROR: unexpected status 429 Too Many Requests"),
                         "err:rate-limited")
        self.assertEqual(registry.classify("ERROR: toomanyrequests"), "err:rate-limited")

    def test_missing_image_is_not_a_blind_spot(self):
        self.assertEqual(registry.classify("ERROR: manifest unknown"), "err:no-such-image")
        self.assertEqual(registry.classify("pull access denied for x"), "err:no-such-image")

    def test_anything_else_is_other(self):
        self.assertEqual(registry.classify("ERROR: x509: certificate expired"), "err:other")
        self.assertEqual(registry.classify(""), "err:other")


class ProbeParsing(unittest.TestCase):
    def test_the_real_capture_reads_as_clean(self):
        facts = hostprobe.parse(fixture("probe_2026-11-06_beelink.txt"))
        self.assertEqual(facts["running"], "7.0.0-43-generic")
        self.assertEqual(facts["newest_installed"], "7.0.0-43-generic")
        self.assertEqual(facts["kernel"], "kernel-current")
        self.assertEqual(facts["pending"], [])
        self.assertEqual(facts["os"], {"id": "ubuntu", "codename": "resolute"})
        self.assertEqual(facts["images_outcome"], "measured")
        self.assertEqual([i["state"] for i in facts["images"]], ["current", "current"])
        # the dpkg version is kept: it is what lets us compare a tracker version exactly
        self.assertEqual(facts["installed_packages"]["7.0.0-43-generic"], "7.0.0-43.43")

    def test_the_incident_capture_is_a_finding_with_a_blind_registry(self):
        facts = hostprobe.parse(fixture("probe_2026-11-06_before_upgrade.txt"))
        self.assertEqual(facts["kernel"], "kernel-update-available")
        self.assertEqual(facts["candidate"], "7.0.0-43-generic")
        self.assertEqual(len(facts["pending"]), 4)
        # both registries answered 429 — unknown, never "nothing to do" (rule 5)
        self.assertEqual({i["state"] for i in facts["images"]}, {"unknown"})

    def test_a_missing_sentinel_is_a_refusal_not_a_partial_read(self):
        with self.assertRaises(ValueError):
            hostprobe.parse("7.0.0-43-generic\n")

    def test_docker_refusing_is_unreadable_not_clean(self):
        text = ("7.0.0-43-generic\nlinux-image-7.0.0-43-generic 7.0.0-43.43\n@@K@@\n7.0.0-43-generic\n"
                "@@A@@\n@@I@@\nimg|docker-unreadable||\n@@R@@\nubuntu resolute\n")
        facts = hostprobe.parse(text)
        self.assertEqual(facts["images_outcome"], "unreadable")
        self.assertEqual(facts["images"], [])

    def test_no_docker_is_not_a_blind_spot(self):
        text = ("7.0.0-43-generic\nlinux-image-7.0.0-43-generic 7.0.0-43.43\n@@K@@\n7.0.0-43-generic\n"
                "@@A@@\n@@I@@\nimg|no-docker||\n@@R@@\nubuntu resolute\n")
        self.assertEqual(hostprobe.parse(text)["images_outcome"], "not-applicable")


class PlanFromTheIncident(unittest.TestCase):
    """Acceptance item 3: the 2026-11-06 incident, reproduced from a captured simulation."""

    def setUp(self):
        self.facts = hostprobe.parse(fixture("probe_2026-11-06_before_upgrade.txt"))
        self.host = host_payload(self.facts)

    def test_the_kernel_fix_is_offered_by_full_upgrade_and_needs_a_reboot(self):
        steps = plan.steps_for(self.host)
        commands = " ".join(s["command"] for s in steps)
        self.assertIn("full-upgrade", commands)
        self.assertIn("reboot", commands)
        self.assertNotIn(" apt-get -y upgrade", commands, "plain upgrade keeps a new kernel back")
        self.assertEqual(self.host["kernel"]["installable"], "7.0.0-43-generic")

    def test_every_step_carries_its_verification_and_its_reversal(self):
        for step in plan.steps_for(self.host):
            self.assertTrue(step["verify"], step)
            self.assertTrue(step["reversal"], step)
            self.assertIn(step["risk"], ("low", "medium", "high"))

    def test_a_patched_host_gets_a_refusal_not_an_empty_plan(self):
        host = host_payload(hostprobe.parse(fixture("probe_2026-11-06_beelink.txt")))
        planned = plan.plan_for(host)
        self.assertEqual(planned["steps"], [])
        self.assertTrue(planned["refusals"], "an empty plan must say why it is empty")


class CveTracker(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(fixture("cve-2026-98432_resolute.json"))
        self.parsed = cve_tracker.parse(self.record, "resolute")

    def test_the_record_parses(self):
        self.assertEqual(self.parsed["id"], "CVE-2026-98432")
        self.assertEqual(self.parsed["priority"], "critical")
        self.assertEqual(self.parsed["notices_ids"], [])

    def test_dne_entries_are_dropped_and_open_statuses_kept(self):
        names = {s["package"] for s in self.parsed["statuses"]}
        self.assertIn("linux", names)
        self.assertNotIn("linux-hwe", names)          # DNE in resolute: not a fact about us
        linux = next(s for s in self.parsed["statuses"] if s["package"] == "linux")
        self.assertEqual((linux["status"], linux["version"]), ("pending", "7.0.0-43.43"))
        self.assertTrue(linux["open"])

    def test_the_tracker_disagrees_with_the_measured_machine(self):
        host = host_payload(hostprobe.parse(fixture("probe_2026-11-06_beelink.txt")))
        compared = cve_tracker.compare_to_measurement(self.parsed, host)
        self.assertEqual(len(compared["disagreements"]), 1, compared)
        only = compared["disagreements"][0]
        self.assertEqual(only["package"], "linux")
        self.assertEqual(only["certainty"], "exact version")
        self.assertEqual(only["we_have_installed"], "7.0.0-43.43")
        # a realtime or cloud kernel's fix says nothing about a generic-running host
        self.assertIn("linux-realtime", {s["package"] for s in compared["not_compared"]})

    def test_an_older_machine_is_not_a_disagreement(self):
        host = host_payload(hostprobe.parse(fixture("probe_2026-11-06_before_upgrade.txt")))
        compared = cve_tracker.compare_to_measurement(self.parsed, host)
        self.assertEqual(compared["disagreements"], [],
                         "the fix is not installed there, so the tracker's 'pending' is right")


class UsnNotices(unittest.TestCase):
    NOTICES = [{"id": "USN-9003-1", "title": "Linux kernel (NVIDIA) vulnerabilities",
                "published": "2026-11-06T11:30:38.911946",
                "cves_ids": ["CVE-2026-72154", "CVE-2026-98432"],
                "release_packages": {"resolute": [{"name": "linux", "version": "7.0.0-43.43",
                                                   "is_source": True}]}}]

    def test_a_notice_naming_the_cve_is_found(self):
        hits = usn.for_cve(self.NOTICES, "cve-2026-98432")     # case-insensitive on purpose
        self.assertEqual([h["id"] for h in hits], ["USN-9003-1"])

    def test_a_cve_no_notice_names_is_an_empty_answer(self):
        self.assertEqual(usn.for_cve(self.NOTICES, "CVE-1999-0001"), [])

    def test_fixed_versions_carry_the_source_flag(self):
        fixed = usn.fixed_versions(self.NOTICES[0], "resolute")
        self.assertEqual(fixed, [{"package": "linux", "version": "7.0.0-43.43", "is_source": True}])

    def test_index_and_explain_agree_on_a_source_package(self):
        idx = verdict.usn_index(self.NOTICES)
        self.assertEqual(verdict.explain("linux-image-generic", "7.0.0-43.43", idx), "USN-9003-1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
