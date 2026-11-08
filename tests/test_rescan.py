"""The contract of one per-device run: every counted number has a sentence, and a 2 has a reason.

The scenario batch caught this on a synthetic host: `cve_rescan` returned exit_code 2 with an answer
that listed counts and timings and never said what could not be looked at. Reading that line, the only
honest interpretation is "everything was read" — which is the one claim this plugin may not make.
"""
import json
import os
import tempfile
import unittest

from patch_sentinel import store, tools


class RescanAnswer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rescan-")
        tools.configure({"data_dir": self.tmp, "hosts": "testbox=local", "release": "resolute",
                         "usn_limit": 20, "acknowledged": "", "osv_offline": "1"})
        self.original = {}

    def tearDown(self):
        for name, handler in self.original.items():
            setattr(tools, name, handler)

    def stub(self, name, payload):
        self.original[name] = getattr(tools, name)
        setattr(tools, name, lambda args=None: json.dumps(payload))

    def run_rescan(self):
        payload = json.loads(tools.cve_rescan({"host": "testbox"}))
        return payload

    def test_a_stage_that_could_not_look_says_which_and_why(self):
        self.stub("cve_scan", {"tool": "cve_scan", "exit_code": 0,
                               "hosts": {"testbox": {"label": "testbox", "pending_count": 0,
                                                     "where": {"kind": "local"}}}})
        self.stub("cve_integrity", {"tool": "cve_integrity", "exit_code": 2,
                                    "answer": "the package database could not be read on testbox "
                                              "(permission denied)"})
        self.stub("cve_libraries", {"tool": "cve_libraries", "exit_code": 0, "vulnerable": []})
        self.stub("cve_plan", {"tool": "cve_plan", "exit_code": 0, "steps": []})

        payload = self.run_rescan()

        self.assertEqual(payload["exit_code"], 2, "a stage that could not look is exit 2")
        self.assertIn("could not look", payload["answer"],
                      "exit 2 must carry a sentence saying what was not read")
        self.assertIn("integrity", payload["answer"])
        self.assertIn("permission denied", payload["answer"], "the reason travels with the stage")
        blind = payload["bundle"]["devices"]["testbox"]["blind"]
        self.assertEqual([item["name"] for item in blind], ["integrity"])
        self.assertTrue(blind[0]["why"])

    def test_a_clean_run_carries_no_blind_line(self):
        self.stub("cve_scan", {"tool": "cve_scan", "exit_code": 0,
                               "hosts": {"testbox": {"label": "testbox", "pending_count": 0,
                                                     "where": {"kind": "local"}}}})
        self.stub("cve_integrity", {"tool": "cve_integrity", "exit_code": 0,
                                    "integrity": {"state": "ok", "tamper": {}}})
        self.stub("cve_libraries", {"tool": "cve_libraries", "exit_code": 0, "vulnerable": []})
        self.stub("cve_plan", {"tool": "cve_plan", "exit_code": 0, "steps": []})

        payload = self.run_rescan()

        self.assertEqual(payload["exit_code"], 0)
        self.assertNotIn("could not look", payload["answer"])
        self.assertEqual(payload["bundle"]["devices"]["testbox"]["blind"], [])

    def test_the_stages_run_in_the_order_the_page_draws_them(self):
        for name in ("cve_scan", "cve_integrity", "cve_libraries"):
            self.stub(name, {"tool": name, "exit_code": 0, "vulnerable": []} if name.startswith("cve_lib")
                      else {"tool": name, "exit_code": 0})
        self.stub("cve_plan", {"tool": "cve_plan", "exit_code": 0, "steps": []})

        payload = self.run_rescan()

        stages = [stage["name"] for stage in payload["bundle"]["stages"]]
        self.assertEqual(stages, ["scan", "integrity", "libraries", "plans"],
                         "the run must follow the section order: packages, integrity, libs")


if __name__ == "__main__":
    unittest.main(verbosity=2)
