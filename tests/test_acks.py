"""An acknowledgement has to be a record, not a mute button.

These tests pin the three properties that make that true: a reason is compulsory, the record names one
advisory id (so a new advisory on the same version reappears), and it expires on its own.
"""

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patch_sentinel.sources import acks


def row(advisory, package="diskcache", version="5.6.3", ecosystem="PyPI"):
    return {"id": advisory, "ecosystem": ecosystem, "package": package,
            "version": version, "fix_state": "not-fixed"}


class TheReasonIsCompulsory(unittest.TestCase):
    def test_an_acknowledgement_without_a_reason_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            for reason in ("", "   ", None):
                answer = acks.acknowledge(tmp, host="beelink", ecosystem="PyPI",
                                          package="diskcache", version="5.6.3",
                                          advisory="GHSA-1", reason=reason)
                self.assertFalse(answer["ok"], reason)
                self.assertIn("reason", answer["reason"])
            self.assertEqual(acks._read(tmp), [], "a refused record was written anyway")


class OneAdvisoryAtATime(unittest.TestCase):
    def test_a_new_advisory_on_the_same_version_is_not_covered(self):
        with tempfile.TemporaryDirectory() as tmp:
            acks.acknowledge(tmp, host="beelink", ecosystem="PyPI", package="diskcache",
                             version="5.6.3", advisory="GHSA-1", reason="no fix, accepted")
            kept, acked = acks.split(tmp, "beelink", [row("GHSA-1"), row("GHSA-2")])
            self.assertEqual([r["id"] for r in acked], ["GHSA-1"])
            self.assertEqual([r["id"] for r in kept], ["GHSA-2"])

    def test_another_host_is_not_covered_by_the_same_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            acks.acknowledge(tmp, host="beelink", ecosystem="PyPI", package="diskcache",
                             version="5.6.3", advisory="GHSA-1", reason="accepted")
            kept, acked = acks.split(tmp, "webasix", [row("GHSA-1")])
            self.assertEqual(acked, [])
            self.assertEqual(len(kept), 1)

    def test_release_reopens_the_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            acks.acknowledge(tmp, host="beelink", ecosystem="PyPI", package="diskcache",
                             version="5.6.3", advisory="GHSA-1", reason="accepted")
            answer = acks.release(tmp, host="beelink", ecosystem="PyPI", package="diskcache",
                                  version="5.6.3", advisory="GHSA-1")
            self.assertTrue(answer["ok"])
            kept, acked = acks.split(tmp, "beelink", [row("GHSA-1")])
            self.assertEqual(acked, [])
            self.assertEqual(len(kept), 1)

    def test_releasing_something_never_acknowledged_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            answer = acks.release(tmp, host="beelink", ecosystem="PyPI", package="diskcache",
                                  version="5.6.3", advisory="GHSA-never")
            self.assertFalse(answer["ok"])


class ItExpires(unittest.TestCase):
    def test_an_expired_record_covers_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            acks.acknowledge(tmp, host="beelink", ecosystem="PyPI", package="diskcache",
                             version="5.6.3", advisory="GHSA-1", reason="until next quarter", days=1)
            stored = acks._read(tmp)
            self.assertEqual(len(stored), 1)
            later = stored[0]["until"] + 1
            kept, acked = acks.split(tmp, "beelink", [row("GHSA-1")], now=later)
            self.assertEqual(acked, [], "an expired acknowledgement still hid a finding")
            self.assertEqual(len(kept), 1)

    def test_days_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            answer = acks.acknowledge(tmp, host="beelink", ecosystem="PyPI", package="x",
                                      version="1", advisory="A-1", reason="r", days=9999)
            self.assertEqual(answer["ack"]["days"], acks.MAX_DAYS)
            answer = acks.acknowledge(tmp, host="beelink", ecosystem="PyPI", package="y",
                                      version="1", advisory="A-2", reason="r", days=0)
            self.assertEqual(answer["ack"]["days"], 1, "a zero-day record would vanish before it is read")


class TheFileIsPrivate(unittest.TestCase):
    def test_acks_json_is_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            acks.acknowledge(tmp, host="beelink", ecosystem="PyPI", package="diskcache",
                             version="5.6.3", advisory="GHSA-1", reason="accepted")
            mode = os.stat(os.path.join(tmp, "acks.json")).st_mode & 0o777
            self.assertEqual(mode, 0o600, oct(mode))


if __name__ == "__main__":
    unittest.main()
