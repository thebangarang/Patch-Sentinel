"""The integrity reading, on the real output of a healthy Ubuntu box.

The captured `dpkg -V` output below is the one that matters: a healthy machine as a non-root account
prints eleven `?????????` lines (could not read) and two `5` lines in conffiles. Folding the first into
"files changed" is how this check would have accused a clean host of eleven tampered binaries, so the
parser is pinned to exactly what dpkg writes.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patch_sentinel.sources import integrity


def probe(dpkg="", listeners="", preload="NO-PRELOAD", tools="dpkg", uid=1000, user="hermes"):
    return "\n".join([
        integrity.MARK_DB, f"WHOAMI={user} UID={uid}"]
        + [f"HAVE-{t}" for t in tools.split() if t]
        + [integrity.MARK_PRELOAD, preload, integrity.MARK_LISTEN, listeners,
           integrity.MARK_TAMPER, dpkg, integrity.MARK_END, ""])


HEALTHY_NONROOT = "\n".join([
    "?????????   /boot/vmlinuz-7.0.0-43-generic",
    "?????????   /usr/share/chrony/chrony.keys",
    "??5?????? c /etc/default/ufw",
    "?????????   /usr/libexec/sssd/sssd_pam",
    "????????? c /etc/sudoers",
    "??5??????   /usr/bin/ssh",
    "missing     /var/cache/cups/rss (Permission denied)",
])

LISTENERS = "\n".join([
    "udp UNCONN 0      0        127.0.0.53%lo:53    0.0.0.0:*",
    "udp UNCONN 0      0        127.0.0.1:323        0.0.0.0:*",
    "tcp  LISTEN 0      128      0.0.0.0:22          0.0.0.0:*",
    "tcp  LISTEN 0      511      [::]:443            [::]:*",
])


class TheParsersReadWhatTheToolsWrite(unittest.TestCase):
    def test_unreadable_files_are_not_tampering(self):
        lines = ["?????????   /boot/vmlinuz-7.0.0-43-generic",
                 "????????? c /etc/sudoers",
                 "missing     /var/cache/cups/rss (Permission denied)"]
        parsed = integrity.parse_dpkg(lines)
        self.assertEqual(parsed["changed"], [], "a file dpkg could not read was called modified")
        self.assertEqual(len(parsed["unreadable"]), 3)
        # an unreadable conffile is unreadable, not "an edited conffile": the reading has to say
        # "could not look", and a `c` next to `?????????` does not turn that into a measurement
        self.assertEqual(len(parsed["conffiles"]), 0)

    def test_an_edited_conffile_is_counted_apart(self):
        parsed = integrity.parse_dpkg(["??5?????? c /etc/default/ufw", "??5??????  /usr/bin/ssh"])
        self.assertEqual(parsed["changed"], ["/usr/bin/ssh"])
        self.assertEqual(parsed["conffiles"], ["/etc/default/ufw"])

    def test_a_deleted_packaged_file_is_a_finding(self):
        parsed = integrity.parse_dpkg(["missing     /usr/bin/sudo"])
        self.assertEqual(parsed["missing"], ["/usr/bin/sudo"])

    def test_ss_columns_are_read_by_shape_not_by_position(self):
        ports = integrity.parse_listeners(LISTENERS.splitlines())
        self.assertEqual(ports, ["tcp:22", "tcp:443", "udp:53", "udp:323"])

    def test_a_header_line_is_not_a_port(self):
        ports = integrity.parse_listeners(["Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port"])
        self.assertEqual(ports, [])


class TheThreeStates(unittest.TestCase):
    def test_a_healthy_host_is_measured_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = integrity.parse(probe(dpkg="?????????   /boot/vmlinuz", listeners=LISTENERS),
                                    "beelink", tmp)
            self.assertEqual(state["tamper"]["state"], "ok")
            self.assertIn("in the surfaces read", integrity.summarise(state))
            self.assertIn("could not be read", state["note"])

    def test_a_second_reading_compares_the_socket_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = integrity.parse(probe(listeners=LISTENERS), "beelink", tmp)
            self.assertEqual(first["listeners"]["state"], "baseline")
            second = integrity.parse(probe(listeners=LISTENERS), "beelink", tmp)
            self.assertEqual(second["listeners"]["state"], "ok")
            third = integrity.parse(probe(listeners=LISTENERS + "\ntcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:*"),
                                    "beelink", tmp)
            self.assertEqual(third["listeners"]["state"], "finding")
            self.assertEqual(third["listeners"]["new"], ["tcp:4444"])

    def test_a_preload_hook_is_a_finding_on_its_own(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = integrity.parse(probe(preload="/usr/local/lib/libhide.so", listeners=LISTENERS),
                                    "beelink", tmp)
            self.assertEqual(state["preload"]["state"], "finding")
            self.assertEqual(state["state"], "finding")
            self.assertIn("ld.so.preload", integrity.summarise(state))

    def test_no_package_database_is_unmeasured_never_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = integrity.parse(probe(tools="", listeners=LISTENERS), "alpine-unknown", tmp)
            self.assertEqual(state["tamper"]["state"], "unmeasured")
            self.assertEqual(state["state"], "unmeasured")
            self.assertIn("not measured", integrity.summarise(state))

    def test_no_sockets_listed_is_unmeasured(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = integrity.parse(probe(listeners=""), "beelink", tmp)
            self.assertEqual(state["listeners"]["state"], "unmeasured")

    def test_a_host_that_does_not_answer_is_unmeasured(self):
        state = integrity.collect("root@203.0.113.9", tempfile.mkdtemp(), "ghost", timeout=1)
        self.assertEqual(state["state"], "unmeasured")


class TheBaselineIsAFact(unittest.TestCase):
    def test_the_baseline_file_is_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            integrity.parse(probe(listeners=LISTENERS), "beelink", tmp)
            mode = os.stat(os.path.join(tmp, "integrity.json")).st_mode & 0o777
            self.assertEqual(mode, 0o600, oct(mode))

    def test_the_last_reading_is_kept_with_its_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = integrity.parse(probe(listeners=LISTENERS), "beelink", tmp)
            saved = integrity.save_result(tmp, "beelink", state)
            read = integrity.read_result(tmp, "beelink")
            self.assertAlmostEqual(read["at"], saved["at"], places=3)
            self.assertEqual(read["state"]["state"], state["state"])

    def test_rows_are_the_three_readings(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = integrity.parse(probe(listeners=LISTENERS), "beelink", tmp)
            rows = integrity.answers(state)
            self.assertEqual([r["check"] for r in rows],
                             ["package checksums", "preload hook", "listening sockets"])


if __name__ == "__main__":
    unittest.main()
