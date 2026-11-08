"""The integrity reading, on the real output of a healthy Ubuntu box.

The captured `dpkg -V` output below is the one that matters: a healthy machine as a non-root account
prints eleven `?????????` lines (could not read) and two `5` lines in conffiles. Folding the first into
"files changed" is how this check would have accused a clean host of eleven tampered binaries, so the
parser is pinned to exactly what dpkg writes.
"""

import os
import sys
import tempfile
import time
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
            self.assertIn("could not be verified", state["note"])

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


class SocketsAreClassifiedBeforeTheyAreAccused(unittest.TestCase):
    """A port is not a verdict. The four decisions this pins are the difference between a panel people
    read and one they learn to ignore.

    The operator's own machine produced `tcp:48997, udp:45709, udp:45753, udp:60365` on one read and
    none of them two minutes later — the agent's own loopback port and a browser's QUIC sockets. All
    reported as "not in the baseline" is technically true and useless.
    """

    BASE = "\n".join([
        "tcp  LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))",
        "tcp  LISTEN 0 511 [::]:443 [::]:* users:((\"nginx\",pid=2,fd=4))",
        "udp  UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=3,fd=5))",
    ])

    def read(self, tmp, extra="", first=False):
        return integrity.parse(probe(listeners=self.BASE + ("\n" + extra if extra else "")),
                               "beelink", tmp)

    def test_an_ephemeral_loopback_socket_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.read(tmp)
            state = self.read(tmp, "tcp LISTEN 0 2048 127.0.0.1:48997 0.0.0.0:* "
                                   "users:((\"hermes\",pid=9,fd=7))")
            self.assertEqual(state["listeners"]["state"], "ok",
                             "the agent's own ephemeral port was raised as a finding")
            self.assertEqual(state["listeners"]["drift_count"], 1)
            self.assertEqual(state["listeners"]["new"], [])
            self.assertIn("close by themselves, not counted", integrity.summarise(state))

    def test_a_udp_socket_on_an_ephemeral_port_is_a_client_not_a_door(self):
        # the operator's lab VM (qemu-system-x86_64) binds short-lived UDP sockets on 0.0.0.0 for DNS;
        # three of them became findings, and they were gone two minutes later
        with tempfile.TemporaryDirectory() as tmp:
            self.read(tmp)
            state = self.read(tmp, "udp UNCONN 0 0 0.0.0.0:41241 0.0.0.0:* "
                                   "users:((\"qemu-system-x86\",pid=42,fd=9))")
            self.assertEqual(state["listeners"]["state"], "ok")
            self.assertEqual(state["listeners"]["drift_count"], 1)
            self.assertEqual(state["listeners"]["drift_public"], ["udp:41241"])
            self.assertIn("clients do", integrity.summarise(state))

    def test_a_tcp_socket_on_an_ephemeral_port_is_still_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.read(tmp)
            state = self.read(tmp, "tcp LISTEN 0 128 0.0.0.0:41241 0.0.0.0:*")
            self.assertEqual(state["listeners"]["state"], "finding")
            self.assertEqual([s["id"] for s in state["listeners"]["exposed"]], ["tcp:41241"])

    def test_a_socket_reachable_from_anywhere_is_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.read(tmp)
            state = self.read(tmp, "tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:* "
                                   "users:((\"python\",pid=77,fd=3))")
            self.assertEqual(state["listeners"]["state"], "finding")
            self.assertEqual([s["id"] for s in state["listeners"]["exposed"]], ["tcp:4444"])
            self.assertIn("reachable from the network", integrity.summarise(state))
            self.assertIn("python", integrity.summarise(state))

    def test_a_new_loopback_socket_on_a_fixed_port_is_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.read(tmp)
            state = self.read(tmp, "tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*")
            self.assertEqual(state["listeners"]["state"], "finding")
            self.assertEqual([s["id"] for s in state["listeners"]["stable"]], ["tcp:8080"])

    def test_the_same_port_moving_to_the_network_is_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.read(tmp, "tcp LISTEN 0 128 127.0.0.1:9000 0.0.0.0:*")
            state = self.read(tmp, "tcp LISTEN 0 128 0.0.0.0:9000 0.0.0.0:*")
            self.assertEqual(state["listeners"]["state"], "finding")
            self.assertEqual([s["id"] for s in state["listeners"]["widened"]], ["tcp:9000"],
                             "a port that opened to the network kept the same id and slipped through")

    def test_the_owner_is_kept_when_the_process_is_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self.read(tmp)
            owners = {(s["id"], s["owner"]) for s in state["listeners"]["records"]}
            self.assertIn(("tcp:22", "sshd"), owners)
            self.assertIn(("udp:53", "systemd-resolve"), owners)

    def test_the_advice_names_the_port_to_look_at(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.read(tmp)
            state = self.read(tmp, "tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:*")
            row = [r for r in integrity.answers(state) if r["check"] == "listening sockets"][0]
            self.assertIn("ss -lntup", row["advice"])
            self.assertIn("4444", row["advice"])


class ArchSaysBackupFile(unittest.TestCase):
    """Real `pacman -Qkk` output from a fresh Arch install: 11 size mismatches and 11 checksum
    mismatches, every one of them a `backup file:` (a conffile), plus 12 files this account could not
    read. Reading that as 22 tampered files would have accused a clean machine."""

    SAMPLE = [
        "warning: audit: /etc/libaudit.conf (failed to calculate SHA256 checksum)",
        "warning: filesystem: /etc/resolv.conf (File type mismatch)",
        "backup file: filesystem: /etc/fstab (Size mismatch)",
        "backup file: filesystem: /etc/fstab (SHA256 checksum mismatch)",
        "backup file: filesystem: /etc/group (Modification time mismatch)",
        "warning: bash: /usr/bin/bash (Size mismatch)",
    ]

    def test_a_conffile_that_differs_is_not_tampering(self):
        parsed = integrity.parse_pacman(self.SAMPLE)
        self.assertEqual(parsed["changed"], ["/usr/bin/bash"],
                         "a pacman backup file was counted as tampered")
        self.assertIn("/etc/fstab", parsed["conffiles"])
        self.assertIn("/etc/resolv.conf", parsed["conffiles"])

    def test_a_file_it_could_not_read_is_unreadable(self):
        parsed = integrity.parse_pacman(self.SAMPLE)
        self.assertEqual(parsed["unreadable"], ["/etc/libaudit.conf"])


class TheRootReadingComesBackAsAPaste(unittest.TestCase):
    """The pane cannot elevate, so the operator runs the command and the pane reads the paste.

    What must stay true: it is labelled as theirs, a mismatch found that way is still a finding, and a
    blank paste is refused (a clean run prints nothing, so a blank is indistinguishable from a misfire).
    """

    def state(self, tmp):
        return integrity.parse(probe(dpkg="?????????   /etc/sudoers", listeners=LISTENERS),
                               "beelink", tmp)

    def test_a_clean_root_run_completes_the_coverage_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self.state(tmp)
            self.assertIn("could not be verified", state["note"])
            merged = integrity.merge_pasted(state, "??5?????? c /etc/default/ufw\n"
                                                  "??5?????? c /etc/apt/sources.list.d/x.list")
            self.assertTrue(merged["ok"])
            self.assertEqual(merged["root_reading"]["changed_count"], 0)
            self.assertEqual(merged["root_reading"]["conffile_count"], 2)
            self.assertIn("coverage completed by a root reading", state["note"])
            self.assertIn("run by you", state["note"])
            self.assertTrue(state["tamper"]["covered"])
            self.assertEqual(state["state"], "ok")

    def test_a_mismatch_in_the_paste_is_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self.state(tmp)
            merged = integrity.merge_pasted(state, "??5??????   /usr/bin/ssh")
            self.assertTrue(merged["ok"])
            self.assertEqual(state["state"], "finding")
            self.assertEqual(state["tamper"]["changed"], ["/usr/bin/ssh"])
            self.assertIn("a finding", merged["answer"])

    def test_a_blank_paste_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self.state(tmp)
            for blank in ("", "   \n\n "):
                merged = integrity.merge_pasted(state, blank)
                self.assertFalse(merged["ok"])
                self.assertIn("empty", merged["reason"])

    def test_a_host_with_no_package_database_refuses_a_paste(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = integrity.parse(probe(tools="", listeners=LISTENERS), "unknown", tmp)
            merged = integrity.merge_pasted(state, "??5?????? /usr/bin/ssh")
            self.assertFalse(merged["ok"])

    def test_the_paste_is_kept_with_its_source_and_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self.state(tmp)
            integrity.merge_pasted(state, "??5?????? c /etc/default/ufw", now=1_800_000_000)
            self.assertEqual(state["root_reading"]["source"], "pasted by the operator")
            self.assertEqual(state["root_reading"]["at"], 1_800_000_000)


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
            # the two calls take their own `time.time()`; what matters is that the time is kept
            self.assertLess(abs(read["at"] - saved["at"]), 2)
            self.assertEqual(read["state"]["state"], state["state"])

    def test_rows_are_the_three_readings(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = integrity.parse(probe(listeners=LISTENERS), "beelink", tmp)
            rows = integrity.answers(state)
            self.assertEqual([r["check"] for r in rows],
                             ["package checksums", "preload hook", "listening sockets"])


class RootCoverage(unittest.TestCase):
    """A root run the operator did must close the row — and reopen when the package set moves.

    The reported loop: the same "16 files this account cannot read" came back after every scan, even
    though the operator had already run `sudo dpkg -V` and pasted the result.
    """

    def test_a_fresh_root_run_covers_the_set(self):
        now = time.time()
        coverage = {"at": now - 60, "changed_count": 0, "conffile_count": 2, "db_mtime": now - 7200}
        self.assertTrue(integrity.coverage_covers(coverage, "dpkg -V", now=now))

    def test_an_install_since_the_root_run_reopens_it(self):
        # the database is newer than the run: it described a different package set
        now = time.time()
        coverage = {"at": now - 60, "db_mtime": 1_000_000}       # ancient stamp
        self.assertFalse(integrity.coverage_covers(coverage, "dpkg -V", now=now))

    def test_a_month_old_run_is_asked_again(self):
        now = time.time()
        coverage = {"at": now - (31 * 86400), "db_mtime": None}
        self.assertFalse(integrity.coverage_covers(coverage, "dpkg -V", now=now))

    def test_no_coverage_at_all_does_not_cover(self):
        self.assertFalse(integrity.coverage_covers(None, "dpkg -V"))
        self.assertFalse(integrity.coverage_covers({}, "dpkg -V"))

    def test_attesting_a_clean_run_marks_the_state_covered(self):
        data = tempfile.mkdtemp()
        state = {"tamper": {"tool": "dpkg -V", "unreadable_count": 16}}
        result = integrity.attest(data, "box", state)
        self.assertTrue(result["ok"])
        self.assertTrue(state["tamper"]["covered"])
        self.assertEqual(state["tamper"]["root_reading"]["changed_count"], 0)
        saved = integrity.read_root_coverage(data, "box")
        self.assertIsNotNone(saved, "the attestation was not stored")
        self.assertIn("printed nothing", saved["source"])


if __name__ == "__main__":
    unittest.main()
