# The 90-second demo — shot list, prompts, captions

Everything below is filmable **as it stands**: every number comes from a run on this machine. Record
one continuous take, then cut the dead air (the apply takes ~105 s — cut it to the receipt, and say
the duration out loud).

## Before you record (5 minutes, once)

```bash
cd ~/projects/patch-sentinel
.venv/bin/python scripts/lab_vm.py down fedora
rm -f tmp/vms/fedora.qcow2 tmp/vms/fedora-seed.iso      # a fresh Fedora = 109 pending again
.venv/bin/python scripts/lab_vm.py up fedora            # ~25 s
.venv/bin/python tmp/scan_all.py                        # confirm: fedora-lab, 109 pending, exit 1
```

Also have open: the Hermes window with the **Patch Sentinel pane**, and a terminal at
`~/projects/patch-sentinel`.

Do **not** reboot the beelink, and do not apply to it — every real change in the video happens on
the Fedora VM, which is disposable.

## The six shots

| # | time | on screen | say / type |
|---|---|---|---|
| 1 | 0:00–0:14 | pane top: the **verdict bar** — `2 servers · 3 updates pending · 1 exploited · 1 could not look · measured just now` — then `hermes chat -q "are we patched?"` with the `⚡ Cve_scan` line | "Every scanner answers 'are we patched?'. This one answers in one line, per host, and names what it could not look at." |
| 2 | 0:14–0:30 | **OVERVIEW**: `fedora-lab` amber, `109 pending`, `kernel 7.2.11 → 7.2.15 installed, reboot needed` | "Fedora, not my laptop. 109 updates, and a kernel that is *installed* while an older one is *running* — it keeps those apart instead of calling it done." |
| 3 | 0:30–0:46 | **LIBS & RUNTIMES** on the log4j fixture: `8 advisories · critical · fix 2.15.0`, chips `EXPLOITED · RANSOMWARE` and `EPSS 100.0%` | "This is the part that decides tonight: not 'critical', but *being used in ransomware campaigns right now*, from CISA's own catalogue, with the probability score beside it." |
| 4 | 0:46–1:02 | **SERVERS → add a server**: type `debian-lab` / `debian@10.0.0.9:2223` → test fails at chip `STOPPED AT AUTH` with the `ssh-copy-id` command → copy, run, test again → `reached it: apt · debian/12 · kernel-current` | "Adding a fleet member never fails with 'it didn't work'. It tells you which hop failed and gives you the one command that fixes it — and it only saves the host once a real probe came back." |
| 5 | 1:02–1:16 | **SYSTEM PACKAGES** for `debian-lab`: the vendor-lag block — `fix exists upstream, this archive does not carry it` — plus the `archive index is older than 48 h` warning | "A fix can exist and still not be installable here. That's its own state, and it never gets folded into 'nothing to do'." |
| 6 | 1:16–1:30 | **APPLY**: type `fedora-lab` → stage → apply (cut the 105 s) → receipt: kernel *installed* 7.2.15, *running* 7.2.11 → then `uname -r` after reboot | "Applying needs the name typed by hand. It applied, re-measured, and refused to call itself patched until the reboot — which is the whole point." |

Narration is optional; if you prefer silence, the six shots still tell it — subtitle them with those
same lines.

## Caption (X), ≤ 280 characters

> Patch Sentinel — a Hermes plugin that answers "are we patched?" with evidence, for whatever the
> host runs: apt, dnf, pacman, zypper, container digests, your npm/pip stack. It refuses to say
> "clean" when it couldn't look. 90 s, real machines, one gated apply. @NousResearch
> github.com/thebangarang/Patch-Sentinel

## Credits line (end card)

> Patch Sentinel · MIT · github.com/thebangarang/Patch-Sentinel
> Built with Hermes Agent · demo run on Ubuntu 26.04, Fedora 45, Debian 12, Arch and openSUSE Leap
> (the last four in QEMU)

## What NOT to claim on camera

- **Not** "patches everything": say which four package families, and that Alpine/macOS/Windows have
  no verified adapter yet.
- **Not** "finds every CVE": in-image CVEs and per-project lockfiles are named gaps, on the GAPS
  panel, in the same breath as the findings.
- **Not** "nothing is exploited" when KEV has no match — the catalogue is a US feed and absence is not
  safety. The pane says `kev_state: measured`, never `safe`.
- **Not** "EPSS says it will be exploited" — it is a 30-day forecast, shown as a percentage, never as a
  verdict on its own.
- **Not** "it patched my laptop": the real apply happened on a disposable Fedora VM, and saying so
  costs nothing.
- The 109 pending updates are **the image's**, not a machine that was neglected — say "a fresh boot
  of the Fedora cloud image, six days behind" if it comes up.
