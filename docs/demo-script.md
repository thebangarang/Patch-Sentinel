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
| 1 | 0:00–0:12 | `hermes chat -q "are we patched?"` — the tool line `⚡ Cve_scan` appears, then the answer | "Every scanner answers 'are we patched?'. This one answers it per host — and shows you what it could not look at." |
| 2 | 0:12–0:30 | the pane: **NOW** row for `fedora-lab` amber, `109 pending`, `kernel 7.2.11-300.fc45 → kernel-update-available` | "Fedora, not my laptop. 109 updates, and a kernel that is installed… no — a kernel that is *installable* while an older one is *running*. Those are different facts, and it keeps them apart." |
| 3 | 0:30–0:45 | `hermes chat -q "what about CVE-2026-98432?"` → `cve_explain`, the `disagreements[]` block on screen | "Ubuntu's own tracker still says *pending* for this CVE. This machine runs the version it calls the fix. The verdict follows the measurement, not the page." |
| 4 | 0:45–1:00 | pane **GAPS** panel, then a scan with an unreachable host (`vps=nowhere.invalid`) → red row, `COULD NOT LOOK`, exit 2 | "Here's the part no other scanner does: when it can't look, it says so. Unreachable host — red, not green. Missing tool — red. That's the whole product." |
| 5 | 1:00–1:25 | pane **APPLY** gate: type `fedora-lab` → **dry run** → step rc 100 · then **apply** (cut the 105 s) → receipt line | "Applying needs the host name typed by hand and the dry run passed first. It staged, it applied 107 packages, and then it re-measured the machine: kernel *installed* 7.2.15, *running* 7.2.11 — so it won't call that patched." |
| 6 | 1:25–1:30 | terminal: `lab_vm.py ssh fedora -- uname -r` → `7.2.15-300.fc45.x86_64`; then the repo URL | "Rebooted. Now it's patched, and the receipt says so. Code's at github.com/thebangarang/Patch-Sentinel." |

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
- **Not** "it patched my laptop": the real apply happened on a disposable Fedora VM, and saying so
  costs nothing.
- The 109 pending updates are **the image's**, not a machine that was neglected — say "a fresh boot
  of the Fedora cloud image, six days behind" if it comes up.
