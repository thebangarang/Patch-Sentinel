# PR: add `patch-sentinel` to the plugin catalogue

## What it does

Patch Sentinel answers *"are we patched?"* with evidence, for whatever the host actually runs. It
picks a package-manager adapter from the host's own `/etc/os-release` (`apt` for Ubuntu/Debian and
relatives, `dnf` for Fedora/RHEL/Rocky/Alma/CentOS/Amazon, `pacman` for Arch, `zypper` for
openSUSE/SLES), and reports three surfaces: the running kernel versus the newest installed and the
newest installable; every pending package update, unfiltered by `-security`, annotated with the
advisory that names that exact version; and each running container image's tag against its registry
digest. A fifth tool checks the language stack (npm global, pip on PATH) through OSV.

**Every check has three outcomes** — clean, finding, could-not-look. An unreachable host, a distro
with no adapter, or a registry that rate-limited us is reported as `unknown` with its reason and a
non-zero exit code, never as patched. That is the plugin's whole argument.

`cve_apply` is the only tool that changes a machine: it refuses unless the operator types the host
label, the user can run `sudo` without a prompt on that host, and `dry_run=false`. It stages first,
applies, then re-measures the host so the receipt says what the machine *is*.

## Evidence (all on real machines, 2026-11-06)

- Five hosts, four families, one call: Ubuntu 26.04, Debian 12, Fedora 45, Arch, openSUSE Leap 15.6
  → `exit_code 0, findings 0, blind 0`.
- A real gated apply on the Fedora VM: 109 pending → stage rc 100 → apply rc 0 (3 installing / 107
  upgrading, 105 s) → re-measured: kernel **installed** 7.2.15, **running** 7.2.11 →
  `reboot_required: true` → after rebooting, `uname -r` reads `7.2.15-300.fc45`.
- 348 unit tests; the 23 assertions ported from our standing routine (differentially checked against
  it over 770 comparisons) are among them.

## Disclosure (also in the README and SECURITY.md)

- **Network**: `ubuntu.com/security/notices.json` and `/cves/<CVE>.json`, `api.osv.dev`, and the
  container registry's manifest API via `docker buildx imagetools`. No telemetry, no analytics.
- **Subprocesses**: `uname`, `dpkg-query`, `apt-cache`, `apt-get -s dist-upgrade`, `rpm`, `dnf -q
  check-upgrade`/`list`, `pacman -Q`/`-Qu`, `zypper -q lu`, `docker ps|inspect|buildx`, and
  `ssh <host>` — all read-only in the scan. The apply runs `apt-get -y full-upgrade` or
  `dnf -y upgrade --refresh` with `sudo`, only after the typed host name, and writes a receipt.
- **Credentials**: none. No `requires_env`/`optional_env`; registry reads are anonymous, remote hosts
  use the operator's own SSH agent. The plugin never reads `.env` or `auth.json`.
- **Files written**: `last_scan.json`, `settings.json` and `receipts.jsonl` under
  `$HERMES_HOME/patch-sentinel`, mode 600.
- **Desktop half**: opt-in (`defaultEnabled: false`), three panels + a gated apply control, talks
  only to its own `/api/plugins/patch-sentinel` routes.

## Known gaps, stated as gaps

- No in-image CVE scanning (needs trivy) and no per-project lockfile scanning; both are named in
  every `cve_coverage` answer and on the pane's GAPS panel.
- No adapter for Alpine (the `apk` code exists but has never read a real Alpine host, so it is not
  registered — Alpine answers `unsupported`), macOS, or Windows (which needs a PowerShell transport
  rather than a shell block).
- The pinned SHA points at the reviewed tree; the pin itself lands in a follow-up commit, since a
  commit cannot contain its own hash.
