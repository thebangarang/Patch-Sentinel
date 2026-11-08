# Add `patch-sentinel` to the plugin catalogue

Adds one entry: `plugin-catalog/patch-sentinel.yaml`. Community tier, MIT, Linux.

`patch-sentinel` answers *"are we patched?"* with evidence, for whatever the host actually runs — the
machine Hermes runs on, and any host it can reach over SSH.

- **Adapter from `/etc/os-release`**: apt, dnf, pacman, zypper, apk. Any other OS answers
  `unsupported` with its name rather than a green.
- **The running kernel** against the newest installed and the newest installable — a kernel update
  that is installed but not booted is its own verdict, because it is the commonest false clean there is.
- **Every pending package update**, deliberately unfiltered by `-security`, annotated with the advisory
  that names that fixed version per release (Ubuntu notices; OSV per release for Debian, Alpine and the
  RHEL family; Arch's tracker; Bodhi for Fedora; SUSE's OVAL).
- **Container image digests** against the registry, anonymously, without starting the image.
- **Integrity**: package checksums, `/etc/ld.so.preload`, and listening sockets against a recorded
  baseline. It says *no evidence of tampering in the surfaces read*, never "not compromised".
- **The language stack**: nine ecosystems through OSV — npm, pip (global *and* every virtualenv),
  Packagist, RubyGems, crates.io, Maven, Go, NuGet, Pub — plus jars on disk and eight lockfile kinds.
- **A CycloneDX SBOM** export.

**Every check has three outcomes: clean, finding, could-not-look.** An unreachable host, a distro with
no adapter, a registry that rate-limited us, or a language store that is not installed is reported as
unknown *with its reason*, never as patched. `exit_code` is 0/1/2 on that contract, and the pane shows
the same thing the tools do.

The desktop pane has **one control** — `scan all · <device>` — which reads one device at a time in the
order the page draws its sections, and then hands over the exact commands per device, numbered, with the
risk, the downtime, how to verify each step and how to undo it. **The pane changes nothing.**

`cve_apply` is the only tool that changes a machine. It refuses unless the operator types the host label,
`sudo -n` works on that host, and `dry_run=false`; it stages, applies, re-measures and writes a receipt,
and it hands the same commands over when it refuses. It never asks for, holds or forwards a password.

## Verification at the pinned SHA

- `python3 -m unittest discover -s tests -t .` — **349 tests**, green.
- `python3 scripts/scenario_batch.py` — **19 situations, 176 assertions, 0 findings**: an empty home, a
  read-only data dir, a corrupt state file, clock skew, no network, HTTP 429, a data dir that is a file,
  a host entry shaped like a command, duplicate labels, and two identical runs on an unchanged machine.
- `./scripts/pane_check.sh` — every panel rendered, both states.
- `hermes plugins validate .` and `hermes plugins doctor . --ci` — green (11 tools, 0 hooks, no network
  at import time).
- `scripts/validate_plugin_catalog.py` on the entry file in this PR — **OK, 1 file(s) valid**.

Read live, not from documentation: Ubuntu 26.04 (this machine) and a VPS over ssh, Debian 12, Fedora 45
and Arch, by copying the plugin onto each VM and running it with that distro's own `python3`. The
README's verified table names, per family, what was actually run — and the rows that are *not* verified
(openSUSE is command-level only; Alpine has never accepted the lab key; the RHEL family has no live
host) say so in the table, in the pane's gap list, and in every coverage answer.

## Disclosure

- **Network, anonymously**: `api.osv.dev`; `ubuntu.com/security/notices.json` and `/cves/<id>` on Ubuntu
  hosts only; `bodhi.fedoraproject.org` on Fedora; `security.archlinux.org` on Arch; SUSE's OVAL document
  on SUSE; and the container registries the user's images already come from, through
  `docker buildx imagetools`. No telemetry, no analytics, no other third party.
- **Subprocesses**: `uname`, `dpkg-query`/`dpkg -V`, `apt-cache`, `apt-get -s`, `rpm -qa`/`rpm -Va`,
  `dnf -q check-update`, `pacman -Q`/`-Qu`/`-Qkk`, `zypper -q lu`, `apk version`/`apk audit`, `ss`,
  `docker ps|inspect|buildx`, and `ssh <host>` for remote hosts. All read-only in the scan; every call is
  an argv list, never `shell=True`. The one privileged path is `cve_apply`, which runs `sudo -n` on the
  plan it just printed.
- **Credentials**: none. No `requires_env`, no `optional_env`, no credential file read. Registry and
  advisory reads are anonymous; remote hosts use the operator's own SSH agent, so `ssh` sees the key and
  the plugin never does. `docker login` on a host is used by the docker CLI, not read by the plugin.
- **Files written**: `last_scan.json`, `rescan.json`, `integrity.json`, `acks.json` and the apply
  receipts under `$HERMES_HOME/patch-sentinel` (directory 700, files 600). Nothing outside it.
- **Desktop half**: `desktop/plugin.js` uses only the plugin SDK and React — no prototype patching, no
  `eval`, no `import()` beyond `@hermes/plugin-sdk`/`react`, no access to the app's markup or stores.

## Admission scan

`hermes plugins validate .` passes; the install scanner rates the plugin **caution**, not dangerous. The
findings are `privilege_escalation` matches on strings like `sudo apt-get full-upgrade` — the plugin's
output *is* patch commands, and those strings are what it prints for a human to run. Nothing in the scan
executes them; the one tool that can is gated on a typed host name and `sudo -n`.

## The pin

The entry pins `d13d3693382ab8140b51873211831a3d4436590e`, which is the reviewed tree: README,
SECURITY, MIT licence, the pane and its tests, the 78-second demo, the banner. The commit that writes the
pin follows it, because a commit cannot contain its own hash. The `image:` URL is pinned to the same SHA,
so the banner cannot change under a reviewer.

## Known gaps, stated as gaps

- No CVE scanning inside image layers (needs an image scanner), and no coverage of a project that has
  only a manifest and no lockfile. Both are named in every coverage answer and in the pane.
- Alpine's `apk` adapter exists and is unit-tested against captured output but is **not registered** —
  every headless Alpine image in the lab refused the key, so no live host has been read. Such a host
  answers `unsupported`.
- openSUSE Leap ships python 3.6 and the plugin needs 3.10+, so that family is command-level only.
- No macOS or Windows: the probe is a POSIX shell block, and Windows would need a PowerShell transport
  before it could be a claim.
