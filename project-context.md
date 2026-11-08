# patch-sentinel — project context

## What it is

A **Hermes plugin** that answers *"are we patched?"* with evidence, for the machine Hermes runs on and
for any host it can reach over SSH, and that hands over the exact commands to close what it finds.

One rule governs the whole product: **an answer is a measurement, never an assumption.** Every check
reports one of three outcomes — clean, finding, *could not look* — and a surface that could not be read
is never shown as patched. `exit_code` 0 means nothing to do, 1 something to patch, 2 something could
not be looked at.

## Why it exists

We lived the problem in November 2026:

- CVE-2026-98432 was published 15 Oct; Ubuntu shipped the fixed kernel (7.0.0-43.43) on 5–6 Nov.
- **Ubuntu's CVE page still read "vulnerable, work in progress" while the fixed kernel was already
  published and installable through `-updates`.** Anyone trusting the CVE page alone was still waiting.
- **`apt-get upgrade` silently keeps a new kernel back** (a new kernel arrives as a new *package*), so
  the box looks handled and is not.
- The fix arrived through `-updates`, not `-security` — a security-pocket filter would have missed it.
- The machine had the fixed kernel *installed* and was still *running* the old one. A version list would
  have called that patched. It was not.
- A Docker Hub `429` made an image check answer "nothing to do" while four images were out of date: a
  false all-clear that took a second instrument to catch.

Each of those is now a rule in `docs/design.md`. That is the differentiator — not "we scan CVEs", but
"we refuse to report a clean we did not measure".

## What it does

| surface | how it is read |
|---|---|
| system packages | the host's own manager — apt, dnf, pacman, zypper, apk — through its simulation/dry-run output; never filtered to `-security` |
| running kernel | running vs newest installed vs newest installable, and the held-back boot |
| vendor lag | the advisory that names the fixed version, per family: Ubuntu USN, Debian/Alpine/RHEL through OSV per release, Arch's AVG tracker, Fedora's Bodhi, SUSE's OVAL |
| container images | tag → digest against the registry, anonymously |
| integrity | package checksums, `/etc/ld.so.preload`, listening sockets against a recorded baseline |
| language stack | npm, pip (global *and* every virtualenv), PHP, Ruby, Rust, .NET, Maven, Go, Dart, plus jars on disk and lockfile pins, against OSV |
| SBOM | CycloneDX export of what was read |
| the commands | the plan, per device, with risk, downtime, how to verify and how to undo |

The pane has **one control**: `scan all · <device>`. It reads one device at a time, in the order the page
draws its sections — packages → integrity → libs & runtimes — and every device keeps its own last
reading. Nothing in the pane changes a machine; it hands over commands. `cve_apply` exists as a tool for
an agent explicitly asked to patch (typed host name, dry run by default, `sudo -n`).

## Constraints that are load-bearing

1. **`hermes plugins validate .` and `hermes plugins doctor . --ci` must stay green** — the latter blocks
   sockets during registration, so nothing may touch the network at import time.
2. **Stdlib only.** No declared Python dependencies; network calls happen at call time, never at import.
3. **Project isolation** (root AGENTS.md, 8 dimensions): this folder only, its own `.venv` and `.env`,
   its own git repo; services loopback-only.
4. **Security tier: High (Tier 2)** — see `SECURITY.md`. It reads privileged state and can change a system
   through `cve_apply`, so those rules are load-bearing.
5. **No credential path.** Anonymous registry and advisory reads; remote hosts use the operator's own SSH
   agent. The plugin stores, reads and forwards no secret.

## Provenance

The logic core was ported from a standing routine in `~/hermes-admin/scripts/` (`cve-watch.py` and its
23-assertion selftest), and the verdict functions in `patch_sentinel/verdict.py` are a differential port
of it — the same inputs give the same answers, checked in `tests/`.

## Out of scope, deliberately

Applying patches unattended; macOS and Windows (the plugin answers `unsupported` with the OS name); CVE
scanning inside image layers (needs an image scanner — reported as a stated gap, never as clean);
SCAP/OVAL compliance scanning; any SaaS backend or telemetry.

## Where the state lives

- `README.md` — what it does and how to run it.
- `docs/coverage.md` — the verified matrix: which distro, which surface, what was actually run.
- `docs/design.md` — the decisions, including the ones that were reversed.
- `docs/verify.md` — the commands that reproduce every claim.
- `worklog.md` · `decisions.md` — the running record.
