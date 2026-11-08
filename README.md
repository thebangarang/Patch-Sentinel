# Patch Sentinel — a Hermes plugin that keeps a machine honest about its patches

> Status: **hackathon entry** (Hermes Agent Plugin Hackathon, submissions due 11 Nov 2026, 17:00 EST).
> Repo: https://github.com/thebangarang/Patch-Sentinel · MIT. Every number in this file comes from a
> run on this repository at the commit named in the catalogue entry.

Patch Sentinel answers one question with evidence: **what is published as a fix that this machine — or
a machine we manage — is not running?** It reads what the vendor published, compares it with what is
installed *and running*, and returns a patch plan: the exact commands, the downtime each costs, and a
refusal when it cannot know.

It does not guess. A check that could not look says so. A kernel that is installed but not booted is
its own verdict, not "patched". A registry that answered `429` is *unverified*, never *current*.

## What you can ask it

| you type | you get |
|---|---|
| "are we patched?" | per host: installable updates with the advisory id that names them, kernel currency (running vs installed vs installable), container images rebuilt upstream — each with the measurement time and an `exit_code` |
| "what about CVE-2026-98432?" | the vendor record for that CVE: the notices that name it, the versions it fixes, whether that fix is installable or already running here, and — where the tracker's status word disagrees with the measurement — which one the verdict follows |
| "how do we close these?" | a numbered patch plan per host: command, risk, downtime, why, how to verify, how to reverse. Nothing is executed |
| "what are you NOT checking?" | the coverage gaps, named: CVEs inside image layers, language dependencies, hosts it cannot reach, hosts that are not Ubuntu |
| "do it" + the host name typed | `cve_apply` runs the plan: stage → apply → re-measure → receipt. Dry run by default; a real apply needs the host name typed by you *and* `dry_run=false` |

## Why it can be trusted

- **The distro's own feeds are the source of truth** — the Ubuntu security notices, the archive as apt
  reports it, and the registry's own digests. The CVE tracker page is read as *context only*: it read
  "pending" for a kernel version that was already installed and running on this machine (reproduced
  live on 2026-11-06, and pinned as a test with the real payload in `tests/fixtures/`).
- **A patch counts only when it is running** — `uname -r`, not "the package is installed".
- **Three outcomes per check**: clean, finding, and *could not look*. The third is in the payload, in
  the `blind` list, and makes `exit_code` 2.
- **Refusals are payloads** — `{"match": "none", "answer": null, "reason": …, "nearest": […]}` — so the
  model relays a refusal instead of substituting a plausible sentence.
- **`full-upgrade`, never `upgrade`**: a new kernel arrives as a new *package*, which `upgrade` keeps
  back. That is design rule 4, and it has its own test.

## The tools

| tool | input | what it measures |
|---|---|---|
| `cve_scan` | `host?` | running vs installed vs installable kernel, every `Inst` line from `apt-get -s dist-upgrade`, which recent Ubuntu notice names those exact versions, every running image's tag vs its registry digest |
| `cve_plan` | `host` | the ranked, reversible plan for what `cve_scan` found. Never executes |
| `cve_explain` | `cve_id` | the vendor record for one CVE, plus our measured state and any tracker/measurement disagreement |
| `cve_coverage` | — | what answered and when, and the standing gaps. Never empty, never green |
| `cve_image` | `image`, `host?` | what is inside one container image — distro, packages read from its layers, CVEs with fixing versions. Never starts the image |
| `cve_libraries` | `host?`, `project?` | every language package installed machine-wide, every project virtualenv, jars on disk, or one project's lockfiles — asked against OSV. Lockfile ranges are counted as unverifiable, never as findings |
| `cve_integrity` | `host?`, `action?` | package checksums, the `/etc/ld.so.preload` hook, and listening sockets against the recorded baseline. Says clean / finding / could-not-look — never "not compromised" |
| `cve_ack` | `package`, `advisory`, `reason` | records one advisory as accepted, with a reason and an expiry (90 days). `action: release` reopens it |
| `cve_apply` | `host`, `confirm`, `dry_run` | runs the plan behind a typed-confirmation gate; refuses without a passwordless sudo as a handover of the same commands |

## Coverage — what is proven, and on which machine

The adapter is chosen from the host's own `/etc/os-release`; every claim below was read off a real
machine, not written from documentation.

### Every distro was tested the same way

`scripts/portability_probe.py` is copied to a freshly booted machine, imports the plugin with that
machine's own python, and runs every user-facing tool: scan, machine-wide libraries, a project with
eight kinds of lockfile, a virtualenv, two integrity readings, plan, coverage, SBOM, image and a
dry-run apply. No venv, no Hermes, no configuration beyond one host line.

| machine | how it was run | what came back |
|---|---|---|
| **Ubuntu 26.04** (this one) | the plugin as shipped, inside Hermes | the whole pane; scan, libraries, integrity, plan, apply handover — the reference build |
| **Debian 12 bookworm** (fresh VM, python 3.11) | clone + `python3`, nothing installed | `apt`: 0 pending, 3 vendor-lag rows, release supported · libraries: 40 distro packages (118 advisories, counted apart) + a 2-package venv (38 findings, all real) · 8/8 lockfile kinds read · integrity **ok** (4 unreadable, 1 volatile path excluded) · SBOM 42 components · image: "no container runtime", exit 2 · apply: "nothing to apply" |
| **Fedora 45** (fresh VM, python 3.15) | same | `dnf`: **109 pending**, `kernel-update-available`, Bodhi measured, 0 lag · libraries: 30 packages · integrity **ok** (24 conffiles, 370 files it could not verify) · plan: 3 steps · apply dry run: nothing executed · image: no container runtime |
| **Arch** (fresh VM, python 3.14) | same | `pacman`: 0 pending, kernel current · integrity **ok** via `pacman -Qkk` (0 changed, 13 conffiles, 12 unreadable) · libraries: distro packages tagged, venv found · apply: refused, Arch has no apply plan |
| **openSUSE Leap 15.6** | command-level only | the `zypper`/`rpm` probe and parsers run against the real host; **the plugin itself cannot run on Leap's system python 3.6** (it needs the interpreter Hermes ships, 3.10+), so this family is not verified end to end |

### Case scenarios: the situations a user lands in, not the ones we designed for

`scripts/scenario_batch.py` builds a small world for each one — an empty home, a broken state file,
a dead network, a lockfile set with four languages in it — and checks every answer against invariants
that must hold for *any* answer the plugin gives: a JSON object with a `tool` and an `exit_code` in
{0 nothing to do, 1 something to patch, 2 could not look}, counts that agree with the lists they count,
no placeholder or invented command, no verdict that claims a clean it did not measure, and two
identical runs on an unchanged machine.

Eighteen scenarios, **152 assertions, 0 findings** as of the last run. What it caught, in the order it
caught them: a read-only data directory crashing the integrity read instead of reporting the reading and
saying it could not be kept; three refusal paths returning no `exit_code` at all and a `null` answer; an
internal exception answering as "the tool failed internally" without naming the tool; an `integrity.json`
that parses to a list crashing the writer; a vendor's "Workarounds: None." being surfaced as a mitigation
worth trying; and a `read_at` in the future rendered as an age.

### What is *not* verified, and says so in the pane

| surface | state |
|---|---|
| **Alpine** | the `apk` adapter is written and unregistered: Alpine's cloud image never created an account, so no live host has been read. An Alpine host answers `unsupported`, not "patched" |
| **RHEL / Rocky / Alma** | `dnf` is proven on Fedora; the RHEL family shares it, but no RHEL host exists in this lab |
| **macOS / Windows** | not measured. The probe is a POSIX shell block; Windows needs a PowerShell transport before it is a claim |
| **rpm-based container images** | `cve_image` reads dpkg and apk images; an rpm image says `unmeasured` rather than clean |
| **APPLY without passwordless sudo** | refused, with the commands handed over — by design, never a password |
| **Kubernetes / Helm** | not read at all; no manifest parser |

### Language runtimes

`cve_libraries` lists what each toolchain reports as installed **machine-wide**, then asks OSV (the
same database osv.dev serves) for advisories naming those exact versions:

| ecosystem | read from | status |
|---|---|---|
| npm | `npm ls -g --json` | proven (real machine) |
| PyPI | `pip list`, `pipx list --short`, `uv tool list` | proven (real machine + container) |
| Pub (Dart) | `dart pub global list` | proven (container capture) |
| Packagist | `composer global show --format=json` | proven (container capture) |
| RubyGems | `gem list --local` | proven (container capture) |
| crates.io | `cargo install --list` | proven (container capture, rust:1-slim) |
| NuGet | `dotnet tool list -g` | proven (container capture, dotnet SDK 8) |
| Maven | every `*.pom` under `~/.m2/repository` | proven (container capture, 227 artifacts) |
| Go | `go version -m` on each binary in `GOPATH/bin` | proven (container capture, golang:alpine) |

A toolchain that is not installed reports **`missing`**, never "zero findings".

Project lockfiles *are* read (local only — a project path is a path on this machine): `package-lock.json`
(v1/v2/v3), `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `constraints.txt`, `poetry.lock`,
`Pipfile.lock`, `go.sum`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`, `pubspec.lock`. Exact
versions only: a `>=` range is counted as unverifiable, never turned into a finding.

Where an advisory carries one, the finding also shows the **vendor's own workaround** — the temporary
mitigation (disable a feature, validate input, set a flag) you can apply while the patched version is
not installed yet. It is quoted from the advisory, never invented.

| family | covers | proven on |
|---|---|---|
| `apt` | Ubuntu, Debian, Mint, Pop, Proxmox, Kali… | this machine (Ubuntu 26.04) and a Debian 12 VM |
| `dnf` | Fedora, RHEL, Rocky, Alma, CentOS, Amazon | a Fedora 45 VM (and a `fedora:latest` container) |
| `pacman` | Arch, Manjaro, EndeavourOS, CachyOS | an Arch VM |
| `zypper` | openSUSE Leap/Tumbleweed, SLES | an openSUSE Leap 15.6 VM |

An OS with no adapter answers **`unsupported` with its own id** and lands in GAPS as a red gap — a
Mac, a Windows box or an Alpine host never reads as "patched". Alpine is the honest example: the
`apk` adapter is written, but its cloud images would not take a cloud-init seed, so it has never
read a real Alpine host and is **not registered**. Windows needs a different transport (PowerShell,
not a shell block) before it is a real claim.

`docs/lab.md` has the lab recipe and every number above.

## Your packages, and the agent's own

A plugin that runs inside an agent reads that agent's environment too, and Hermes ships ~130 Python dependencies of its own. Reporting them as *your* findings is noise at best: the pane told its first
user to `pip install -U` three packages that live in the agent's venv, which has no pip at all.

So every package now carries an owner, read from where its files actually are
(`importlib.metadata`, one call, not a guess from a name):

* **your packages** — counted, listed and given a runnable fix command;
* **`hermes`'s own environment** — separated into their own block, with the sentence that matters:
  *these ship with the agent and are upgraded with `hermes update`, not one by one.* The check reads
  that environment by path, so the answer no longer depends on which `python3` happens to be on the
  inherited `PATH`.

## "There is a CVE but Ubuntu has not shipped the fix yet"

A host can be *correctly* reported as `0 pending` while a known CVE is still open — because the
archive has nothing to install. Folding that into "nothing to do" is the false comfort this plugin
exists to remove, so it is now its own state, **vendor lag**:

> 3 fix(es) exist upstream but not in this archive yet
> `openssl 3.0.13-1ubuntu0.3 → 3.0.13-1ubuntu0.4 (USN-9001-1)`

The comparison needs a feed that names a fixed version **per release**, and every family this plugin
ships now has one:

| family | feed |
|---|---|
| Ubuntu | its own security notices |
| Debian, Alpine, Rocky/Alma/RHEL | OSV, per release (`Debian:12`, `Alpine:v3.22`, `Rocky Linux:9`…) |
| Arch | `security.archlinux.org` |
| **Fedora** | **Bodhi** — the stable security updates for the host's release, indexed per package |
| **openSUSE / SLES** | **SUSE's OVAL** — one document per product, already joining CVE → package → fix |

Installed ≥ fix → already fixed; the archive's candidate ≥ fix → it is in the pending list; candidate
< fix → **vendor lag**. Both new feeds are cached (6 h / 12 h) because they cost real time: a Bodhi page
takes about ten seconds and the OVAL document is 12 MB compressed.

Each feed's **own date** travels with the answer. openSUSE Leap 15.6's OVAL last moved on 2026-06-25,
because the release left support: the row quotes it, anything older than 30 days is flagged, and the
pane says plainly that a stale feed is not a vendor delay.

Version ordering is dpkg's own, ported and checked against `dpkg --compare-versions` over 900 pairs
(0 mismatches). Two guards matter more than the comparison itself: the distro feeds name **source**
packages (`openssl`, not `libssl3`), so binaries are mapped to their source and back; and every lag
row carries the age of the archive index, because a host that has not refreshed its metadata sees its
own staleness as a vendor delay.

Where an advisory carries a Workarounds section, the finding also shows the vendor's own temporary
mitigation — quoted, never invented.

## "Is this still what we installed?" — the integrity section

A patch scanner reads versions. An intrusion does not change a version: it replaces a binary, preloads
a library, or opens a port. `cve_integrity` reads three surfaces, on demand (it takes about a minute on
a full package database, so a scan never runs it — the pane shows the last reading and its age):

| reading | a finding means |
|---|---|
| **package checksums** — `dpkg -V`, `rpm -Va`, `apk audit` | a package-managed file no longer matches the checksum of the package that owns it, or is gone. Files marked `c` are **conffiles**, which are meant to be edited: they are counted apart and never called tampering. `?????????` means dpkg *could not read* the file — it is reported as unreadable, never as modified. |
| **preload hook** — `/etc/ld.so.preload` | the file is not empty. Almost nothing legitimate uses it, and it is what an injected library needs. |
| **listening sockets** — `ss`/`netstat` | a socket that is not in the baseline this plugin recorded. The first reading records the baseline and says so; `re-baseline the sockets` accepts the current set after a deliberate change. |

Two refusals keep it honest. A non-root reading cannot see every file, so the payload names how many
it could not read and says the check is not conclusive without root. And the section **never says "not
compromised"**: the strongest sentence it prints is *no evidence of tampering in the surfaces read*, and
`what this cannot see` states the rest — a rootkit that hides from `ss`/`dpkg`, a fileless attack, a
kernel compromise, and an intrusion that restored the checksums afterwards are all invisible here. Real
compromise detection is an EDR (Wazuh, auditd rules, Falco) with somewhere to send its alerts.

## "There is a fix for nobody" — and how to live with it

Some advisories have no fixed version at all. `diskcache 5.6.3` carries two, and no release closes
them. A list that keeps reprinting that is a list people stop reading, so the pane does two things:

* **collapses them**: the default view is what can be done. Findings with no published fix sit behind
  one line — `show 1 package(s) / 2 advisory(ies) with no published fix` — and the header still counts
  them, so nothing is hidden from the count.
* **lets you record a decision**: `acknowledge` asks for a reason, then stores `{host, package,
  version, advisory, reason, until}` in `~/.hermes/patch-sentinel/acks.json` (mode 0600). The record
  names **one advisory id**, not a package — a new advisory against the same version reappears at once
  — and it **expires** (90 days by default, 365 at most). Acknowledged rows stay in the payload with
  their reason and their end date, they are listed under `show N acknowledged`, and `reopen` puts one
  back. Nothing is ever deleted, and no acknowledgement can cover something that has a fix.

The same record is a tool, so the agent can write one: `cve_ack` with `package`, `advisory`, `reason`,
optional `days`, and `action: release` to reopen.

## Where the answers come from

Every claim the plugin makes is traceable to one of these feeds. Nothing is inferred from memory, and a
feed that cannot be read is reported as **unmeasured**, never as clean.

| feed | what it answers | used for | limit |
|---|---|---|---|
| Ubuntu security notices (`ubuntu.com/security/notices.json`) | the fixed version per Ubuntu release | vendor lag on Ubuntu | Ubuntu only |
| OSV, per release (`Debian:12`, `Alpine:v3.22`, `Rocky Linux:9`…) | the fixed version per distro release | vendor lag on Debian, Alpine, RHEL family | Fedora and openSUSE have no OSV ecosystem |
| Arch security tracker (`security.archlinux.org/all.json`) | affected/fixed per AVG, with resolved ones marked | vendor lag on Arch | Arch only |
| OSV advisories (`api.osv.dev`, batched) | which published advisories name an installed version | npm, PyPI, Packagist, RubyGems, Maven, Go, crates.io, NuGet, Pub | machine-wide stores by default; a project is read on request |
| Every virtualenv on the machine (`*.dist-info` names under project `.venv`/`venv`, pipx and poetry environments) | what the projects on this box actually have installed | `cve_libraries` (machine scope) | read by name and version only — nothing is imported or executed; a package pinned in three projects is one finding that names its three environments |
| A repository's lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `go.sum`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`, `pubspec.lock`) | what a project actually pins | `cve_libraries --project <dir>`, or the field in the pane | only exact versions count; a `>=` range is reported as unverifiable, never guessed |
| **CISA KEV** (`known_exploited_vulnerabilities.json`) | is this *being exploited right now* | an `exploited in the wild` flag on any finding, plus the vendor's required action | US catalogue; absence is not proof of safety |
| **FIRST EPSS** (`api.first.org`) | probability of exploitation in 30 days | ranked urgency beside the severity | a forecast, not a fact |
| Docker registry (manifest digests) | does the running image still match its tag | container images | needs registry access; no image scanning |
| The distro's own tools (`apt`, `dnf`, `pacman`, `zypper`, `apk`) | what the archive would install | the pending list and the plan | a stale archive index is called out, never trusted |

Not wired, and named as gaps in the pane: Fedora's Bodhi updates, SUSE's CSAF/VEX documents, and any
form of image scanning (Trivy-class) — the plugin does not pretend to see inside a container.

## One device at a time, one button, one command block

The pane answers two questions about **the device you picked**: **what has to be done**, and **with
what**. Every section below the servers list belongs to that one device.

1. **scan all · <device>** — the only control, and it measures that device completely: packages,
   kernel, images, advisories, the language stack and the integrity reading **at the same time**, then
   the commands the measurement implies. Because the three surfaces run together, the wait is the
   slowest one rather than the sum — ~30 s on this machine, ~30-60 s over ssh, instead of the two and
   a half minutes a fleet-wide run took. Press it once per device; each device keeps its own last
   reading, and switching devices never re-scans.
2. **servers** — the list carries a per-device badge (`nothing to do`, `2 to do`, `not measured`) and
   the age of its last reading, so the fleet stays legible without merging five machines into one
   screen. Clicking a name is what selects the device; there is no dropdown.
3. **what must be done** — that device's rows: pending packages, a kernel that is not running, library
   findings that name a fix, sockets that appeared, files this account cannot read, and a
   `cannot see: …` line for any surface that refused. It says `nothing to do` only when the device was
   measured and nothing is pending — "never measured" is a different sentence.
4. **the fix, as commands** — every command the rows above imply, numbered:
   the package steps (with risk, downtime, verify and reverse), the language-store upgrades that have
   a published fix, and the root verification for files the pane cannot read. *COPY ALL* gives the
   whole set; each row copies on its own. A finding with no published fix never becomes a command.
5. **system packages · integrity · libs & runtimes** — always on screen, for the same device. Each keeps its
   empty state — `nothing available — this host is up to date, as measured`, `not read yet`, `0
   package(s) read` — because a section that vanishes when it has nothing to say reads as a broken
   pane, and "nothing found" is a result worth showing.
6. **gaps** — what the run could not see, and why.

A packaged file that no longer matches — or is gone — names the **package that owns it** and the
command that puts it back (`sudo apt-get install --reinstall apparmor` on dpkg, `dnf reinstall`,
`apk fix`, `pacman -S` elsewhere). The owner is resolved on the host, not guessed; a path no package
claims gets a comment saying so instead of an invented command. Reinstalling is not a package
upgrade, so it is a command in this section rather than a step APPLY runs.

**The pane offers no APPLY control.** It used to: a collapsed "run it from here instead" row. It was
removed because it only ran where the account Hermes runs as can patch without a prompt — never the
machine Hermes runs on — so on the host in front of you it could only refuse. A control that exists to
say no is friction, and every device is patchable from its own terminal with the commands above. The
gated tool (`cve_apply`, typed host name, dry run by default, `sudo -n` only) stays for an agent that
is explicitly asked to patch; the pane does not call it.

The system-package list copies commands, not a list of versions — a package list is a reference, and
the copy control exists to paste something a shell can run.

Packages that ship inside Hermes's own environment are measured and then dropped from the view: they
are upgraded by `hermes update`, so a count of them is a lever you cannot pull. One line appears only
if one of those advisories is being exploited (CISA KEV) — that is a fact about the machine whatever
the fix path is. The same rule drops any component at version `0.0.0`: an in-tree install has no
published version to compare, and matching one against advisory ranges invented twenty CVEs on
`hermes-agent 0.0.0`.

## When APPLY refuses

APPLY runs as the account Hermes runs as, with `sudo -n` — an agent tool call cannot answer a password
prompt. When that account cannot patch unattended the gate refuses and hands you the commands, with
the ssh line and the check to run afterwards. The full walkthrough, local and remote, is in
**[docs/apply-by-hand.md](docs/apply-by-hand.md)** — including the one rule the plugin will not break:
it never asks for, holds or forwards a password.

## Why a scan does not answer instantly

A scan of two servers takes 40-60 seconds: an ssh round trip, `dpkg` for every package an advisory
names, `apt-cache` for the ones actually installed, and a distro upgrade check on each. The desktop
bridge cuts a renderer call at 30 seconds, so a synchronous route reported *"timed out connecting to
Hermes backend"* while the work was still finishing — and a synchronous **apply** would have reported
a failure while the machine was being patched, which is the one message that invites a second one.

Both run as jobs: `POST /rescan` and `POST /apply` answer immediately, `GET /rescan` returns the
bundle the pane renders (and the stage it is on), and the pane follows it. There is **one** refresh
control, at the top — the three per-panel "rescan" buttons did the same work and made the pane look
like three different actions. The individual tools (`cve_scan`, `cve_libraries`, `cve_integrity`)
remain for an agent asking about one surface; `cve_rescan` is the one that answers for all of them.

## Adding the machines this pane answers for

The inventory is editable from the pane (`hosts` → **add a host**): label, then the ssh target —
`user@host:port`, an `ssh` alias from `~/.ssh/config`, or `local` for this machine.

Two rules are enforced by the backend, not the UI:

* **A host is only added after a probe of it succeeded.** The probe is the real scan, so adding a row
  means something reached that machine and read its package manager. A list that can grow on a typo is
  a list that lies.
* **Addresses only, never a credential.** The key stays in your ssh agent; the plugin never reads,
  stores or forwards one. A target is validated against what can legitimately sit in an ssh argv, so
  it cannot smuggle a second command.

Removing a host needs its label typed exactly (it throws away that host's history), and the machine
the plugin runs on cannot be removed at all. A pane edit is written to the plugin's own settings and
wins over `config.yaml` on the next restart, instead of being silently undone.

## Patching a remote server, from here

The inventory is just `label=target` pairs, and the target is anything `ssh` understands — so a VPS is
one entry, not a second product:

```bash
hermes config set plugins.entries.patch-sentinel.settings.hosts \
  'beelink=local,webasix=webasix'          # or vps=deploy@203.0.113.10:2222
```

`webasix` is an `~/.ssh/config` alias; a `user@host:port` works the same way. The probe is a single
round trip over `ssh -o BatchMode=yes`, so it never prompts for a password: the key must already work
non-interactively. Scanning, planning and the gated apply then behave exactly as they do locally —
`cve_apply` still needs the host label typed, still stages first, still re-measures and writes a
receipt. **Applying to a production server is a real change**: read the plan and its reversal line
first, and apply one host at a time.

## Check that it works

```bash
python3 scripts/selfcheck.py                    # every surface, one table, exit 2 if one was blind
python3 scripts/selfcheck.py --host fedora-lab  # a declared host, plus its plan
```

`docs/verify.md` has the recipes: a throwaway venv holding a deliberately vulnerable Jinja2 (the
language check returns 38 advisories across 2 packages), a fresh VM for the update proposal (109
pending → three ordered steps with their reversals), and the refusal (an unreachable host exits 2).

The pane's palette is also a skin: `docs/theme/patch-sentinel.yaml` → copy it to
`~/.hermes/skins/`, then pick **patch-sentinel** in Settings → Appearance.

## Requirements

* the Python interpreter Hermes runs on (3.10+) — the plugin itself is **stdlib only**, no
  dependencies, no `pip install`;
* a POSIX shell on every host it reads (macOS and Windows are not measured);
* `sudo` without a password prompt only if you want APPLY; without it the plugin hands the commands
  over instead of asking for a password.

## Install and try it

```bash
hermes plugins install thebangarang/Patch-Sentinel --enable   # after the catalogue entry lands
hermes chat -q "are we patched?"
```

During development, symlink the checkout into `~/.hermes/plugins/patch-sentinel` and enable it — the
plugin is loaded from the checkout, so edits are live after a plugin reload.

Remote hosts are opt-in, configured as `label=ssh-target` (e.g. `beelink=local,vps=webasix`) in the
plugin settings. The plugin stores no credential for them: it uses your own SSH agent, with
`BatchMode=yes`, so an unkeyed host fails immediately instead of hanging a scan.

## Honest limits (v0.1.0)

- **Applying exists, and it is deliberately awkward.** `cve_apply` refuses unless (a) you type the
  host name, (b) the host's own package manager has commands this version knows, (c) the user can run
  `sudo` without a prompt on that host, and (d) `dry_run=false`. The default is a dry run. It stages,
  applies, re-measures the host, and writes a receipt with the versions before and after. What it
  does **not** do: schedule itself, retry, roll back automatically (each step carries its documented
  reversal instead), or reboot for you — after a kernel update it says `reboot_required: true` and
  stops there.
- **OS packages + kernel + container image digests.** Not CVEs *inside* image layers (that needs an
  image scanner), not language dependencies in your own code (that needs an SBOM + a dependency
  scanner). Both are stated in every `cve_coverage` answer, at the moment they matter.
- **Ubuntu only, for advisories.** Package facts are read on any dpkg host; advisory attribution is
  Ubuntu's feed, and a non-Ubuntu host is a named gap.
- **Anonymous registry reads.** No token is read, stored or passed to a subprocess; a registry that
  rate-limits you is reported as `unknown` with its reason. If you need more than the anonymous
  limit, `docker login` on the host yourself — the plugin never holds that credential.
- **Container images are compared by digest only.** A rebuilt image is "an update exists", never
  "these CVEs are fixed" (decision D5).
- **No in-image scanning, no SCAP/OVAL, no Windows/macOS hosts, no fleet management.**

## Disclosure (what it touches)

- **Network**: HTTPS reads from `ubuntu.com/security/notices.json` (advisory feed) and
  `ubuntu.com/security/cves/<CVE>.json` (tracker context), plus the container registry's manifest API
  via `docker buildx imagetools`. No telemetry, no analytics, no third-party service.
- **Subprocesses**: `uname`, `dpkg-query`, `apt-cache`, `apt-get -s dist-upgrade` (simulation only),
  `docker ps` / `docker image inspect` / `docker buildx imagetools inspect`, and `ssh <host>` for
  remote hosts. All read-only. The string `apt-get -y full-upgrade` appears in `cve_plan`'s output as
  text for a human to run; the plugin never executes it.
- **Reads outside its own data**: the host's package and container state through those commands.
  Nothing else — no `.env`, no `auth.json`, no browser or keychain data.
- **Stored credentials**: none.
- **Files written**: `last_scan.json` (mode 600) and, for a future apply, `receipts.jsonl`, both in
  `$HERMES_HOME/patch-sentinel` (or the configured `data_dir`).
- **Background work**: none in-process. A daily scan is a Hermes cron job the user installs.

## Provenance

Built from a real incident: a Linux kernel use-after-free (CVE-2026-98432) tracked by hand for nine
days on two hosts — interim firefighting controls, a hand-built watcher, and the discovery that
Ubuntu's CVE page lagged the archive by a week. The watcher still runs daily on this machine; the pure
decision functions in `patch_sentinel/verdict.py` are a port of it, and the 23 assertions in
`tests/test_verdict.py` are the same assertions it runs on itself.
