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

## The four tools

| tool | input | what it measures |
|---|---|---|
| `cve_scan` | `host?` | running vs installed vs installable kernel, every `Inst` line from `apt-get -s dist-upgrade`, which recent Ubuntu notice names those exact versions, every running image's tag vs its registry digest |
| `cve_plan` | `host` | the ranked, reversible plan for what `cve_scan` found. Never executes |
| `cve_explain` | `cve_id` | the vendor record for one CVE, plus our measured state and any tracker/measurement disagreement |
| `cve_coverage` | — | what answered and when, and the standing gaps. Never empty, never green |

## Coverage — what is proven, and on which machine

The adapter is chosen from the host's own `/etc/os-release`; every claim below was read off a real
machine, not written from documentation.

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

A toolchain that is not installed reports **`missing`**, never "zero findings". Project-local
dependency files (`package-lock.json`, `composer.json`, `Cargo.toml`, `go.mod`, `*.csproj`) are
**not** read, and that is stated in `cve_coverage` on every run.

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

## "There is a CVE but Ubuntu has not shipped the fix yet"

A host can be *correctly* reported as `0 pending` while a known CVE is still open — because the
archive has nothing to install. Folding that into "nothing to do" is the false comfort this plugin
exists to remove, so it is now its own state, **vendor lag**:

> 3 fix(es) exist upstream but not in this archive yet
> `openssl 3.0.13-1ubuntu0.3 → 3.0.13-1ubuntu0.4 (USN-9001-1)`

The comparison uses Ubuntu's notice feed (which names a fixed version per release) against the host's
own `dpkg` and `apt-cache policy`: installed ≥ advisory's fix → already fixed; candidate ≥ fix → it is
in the pending list; candidate < fix → **vendor lag**. Version ordering is dpkg's own, ported and
checked against `dpkg --compare-versions` over 900 version pairs (0 mismatches) — a comparator that is
wrong either way would manufacture a lag or hide one.

Where an advisory carries a Workarounds section, the finding also shows the vendor's own temporary
mitigation — quoted, never invented.

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
