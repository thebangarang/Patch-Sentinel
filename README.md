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
| "do it" | **refused in 0.1.0.** Applying is not built; the plan is the deliverable (see *Honest limits*) |

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

- **Nothing is applied.** `cve_plan` produces commands; there is no apply tool, no typed-confirmation
  gate wired to a real change, and no receipt of an applied action. The typed gate and the receipt
  format exist in `docs/design.md` and `store.py`; the code path does not. Saying "it patches for you"
  would be false.
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
