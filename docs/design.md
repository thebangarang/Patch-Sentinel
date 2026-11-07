# Patch Sentinel — design

## Shape

```
plugin.yaml                 manifest: name, version, provides_tools
__init__.py                 register(ctx) — tools only; no imports that touch the network
patch_sentinel/
  sources/                  one module per allowlisted source, each returning a typed result
    usn.py                  Ubuntu USN feed (nov 2026: limit ≤ 20, 25+ = HTTP 422)
    apt_sim.py              parse `apt-get -s dist-upgrade` (unprivileged, no lock)
    registry.py             container image digests via `docker buildx imagetools`
    kernel.py               running vs newest installed vs installable
  verdict.py                pure: verdict_kernel(), image_state(), explain(), three outcomes
  plan.py                   pure: findings → ranked patch plan + downtime estimate
  hosts.py                  host inventory (local + ssh targets from config)
  store.py                  SQLite: scans, findings, receipts, notify state
  tools.py                  the four handlers, each JSON out, never raising
dashboard/
  manifest.json             {"name": "patch-sentinel", "api": "plugin_api.py"}
  plugin_api.py             FastAPI router: /status /plan /coverage /apply (gated)
desktop/plugin.js           the pane (opt-in): now / pending / gaps
skills/patch_sentinel/SKILL.md  teaches the agent the workflow and the refusal vocabulary
tests/                      stdlib unittest; fixtures from the real runs
```

Rules from `references/plugin-authoring.md` that bind this layout: handler signature
`(args, **kwargs) -> str` returning JSON; a try/except per tool; data files loaded relative to
`Path(__file__)`; the subpackage imported from `plugin_api.py` with
`importlib.util.spec_from_file_location` (never `sys.path`); no `eval`, no dynamic `import()`.

## Sources: an allowlist, not a crawl

| source | used for | why it and not another |
|---|---|---|
| **Ubuntu USN API** (`/security/notices.json?release=<codename>`) | advisory id + fixed version per package | the distribution's own statement of what it fixed; the thing a `-security`/`-updates` pocket actually serves |
| **The apt simulation** (`apt-get -s dist-upgrade`) | what is installable *here, now* | unprivileged, no lock contention, and it answers for `-updates` too — see rule 3 |
| **The archive itself** (candidate versions) | "is the fix published at all" | the USN can lag; the archive is where the fix lands first |
| **Ubuntu CVE tracker page** | per-CVE narrative, "work in progress in X" | context only — **never** the sole input to a verdict (rule 2) |
| **NVD / cve.org API** | metadata for a CVE the vendor sources already named | enrichment; not a discovery feed (noisy, delayed, and not distro-aware) |
| **Container registry digests** (`buildx imagetools`) | has this tag been rebuilt upstream? | a fact, not a guess; `manifest inspect -v` is the wrong instrument (rule 5) |

Explicitly excluded: scraped "CVE feeds", vendor blogs, model-generated CVE lists. A source enters
this table only with a test that proves its parsing and its failure mode.

## The rules — each one is a measured incident, not a preference

1. **A patch counts only when it is running.** `uname -r` vs installed vs installable is three states.
   *Incident:* the beelink had 7.0.0-43 installed and 42 running for a day; "installed" would have
   reported it patched.
2. **Never let a lagging page produce a verdict.** The archive and the USN are read alongside the CVE
   tracker, and the archive wins. *Incident:* Ubuntu's page said "work in progress" while the fixed
   kernel was published and installable for a week.
3. **Do not filter to `-security`.** A security fix may ship through `-updates`. *Incident:* the
   7.0.0-43 kernel that closed CVE-2026-98432 came through `resolute-updates`.
4. **`apt-get upgrade` is not a patch.** A new kernel arrives as a new *package*, which `upgrade`
   keeps back. Plans say `full-upgrade` (or name the package). *Incident:* the VPS reported "0 package
   upgrades pending" while the kernel fix was available.
5. **A refused source is `unknown`, never `current`.** *Incident:* Docker Hub `429` produced an empty
   digest, the first version of the routine read it as "nothing to do", minutes after it had reported
   four rebuilt images. Classification happens where the error is produced, into short codes
   (`rate-limited` / `no-such-image` / `other`), because truncating the message loses the token.
6. **The right instrument, proven on a known-good case first.** `docker manifest inspect -v`'s first
   digest never equals the image's own RepoDigest; `buildx imagetools` matches exactly. Any new source
   ships with a "known-good reads as clean" fixture before it is trusted.
7. **Every check has three outcomes** — clean, finding, could-not-look. The third is surfaced in the
   pane and in the tool payload, and makes the run's exit code non-zero.
8. **Report the measurement with its timestamp**, and never a count that can go stale without its
   source and moment.

## Tools (agent-facing)

| tool | input | output |
|---|---|---|
| `cve_scan` | `host?` | `{hosts: {<label>: {kernel: {running, installed, verdict}, pending: [...], images: [...], outcomes: {...}}}, blind: [...]}` |
| `cve_plan` | `host` | `{steps: [{action, command, risk, downtime, why}], refusals: []}` — never executes |
| `cve_explain` | `cve_id` | `{id, source, published, fixed_versions, our_state}` or the refusal shape |
| `cve_coverage` | — | `{covered: [...], gaps: [...], hosts_unreachable: [...]}` |

Refusal shape (required by the authoring rules so the model cannot invent an answer):
`{"match": "none", "answer": null, "reason": "...", "nearest": [...]}`.

Titles and bodies for alerts are built from the failing check's own label and reason — a generic
"The system is unhealthy" is a defect (see `scheduled-job-reliability` in the skills tree).

## Apply gate

`cve_plan` proposes. Applying is a separate call that requires `confirm: "<host label>"` typed by the
operator, records a receipt (`data/receipts.jsonl`), and supports `dry_run: true`. Order for real
application: stage first (download/pull, no restart), then apply, then verify by effect (service
answers / `uname -r`), then record. Reversal is documented per action — an apt action's reversal is
the dated pre-change state capture, an image's is the previous image id.

### What is an alert, and what is only measured

Three rules decide what earns the operator's attention, and each was a complaint from a real session:

* **An agent-owned package is never a finding.** The packages inside Hermes's own environment are
  read, annotated, and reported — but the only lever is `hermes update`, so counting them against the
  machine published 40 advisories that no per-package action could clear. They are one quiet footnote,
  shown only when an advisory exists.
* **A version nobody published is not comparable.** An editable install reports `0.0.0`; matching it
  against advisory ranges invented 20 CVEs on `hermes-agent 0.0.0` — half of the "40 advisories".
  Those components are skipped *by name*, in the answer line.
* **A copy control copies something a shell can run.** The package list's copy button handed over
  `openssl 3.0.1 → 3.0.2` lines; the operator pasted them and got no command. Copy now emits the
  upgrade sequence, and the reference list is a second, faint control.

### APPLY is a shortcut, never the last step

The instinctive reading of a scan → plan → apply flow is that apply is the end of the work. On most
machines it is not: the plugin runs as the account Hermes runs as (`hermes`), and `sudo -n` there
fails. So the pane states the precondition **before** the click — `GET /apply/preflight` runs
`sudo -n true` on that host when a server is selected, and the section either says *this host allows
it* or *not available here*, with the reason, the account, and the commands to run instead. The
button stays locked until the preflight has said yes.

## Dashboard pane (opt-in, desktop half)

Three panels, house HUD style (thin wireframe, cyan on near-black, monospace data — see the root
AGENTS.md design directive):

- **NOW** — per host: kernel running/installable, pending count, last scan age, and a colour that means
  exactly one thing (green only when every check answered *and* nothing is pending; grey when not
  measured).
- **PENDING** — the ranked plan: advisory id, package → version, downtime, the command, and a copy
  button. An Apply control exists only when a typed host name has been entered.
- **GAPS** — the blindness panel: hosts unreachable, sources that refused, and the standing limits
  (in-image CVEs, language dependencies). This panel is never empty and never green.

## v0.1 acceptance (the demo is these lines, run live)

1. `hermes plugins validate .` and `hermes plugins doctor . --ci` pass.
2. A fresh `hermes chat -q "are we patched?"` calls `cve_scan` (read the tool-call line) and the answer
   matches ground truth: `apt-get -s dist-upgrade` + `uname -r` on both hosts, quoted with timestamps.
3. **Reproduce the incident from a fixture**: given a captured apt simulation and USN payload from
   2026-11-06, `cve_plan` says "kernel 7.0.0-43.43 available, `full-upgrade`, reboot required" — the
   exact call that a `-security`-only filter or a plain `upgrade` would have missed.
4. **A refusal**: point it at an unreachable host and at a rate-limited registry; the answer is
   `unknown` with a reason, exit non-zero, never "clean".
5. The pane renders all three panels with data from a real scan, and the GAPS panel lists the two
   standing ones.
6. One notification fires on a change and not on a repeat (`--dry-run` proof, no real page).

## Deliberately not in v0.1

Unattended application; in-image scanning (would wrap `trivy`); language ecosystems (would wrap
`osv-scanner` with an SBOM); Windows/macOS hosts; multi-tenant or fleet management; SCAP/OVAL.
Each is a named gap in the pane rather than an implied capability.
