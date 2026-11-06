# patch-sentinel — project context

## What we are building

A **Hermes plugin** that watches the patch posture of the machine Hermes runs on — and of remote
hosts we manage over SSH — and makes its owner reactive: what is published, what we run, what to do
next, with the option to apply behind a typed confirmation.

Target: **hackathon entry**. Deadline, rules and judging criteria are not yet known (see *Open
questions*), so nothing in this project assumes them.

## Why this, why now

We lived the problem for nine days in November 2026 — see `~/hermes-admin/threads/platform--kernel-cve.md`
and `platform--patch-routine.md`:

- CVE-2026-98432 was published 15 Oct; Ubuntu shipped the fix (7.0.0-43.43) on 5–6 Nov.
- **Ubuntu's CVE page still read "vulnerable, work in progress" while the fixed kernel was already
  published and installable through `-updates`.** Anyone trusting the CVE page alone would still be
  waiting.
- **`apt-get upgrade` silently keeps a new kernel back** (a new kernel arrives as a new *package*), so
  the box looks handled and is not.
- The fix arrived through `-updates`, not `-security` — a security-pocket filter would have missed it.
- A Docker Hub `429` made an image check answer "nothing to do" while four images were out of date: a
  false all-clear that took a second instrument to catch.

Each of those is now a rule in `docs/design.md`. That is the differentiator — not "we scan CVEs", but
"we refuse to report a clean we did not measure".

## What already exists on this machine (reuse, do not rebuild)

| asset | what it does | how it is reused |
|---|---|---|
| `~/hermes-admin/scripts/cve-watch.py` | the standing routine: USN feed + apt simulation + registry digests + kernel currency, per host, with a 23-assertion selftest | **the logic core** — port the pure functions (`parse_inst`, `usn_index`, `kernel_verdict`, `image_state`) and their fixtures |
| `~/hermes-admin/scripts/pull-pending-images.sh` | 429-aware pull retry; downloads only, never restarts | the "stage, never apply" pattern |
| `~/hermes-admin/scripts/install-cve-2026-98432-controls.sh` | interim mitigations when no patch exists (idempotent, `--revert`) | the *interim controls* feature (v0.2) |
| `~/hermes-admin/scripts/notify.py` | the one alert channel, dedup by key, `--dry-run` | notification path, unchanged |
| `~/hermes-admin/scripts/probe-cve-2026-98432.py` | proves a netfilter control by effect | the "prove by effect, not by config" test pattern |

## Constraints that shape the build

1. **Hermes plugin API** (`hermes-agent` skill → `references/plugin-authoring.md`): `plugin.yaml` +
   `__init__.py:register(ctx)`; tools return JSON strings and never raise; the desktop half is
   `desktop/plugin.js` + `dashboard/{manifest.json,plugin_api.py}` and is **opt-in for the user**;
   validate with `hermes plugins validate .` and `hermes plugins doctor . --ci` — the latter **blocks
   sockets during registration**, so nothing may touch the network at import time.
2. **No declared Python dependencies if avoidable** — stdlib only; network calls at call time.
3. **Project isolation** (root AGENTS.md, 8 dimensions): this folder only, its own `.venv`, `.env`,
   git repo; services loopback-only.
4. **Security tier: High (Tier 2)** — see `SECURITY.md`. It reads privileged state and can change a
   system, so those rules are load-bearing.

## Scope for v0.1 (the hackathon slice)

In:
- Local host + one remote over SSH (config-driven).
- Three sources: Ubuntu USN feed, the apt simulation, container image digests.
- Tools: `cve_scan`, `cve_plan`, `cve_explain`, `cve_coverage`.
- A dashboard pane: *now*, *pending*, *gaps*.
- A daily scan with change-only notification.

Out (explicitly, so a fresh session does not drift): applying patches unattended; macOS/Windows;
in-image CVE scanning; SCAP/OVAL compliance; any SaaS backend.

## The contest (answered 2026-11-06)

**Hermes Agent Plugin Hackathon**, announced by @NousResearch on 4 Nov 2026: 7 days, $20,000 in prizes.

| rule | what it means for us |
|---|---|
| **Submissions due 5 PM EST, 11 Nov 2026** (= 23:00 CET) | five working days from the day this project opened |
| Entry = **a PR adding the plugin to the Hermes plugin catalogue** | needs a public repo, **MIT licence** (added), README + SECURITY with a disclosure block, and `plugin-catalog/patch-sentinel.yaml` pinning a full 40-char SHA |
| plus a **demo video ≤ 90 s on X, tagging @NousResearch** | the video is a product surface, not a formality — the beat sheet is in `docs/design.md` |
| plus the **Typeform** (`form.typeform.com/to/FwJLvOln`) with both links | can be sent as soon as the PR is open |
| judged on **usefulness, reliability, polish, creativity**; favours plugins that do more than a prompt or a skill | our differentiator is the honesty layer (three outcomes, installed≠running) — exactly "more than a prompt" |

Repository: **github.com/thebangarang/Patch-Sentinel** (public; empty until the first push).

### Decided

- **Auto-apply is out of the demo** (operator, 2026-11-06): the typed-confirmation gate is built, and
  unattended patching is not. Do not re-ask.

### Still open

- **Who posts the video and the form** — both need the operator's own X account and the Typeform. The
  agent writes the script, the credits line and the caption; it never posts them.
