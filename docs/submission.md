# Submission — Hermes Agent Plugin Hackathon (due 11 Nov 2026, 17:00 EST)

## The three things an entry is

| # | what | who can do it | status |
|---|---|---|---|
| 1 | a **PR to `NousResearch/hermes-agent`** adding `plugin-catalog/patch-sentinel.yaml` | anyone with the channel open; **pushing over SSH needs no token**, opening a PR against a repo we do not own needs a GitHub token or the web UI | not started |
| 2 | a **demo video ≤ 90 s, posted on X, tagging @NousResearch** | **the operator only** (his account) | not started |
| 3 | the **Typeform**: `form.typeform.com/to/FwJLvOln` with both links | the operator | not started |

Sendable as soon as the PR is open. Catalogue checks run when a maintainer starts them; entries are
reviewed every few days — so **open the PR days before the deadline, not hours**.

## The catalogue entry — exact schema (from `plugin-catalog/README.md`, checked 2026-11-06)

```yaml
name: patch-sentinel                 # [a-z0-9_-]{1,64} — the catalogue key, = the plugin id
repo: https://github.com/thebangarang/Patch-Sentinel
sha: "<40-hex commit pin>"           # mandatory, exact; branches/tags/short SHAs are refused by the loader
subdir: ""                           # empty: plugin.yaml sits at the repo root
description: >
  Answers "are we patched?" with evidence — vendor advisories, installed vs running versions and
  container image digests — and says when it could not look instead of reporting a clean.
maintainer: thebangarang
tier: community                      # official/verified are Nous-only
category: automation                 # desktop | memory | platform | web | tools | voice | automation | models | general
requires_hermes: ">=0.19"            # SemVer floor, never a date, never newer than the current release;
                                     # declare the same floor in plugin.yaml
version: "0.1.0"                     # quoted, human label for the SHA
docs_url: "https://github.com/thebangarang/Patch-Sentinel#readme"
image: ""                            # optional 2:1 image on a GitHub host
```

Pin the SHA from a **clean tree** (`git status` clean), and bump `version` in the same commit as the pin.

## Admission rules that actually bite this plugin

1. **Exact SHA pins.** Re-pin in a new PR after every change; the listing installs exactly that commit.
2. **No self-updating code, no core patching, no bundled binaries.** Our scan shells out to
   `apt-get`, `uname`, `docker`, `ssh` — those are the system's own tools, not bundled, and each is
   disclosed below.
3. **Credentials only through Hermes**: `agent.secret_scope.get_secret(NAME)` for the optional registry
   token, declared in `requires_env`/`optional_env`. Never read `.env`, `auth.json` or another tool's store.
4. **Approvals respected**: anything that waits for a person must fail cleanly under cron/gateway —
   our apply gate refuses without a typed confirmation rather than hanging.
5. **Risky behaviour disclosed** in the README *and* the PR description (see below).
6. **Truthful compatibility metadata**: `requires_hermes` in both the entry and `plugin.yaml`; `version`
   matches the pinned code.
7. **Desktop surface rules**: the pane may not reach into Hermes' own markup (`data-slot`,
   `data-testid`, `document.body` observers) or call the raw `window.hermesDesktop` bridge —
   `hermes plugins validate` refuses that.

## Disclosure block (paste into README and the PR)

- **Network**: HTTPS reads from `ubuntu.com/security/notices.json` (advisory feed) and the container
  registry's manifest API (`registry-1.docker.io` / `ghcr.io`) — no telemetry, no third-party analytics.
- **Subprocesses**: `apt-get -s dist-upgrade` (simulation only), `uname -r`, `dpkg-query`,
  `docker ps` / `docker buildx imagetools inspect`, and `ssh <host>` for remote hosts — all read-only in
  the scan. The **apply** step runs `apt-get full-upgrade`, service restarts or a reboot, only after the
  operator types the host name.
- **Reads outside the plugin's own data**: the host's package database state via those commands; nothing
  else. No `.env`, no `auth.json`, no browser or keychain data.
- **Stored credentials**: none. The optional registry token is read at call time and never written.
  SSH uses the operator's own agent key.
- **Background work**: none in-process; the daily scan is a Hermes cron job the user installs.

## Demo video — 90 seconds, three beats (in this order)

1. **A finding with proof (≈25 s).** `hermes chat -q "are we patched?"` → the tool call appears, the
   answer names a real pending advisory and the *running* kernel, with the measurement time. Say the
   numbers out loud.
2. **A refusal (≈25 s).** Ask about a host that is unreachable and a registry that is rate-limited: the
   answer is `unknown` with the reason, never "clean". This is the beat no competing scanner has.
3. **A proof it ran (≈25 s).** The pane: three panels, GAPS populated (in-image CVEs, language deps),
   then the apply gate refusing until the host name is typed.
4. Close on a checkable artefact — a receipt line (`host, action, versions before → after, verified by`)
   and the repo URL.

Record one continuous take and cut the dead air; paste the exact prompts from `docs/design.md`
*v0.1 acceptance* so the demo is the acceptance list, not a narration.

## After the hackathon

- Keep the pin current (`hermes plugins update` follows the entry's SHA only).
- The two named gaps (in-image CVEs → `trivy`; language deps → `osv-scanner` + SBOM) are the v0.2
  roadmap and are already listed in the pane's GAPS panel — the honest place for them.
