# Decisions

## D1 — Name: **Patch Sentinel** (2026-11-06) — decided

**Decision:** product **Patch Sentinel**; folder, plugin id and repo `patch-sentinel` /
`github.com/thebangarang/Patch-Sentinel`; the Python subpackage is `patch_sentinel/`.
**Reason:** the operator named the public repository before any code existed; the working name
(`patchpilot`) is retired everywhere.
**Alternatives (rejected earlier):** `cve-guard`, `sentinel`, `patchposture`.
**Consequence:** the id appears in `plugin.yaml`, `dashboard/manifest.json`, the pane's
`/api/plugins/patch-sentinel` prefix and the catalogue entry — created with this name, never renamed
after publication.

## D2 — A plugin, not a standalone service (2026-11-06)

**Decision:** ship as a Hermes plugin (tools + bundled skill + optional desktop pane), not a daemon
with its own web UI.
**Reason:** the value is the *agent* being able to answer and act; a separate service would duplicate
Hermes' cron, notification, profile and UI layers and could not be listed in the catalogue.
**Alternatives:** a standalone FastAPI service (rejected: another thing to run and secure);
an MCP server (viable, but a plugin reaches tools, cron, notify and the desktop pane in one package).
**Consequence:** we inherit the plugin API's constraints — no network at import, JSON-returning
handlers that never raise, opt-in desktop half.

## D3 — Read the vendor feed and the archive; treat the CVE page as context (2026-11-06)

**Decision:** the USN feed + the apt simulation + the archive candidates decide verdicts; the Ubuntu
CVE tracker page is read only for narrative.
**Reason:** measured — the tracker read "vulnerable, work in progress" for a week while 7.0.0-43.43
was published and installable through `-updates`.
**Alternatives:** poll the CVE tracker and parse its status word (rejected: it lags and would have kept
us waiting); poll `-security` only (rejected: this fix came through `-updates`).
**Consequence:** three sources must be reconciled; the reconciliation *is* the product.

## D4 — No security-pocket filter on the apt simulation (2026-11-06)

**Decision:** read every `Inst` line from `apt-get -s dist-upgrade`, annotate which ones a recent USN
names, and never filter to `-security`.
**Reason:** the kernel fix arrived through `resolute-updates`. A `-security`-only filter would have
reported "nothing pending".
**Consequence:** the pane shows some non-security updates; the advisory annotation is what separates
them. That is honest, and it is a feature: an unexplained update is worth seeing.

## D5 — Container images: digest comparison in v0.1, a real scanner later (2026-11-06)

**Decision:** v0.1 compares the running image's digest with the registry's current digest for the tag
(`docker buildx imagetools inspect --format '{{.Manifest.Digest}}'`). In-image CVEs are v0.2 via
`trivy`.
**Reason:** digests are a fact, need no database, and catch the common case (a rebuilt base image). A
scanner adds a binary, a database and a licence to review — too much for a hackathon slice.
**Alternatives:** `docker manifest inspect -v` — **rejected after measurement**: its first digest never
equals the image's own RepoDigest, so it reports every image stale for ever.
**Consequence:** a rebuilt image is reported as "an update exists", never as "these CVEs are fixed".

## D6 — Apply gate: typed host name, staged first, receipt written (2026-11-06)

**Decision:** `cve_plan` never executes. `cve_apply` requires `confirm: "<host label>"` and
`dry_run` defaults to true; applies stage downloads first, then act, then verify by effect.
**Reason:** the operator's own rule for destructive controls (double confirm, typed name), applied to
a tool that can reboot a server.
**Alternatives:** auto-apply unattended (rejected for v0.1: it makes the plugin the cause of an outage,
and it would push the project to Tier 1 with its full gate set); a "trusted hosts" list (rejected:
a list is still an unattended action).
**Consequence:** the demo shows the gate refusing, which is the more persuasive beat.

## D7 — Stdlib only (2026-11-06)

**Decision:** no declared Python dependencies in v0.1.
**Reason:** `plugin-authoring.md`: every dependency is an install-time consent prompt and a resolution
question against Hermes' pins; stdlib keeps install to one command and lets the plugin run under
Hermes' own interpreter.
**Consequence:** hand-written parsers for the small payload shapes we read, each with a refusal path —
which is also what makes the "could not look" rule enforceable.

## D8 — MIT licence (2026-11-06)

**Decision:** MIT, `Copyright (c) 2026 Kevin Lauharatanavisais (AITurn)`.
**Reason:** catalogue admission requires a licence; MIT is the expected one.
**Consequence:** stdlib-only means no licence-compatibility question ever arises.

## D9 — The deadline sets the scope: v0.1 is the submission (2026-11-06)

**Decision:** cut the demo to what can be **verified** by 11 Nov 17:00 EST — one host plus one remote,
three sources, four tools, three-panel pane, one change notification. Everything else is a named gap in
the pane, not a half-built feature.
**Reason:** judging weights reliability and polish: a smaller thing that never lies scores better than a
broad thing with a silent path. The rules also favour "more than a prompt or a skill", which the
three-outcome honesty layer already is.
**Alternatives:** in-image scanning via `trivy`, language deps via `osv-scanner` (deferred: each adds a
binary, a database and a licence review); unattended auto-apply (deferred: Tier 1 gates).
**Consequence:** the demo has a fixed beat sheet — a finding, a refusal, a proof — see
`docs/design.md` *v0.1 acceptance*.

## D10 — No credential path at all in v0.1 (2026-11-06) — decided

**Decision:** the plugin reads no secret, declares no `requires_env`/`optional_env`, and passes no
credential to any subprocess. Registry lookups are anonymous; a rate limit is `unknown` with the reason.
Remote hosts are reached through the operator's own SSH agent (`BatchMode=yes`), which `ssh` reads
itself.
**Reason:** a token path means a credential a plugin holds, a place to store it, a way to hand it to
`docker`, and a rotation story — for one improvement (400 vs 200 pulls/6h) on a machine that pulls a
handful of tags a day. The catalogue's credential rule is easiest to satisfy by having nothing to
satisfy.
**Alternatives:** `optional_env: DOCKER_HUB_TOKEN` + `docker login` at call time (rejected for v0.1:
a secret in a subprocess environment, and a rotation duty nobody would own); reading the operator's
`~/.docker/config.json` (rejected: reading another tool's credential store, explicitly forbidden).
**Consequence:** `.env.example` no longer advertises a registry token, `SECURITY.md` says so plainly, and
a rate-limited registry is a named gap rather than a configuration burden.

## D11 — The CVE tracker is read, but only to show where it is wrong (2026-11-06) — decided

**Decision:** `cve_explain` reads Ubuntu's CVE tracker record for the CVE it was asked about, labels it
`context_only`, and then compares the version the tracker itself names with what the host is measurably
running. Where the tracker's status is still open and that exact version is installed and running, the
answer says so (`disagreements[]`, with the measurement as its evidence). The tracker never sets a
verdict on its own.
**Reason:** on 2026-11-06 the tracker for CVE-2026-98432 read `pending` / "7.0.0-43.43" while
7.0.0-43.43 was installed and 7.0.0-43-generic was running here. That single fact is the product's whole
argument, and it is reproducible from a pinned fixture (`tests/fixtures/cve-2026-98432_resolute.json`).
**Alternatives:** tracker read for narrative only, no comparison (rejected: leaves the user with two
contradicting statements and no verdict); tracker as a verdict input (rejected: D3, measured to lag).
**Consequence:** the comparison is restricted to kernels the host could actually run — the flavour-less
`linux` source package and the package matching the running kernel's own flavour; other flavours go to
`not_compared[]`, because another flavour's fix is not a statement about this host.

