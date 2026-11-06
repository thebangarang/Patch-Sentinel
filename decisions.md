# Decisions

## D1 — Name `patchpilot` (2026-11-06) — provisional

**Decision:** the project folder and plugin id are `patchpilot`.
**Reason:** short, says what it does, no existing Hermes plugin uses it (`manage_catalog search`).
**Alternatives:** `cve-guard` (accurate but sounds like a scanner), `sentinel` (overused),
`patchposture` (accurate, awkward to type).
**Consequence:** renaming is one directory move + `plugin.yaml` + `dashboard/manifest.json`; cheapest
now, so the operator should confirm before the first commit that goes public.

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
