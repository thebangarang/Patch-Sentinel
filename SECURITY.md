# SECURITY.md — patchpilot

**Tier: High (Tier 2).** Escalate to Critical before enabling unattended application (rule below).

## Why this tier and not Standard

The plugin reads privileged host state (installed packages, kernel, container image digests) and, when
the operator confirms, runs commands that change the machine. A defect does not leak data — it changes
a system, or reports it as safe when it is not. Both are worse than an outage.

## Data Classification

| Data type | Classification | Retention | Encryption |
|---|---|---|---|
| Host inventory (kernel, package versions, findings) | Internal | last 90 scan runs in `data/` | at rest: filesystem; local only |
| Scan receipts / apply receipts | Internal | permanent (audit) | local only |
| Credentials (registry token, optional API key) | Restricted | never stored by the plugin — read via `agent.secret_scope` | n/a |

No customer data, no PII. **No secrets are written to disk by this plugin** — that is a rule, not a
convention: a token read is used in-process and dropped.

## Threat Model

1. **Worst case: the plugin reports a machine as patched when it is not.** It becomes the reason a real
   vulnerability stays open. *Mitigation:* three outcomes per check; "installed ≠ running"; a lagging
   advisory page never produces a verdict; every figure carries its measurement time; the GAPS panel
   is never green and never empty.
2. **Most likely: a source changes shape or refuses, and the tool reads the empty answer as clean.**
   This already happened once in the prototype (Docker Hub `429` → "nothing to do"). *Mitigation:*
   classification at the point of failure into short codes, a refusal payload the agent must respect,
   and a test per source proving the refused case is `unknown`, never `current`.
3. **Second worst: it patches the wrong host.** *Mitigation:* the host label must be typed to confirm;
   applies are staged (download, no restart) then applied; a receipt records what changed; commands get
   a dry-run mode; the daily schedule is read-only by construction.

## Secrets

| Secret | Stored in | Scope | Rotation |
|---|---|---|---|
| Docker Hub read-only token (optional, for image digests/pulls) | the operator's vault; read via `agent.secret_scope` at call time | `repo:read` only | 12 months |
| SSH key for remote hosts | the operator's own `~/.ssh` (never the plugin) | host-scoped | operator's policy |

The plugin declares these in `plugin.yaml` (`requires_env` / `optional_env`) and **never** reads
`.env`, `auth.json` or another tool's credential file.

## Privileged operations

- Everything the scan does is unprivileged: `apt-get -s dist-upgrade`, `uname -r`, `docker ps`,
  `docker buildx imagetools inspect`, `ssh <host>` (read-only commands).
- Anything privileged (real apt, service restarts, reboots) is an **apply**, gated, logged, reversible
  per `docs/design.md`, and never reachable from the scheduler.

## Tier checklist (High) — status

- [x] Core security checklists read (`~/hermes-admin/security-framework.md`)
- [ ] Dependency CVE audit — n/a in v0.1 (stdlib only); re-check if a dependency is added
- [ ] Least-privilege review — before the first public release
- [x] Agent instructions reviewed for injection (this file + `AGENTS.md`)
- [ ] Secrets scan before each public commit (`hermes-admin/scripts/install-secret-hooks.sh` shape)
- [ ] Disclosure block in the README (network calls, subprocesses, credential handling) — before the
      catalogue PR

## Incident Response

- **Trigger:** a false "clean" reported to a user, or an apply that changed something it did not
  describe.
- **Containment:** disable the plugin's scheduled job; switch it to `cve_coverage` only (which reports
  gaps, not verdicts) if the verdict logic is suspect.
- **Recovery:** the machine's own state is captured before any apply (dated state file + image ids), so
  recovery is the documented reversal for that action; then re-run the scan and quote the fresh
  measurement, not the previous one.

## Audit Trail

| Date | Activity | Result | By |
|---|---|---|---|
| 2026-11-06 | Initial design + threat model, from the CVE-2026-98432 incident | tier High set; three false-all-clear classes named | Hermes |
