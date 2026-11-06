# SECURITY.md — patch-sentinel

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
| Credentials | none in v0.1 | the plugin reads no secret at all | n/a |

No customer data, no PII. **No secrets are written, read or forwarded by this plugin** — not by
convention but by construction: there is no credential path in the code (see *Secrets*). Registry
reads are anonymous; the operator's SSH agent is used by `ssh` itself, and the plugin never sees the
key.

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

**v0.1.0 handles no credential.** `plugin.yaml` declares no `requires_env` and no `optional_env`,
because there is nothing to declare: registry lookups are anonymous (a rate limit is reported as
`unknown`, with the reason), and remote hosts are reached through the operator's own SSH agent, which
`ssh` reads itself. If a registry token is ever added it must arrive through
`agent.secret_scope.get_secret()` at call time; the plugin never reads `.env`, `auth.json` or another
tool's credential file, and it must never place a secret in a subprocess environment.

## Privileged operations

- Everything the scan does is unprivileged: `apt-get -s dist-upgrade`, `uname -r`, `docker ps`,
  `docker buildx imagetools inspect`, `ssh <host>` (read-only commands).
- **Nothing privileged is implemented in v0.1.0.** The plan's commands are strings for a human; the
  test suite asserts that no apply path exists. When an apply is added it must be gated (host name
  typed by the operator), recorded (a receipt line), reversible (documented per action) and never
  reachable from the scheduler — the design for that is in `docs/design.md` *Apply gate*.

## Tier checklist (High) — status

- [x] Core security checklists read (`~/hermes-admin/security-framework.md`)
- [ ] Dependency CVE audit — n/a in v0.1 (stdlib only); re-check if a dependency is added
- [ ] Least-privilege review — before the first public release
- [x] Agent instructions reviewed for injection (this file + `AGENTS.md`)
- [x] Secrets scan before each public commit — none read, none written, none in the tree
- [x] Disclosure block in the README (network calls, subprocesses, credential handling)
- [x] Admission gates green: `hermes plugins validate .` and `hermes plugins doctor . --ci`

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
| 2026-11-06 | First code: the four read-only tools + the measurement layer | no credential path, no apply path; both admission gates green; 43 tests | Hermes |
