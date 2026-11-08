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

- Everything the **scan** does is unprivileged: `apt-get -s dist-upgrade`, `uname -r`, `docker ps`,
  `docker buildx imagetools inspect`, `ssh <host>` (read-only commands). The pane calls nothing that
  changes a machine — it hands over commands.
- **One privileged path exists, and it is a tool, not a control:** `cve_apply`. It refuses unless the
  operator types the host name, `dry_run` is explicitly `false`, and `sudo -n` works on that host; it
  runs `sudo -n` only, so a password prompt can never hang a call, and it hands the same commands over
  when it refuses. It stages, applies, re-measures and writes a receipt, is reversible per step, and is
  never reachable from a schedule. `tests/test_apply.py` holds the gate; `docs/apply-by-hand.md` has the
  walkthrough.

## Tier checklist (High) — status

- [x] Core security checklists read (`~/hermes-admin/security-framework.md`)
- [x] Dependency CVE audit — n/a while the plugin is stdlib only; re-check the day a dependency lands
- [x] Least-privilege review (2026-11-08): every subprocess is an argv list (no `shell=True`, no
  `eval`/`exec` anywhere in `patch_sentinel/` or `dashboard/`), ssh targets are validated against what
  can legitimately sit in an ssh argv, state files are written 600 inside a 700 directory, and the
  network surface is five anonymous HTTPS endpoints plus the registry
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
| 2026-11-08 | Pre-release audit: whole tree re-read, apply control removed from the pane, coverage claims per family | no secret in the tree; argv-only subprocesses; the pane calls nothing that writes; 348 tests | Hermes |
