# PatchPilot — a Hermes plugin that keeps a machine honest about its patches

> Status: **draft for a hackathon entry.** Nothing here is published yet; every number in this file is
> a claim from a measured run and is re-checked before any catalogue listing is written.

PatchPilot answers one question with evidence, then offers the next step: **what is published as a
security fix that this machine — or a machine we manage — is not running?** It reads what the vendor
published, compares it with what is installed *and running*, and returns a patch plan: the exact
commands, the downtime each costs, and a refusal when it cannot know.

It does not guess. A check that could not look says so. A kernel that is installed but not booted is
its own verdict, not "patched". A registry that answered `429` is *unverified*, never *current*.

## What you can ask it

| you type | you get |
|---|---|
| "are we patched?" | per host: pending security updates with the advisory id, kernel currency (running vs installed vs installable), container images rebuilt upstream |
| "what about CVE-2026-98432?" | the advisory from the vendor source, whether your version is affected, and what closed it |
| "how do we close these?" | a numbered patch plan per host — commands, downtime, nothing executed |
| "do it" + the host name typed | the plan runs, and a receipt records what changed and how it verified |
| "what are you NOT checking?" | the coverage gaps, named: language dependencies, CVEs inside image layers, hosts it cannot reach |

## Why it can be trusted

- **The distro's own security feed is the source of truth** for OS packages (Ubuntu USN + the archive
  itself), not a scraped feed and not a model's memory.
- **A patch counts only when it is running** — `uname -r`, not "the package is installed".
- **Three outcomes per check**: known-clean, known-finding, and *could not look* — the third is shown
  as a blind spot and never folded into a green.
- **Refusals are payloads**: a tool that cannot answer returns a refusal shape the agent is told to
  respect, so it cannot substitute a plausible sentence.

## Honest limits (v0.1)

- OS packages + kernel + container image digests. **Not** CVEs *inside* image layers, **not** language
  dependencies inside your own code (that needs an SBOM + `osv-scanner`).
- Linux only; Ubuntu/Debian package sources verified against the vendor feed. Other distributions are
  a named gap, not a silent pass.
- Auto-remediation ships **off**: the plan proposes, and applying it needs the host name typed.
  Unattended patching is a later decision, not a default.
- Remote hosts need non-interactive SSH and are read through the same three-outcome discipline.

## Install (after publication)

```bash
hermes plugins install <owner>/patchpilot --enable
hermes chat -q "are we patched?"
```

## Provenance

Built from a real incident: a Linux kernel use-after-free (CVE-2026-98432) tracked by hand for nine
days on two hosts — interim firefighting controls, a hand-built watcher, and the discovery that
Ubuntu's CVE page lagged the archive by a week. Each rule in `docs/design.md` cites the measurement
that produced it.
