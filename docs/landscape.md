# Landscape — what already exists, and what that means for our build

*Checked 2026-11-06, before writing code (root AGENTS.md: "Search Before You Build").*

## Hermes-native

- **Catalog**: `manage_catalog search` for `cve security vulnerability patching` and `system audit`
  returns **no plugin** — only community skills about vulnerability-management *practice*
  (`vulnerability-management`, `performing-endpoint-vulnerability-remediation`, `sec-audit`). Those are
  prose workflows; none ships a scanner, a dashboard, or patch execution.
- **Conclusion:** no Hermes plugin occupies this space. The differentiator cannot be "we scan CVEs" —
  it has to be the Hermes-native experience: tools the agent can call, a pane the operator reads, a
  gated apply, and an honesty vocabulary.

## Upstream OSS we should wrap, not re-implement

| project | what it gives | our decision |
|---|---|---|
| **Ubuntu USN API + archive** | the authoritative per-package fix statement for Debian/Ubuntu | **use directly** (already proven in `cve-watch.py`) |
| **`apt-get -s dist-upgrade`** | installability without privileges or locks | **use directly** |
| **osv-scanner** (OSV.dev, Apache-2.0) | language ecosystems (PyPI/npm/Go) from lockfiles/SBOM | v0.2 — wrap it, do not write a dependency matcher |
| **trivy** (Apache-2.0) | CVEs *inside* container images and SBOMs | v0.2 — wrap it; v0.1 only compares registry digests |
| **debsecan / ubuntu-security-status** | per-package CVE mapping | not needed: the USN feed + archive cover it with less parsing |
| **Wazuh / osquery / Greenbone** | full SIEM/agent/compliance suites | out of scope — a Hermes plugin is not a fleet agent; integrating is a different product |
| **unattended-upgrades** | unattended application on the host | **we orchestrate, do not replace**: our plans call it where it is already the local convention |

## What that leaves us to build (the actual product)

1. **The verdict layer** — three states per check, `installed ≠ running`, archive-over-tracker. Nothing
   in the list above does this for an operator: they report package versions, not patch posture.
2. **The plan layer** — ranked, with downtime and the exact command, aware that `upgrade` cannot
   install a new kernel.
3. **The apply gate** — typed confirmation, staged first, verified by effect, receipt written.
4. **The pane** — the operator-facing summary, including the blindness panel.
5. **The Hermes integration** — tools, a bundled skill, cron, the notification channel.

## Risk of being redundant anyway

The honest risk is not another scanner; it is that **`unattended-upgrades` plus a mail already does
80 % of this for a single box**. Our answer: it does not tell you *when it could not look*, does not
distinguish installed from running, and cannot see the remote host or the container images. That is the
gap the demo must show — a machine whose updates are "on" and still unpatched, which is exactly the
9 days we spent on CVE-2026-98432.
