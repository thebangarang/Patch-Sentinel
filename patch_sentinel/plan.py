"""Findings → a ranked, reversible patch plan. Pure: it computes commands, it never runs one.

Three things this module exists to get right, each of them a measured incident:

* the command is ``full-upgrade``, never ``upgrade`` — a new kernel arrives as a new *package*
  and plain ``upgrade`` keeps it back (design rule 4);
* a kernel that is installed but not running gets ``reboot``, not "install it again" (rule 1);
* every step carries its own reversal and its own verification, because the operator asked for
  a plan he can undo, not a plan he has to trust (D6, ``backup-rollback.md``).
"""
from __future__ import annotations

from . import verdict


def _advisories(pending: list[dict]) -> list[str]:
    ids = {str(p["advisory"]) for p in pending if p.get("advisory")}
    return sorted(ids)


def _kernel_facts(host: dict) -> dict:
    """Accept both shapes: the ``cve_scan`` host entry (``kernel`` is a dict) and a flat reading."""
    kernel = host.get("kernel")
    if isinstance(kernel, dict):
        return {"verdict": kernel.get("verdict"), "running": kernel.get("running"),
                "installed": kernel.get("installed"),
                "candidate": kernel.get("installable")}
    return {"verdict": kernel, "running": host.get("running"),
            "installed": host.get("newest_installed"), "candidate": host.get("candidate")}


def steps_for(host: dict) -> list[dict]:
    """The ordered steps for one measured host, each with risk, downtime, why, verify, reversal."""
    steps: list[dict] = []
    pending = host.get("pending") or []
    facts = _kernel_facts(host)
    kernel, running = facts["verdict"], facts["running"]
    installed, candidate = facts["installed"], facts["candidate"]
    rebuilt = [i for i in (host.get("images") or []) if i.get("state") == "rebuilt"]
    advisories = _advisories(pending)

    why_updates = (f"{len(pending)} package update(s) installable on {host.get('label')}"
                   + (f", {len(advisories)} named by a recent advisory: {', '.join(advisories)}"
                      if advisories else ", none named by a recent advisory"))

    if pending:
        steps.append({
            "action": "Refresh the package lists and download everything, without restarting anything",
            "command": "sudo apt-get update && sudo apt-get -y --download-only full-upgrade",
            "risk": "low",
            "downtime": "none (download only)",
            "why": why_updates + ". Staging first means the apply window is not waiting on a mirror.",
            "verify": "apt-get -s dist-upgrade | grep '^Inst ' | wc -l",
            "reversal": "nothing changed to reverse: apt-get clean reclaims the downloaded files",
        })
        steps.append({
            "action": "Install the updates",
            "command": "sudo apt-get -y full-upgrade",
            "risk": "medium",
            "downtime": "1–3 min; services restart as their packages require",
            "why": "full-upgrade and not upgrade: a new kernel is a new package, which upgrade "
                   "keeps back (rule 4).",
            "verify": "apt-get -s dist-upgrade | grep '^Inst ' || echo 'nothing pending'",
            "reversal": "the pre-change state is in the scan this plan came from; "
                        "re-install the recorded versions with apt-get install <pkg>=<version>",
        })

    if kernel == "kernel-update-available":
        steps.append({
            "action": "Reboot into the newly installed kernel",
            "command": "sudo reboot",
            "risk": "high",
            "downtime": "1–2 min, every service on the host",
            "why": f"kernel {candidate} is installable and {running} is "
                   "running: a kernel patch counts only when it is the running kernel (rule 1).",
            "verify": "uname -r   # must print the newly installed release",
            "reversal": "boot the previous kernel from the bootloader menu; it is still installed "
                        "(the previous release is kept, not removed)",
        })
    elif kernel == "kernel-reboot-needed":
        steps.append({
            "action": "Reboot into the kernel that is already installed",
            "command": "sudo reboot",
            "risk": "high",
            "downtime": "1–2 min, every service on the host",
            "why": f"{installed} is installed and {running} is "
                   "running: nothing to install, only to boot (rule 1).",
            "verify": "uname -r   # must print " + str(installed),
            "reversal": "boot the previous kernel from the bootloader menu",
        })

    for image in rebuilt:
        steps.append({
            "action": f"Re-pull {image.get('ref')} in its compose project",
            "command": "docker compose pull && docker compose up -d",
            "risk": "low",
            "downtime": "seconds per service (recreate, not a reboot)",
            "why": f"the tag {image.get('ref')} resolves to a different digest than the running "
                   "image, so it was rebuilt upstream — usually accumulated fixes, never a "
                   "claim about which ones (D5)",
            "verify": "docker inspect --format '{{index .RepoDigests 0}}' $(docker compose ps -q)",
            "reversal": f"docker compose up -d with the previous image id "
                        f"(recorded from {image.get('local') or 'the running container'})",
        })

    return steps


def plan_for(host: dict) -> dict:
    """``{"steps": [...], "refusals": []}`` for one measured host. Never executes anything."""
    steps = steps_for(host)
    refusals = []
    if _kernel_facts(host).get("verdict") == "kernel-unknown":
        kernel_block = host.get("kernel")
        refusals.append({
            "reason": "the kernel was not measurable on this host",
            "detail": (kernel_block.get("reason") if isinstance(kernel_block, dict)
                       else "no kernel package to compare with")})
    if not steps:
        refusals.append({"reason": "nothing to do on this host, as measured",
                         "detail": "kernel current or unmeasured, no installable update, "
                                   "no image rebuilt"})
    return {"host": host.get("label"), "measured_at": host.get("measured_at"),
            "steps": steps, "refusals": refusals,
            "proposal_text": verdict.proposal(host.get("label") or "", host.get("pending") or [],
                                              _kernel_facts(host)["verdict"] or "",
                                              host.get("images") or [])}
