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


# The command for each step depends on the host's own package manager. A plan that says
# `apt-get` on Fedora is worse than no plan: it is wrong *and* it looks authoritative.
COMMANDS = {
    "apt": {
        "refresh": "sudo apt-get update",
        "stage": "sudo apt-get update && sudo apt-get -y --download-only full-upgrade",
        "apply": "sudo apt-get -y full-upgrade",
        "verify": "apt-get -s dist-upgrade | grep '^Inst ' || echo 'nothing pending'",
        "stage_why": "Staging first means the apply window is not waiting on a mirror.",
        # No placeholder angles here: a reversal an operator cannot run is decoration. apt keeps the
        # record itself, so the reversal names the log that holds it and what restoring costs.
        "reversal": "nothing automates this on apt: /var/log/apt/history.log lists every package "
                    "this run upgraded and the version it came from, and apt-get install with that "
                    "old version restores one package at a time — only while the archive still "
                    "carries it",
    },
    "dnf": {
        "refresh": "sudo dnf -q makecache",
        "stage": "sudo dnf -y check-upgrade --refresh",
        "apply": "sudo dnf -y upgrade --refresh",
        "verify": "dnf check-upgrade >/dev/null; echo rc=$?   # 100 = still updates, 0 = none",
        "stage_why": "Refreshing the metadata first means the apply window is not waiting on a "
                     "mirror, and the list is re-read from the repo rather than from a cache.",
        "reversal": "dnf history undo last   (the transaction id is in dnf history)",
    },
    # the other three families are scanned but have no plan yet; the refresh command is still what a
    # stale-index warning needs to name, so it is here rather than invented in the pane
    "zypper": {"refresh": "sudo zypper refresh"},
    "pacman": {"refresh": "sudo pacman -Sy"},
    "apk": {"refresh": "sudo apk update"},
}


def _commands(host: dict) -> dict:
    family = str(host.get("adapter") or host.get("family") or "apt")
    return COMMANDS.get(family, {})


def steps_for(host: dict) -> list[dict]:
    """The ordered steps for one measured host, each with risk, downtime, why, verify, reversal."""
    steps: list[dict] = []
    commands = _commands(host)
    pending = host.get("pending") or []
    facts = _kernel_facts(host)
    kernel, running = facts["verdict"], facts["running"]
    installed, candidate = facts["installed"], facts["candidate"]
    rebuilt = [i for i in (host.get("images") or []) if i.get("state") == "rebuilt"]
    advisories = _advisories(pending)

    why_updates = (f"{len(pending)} package update(s) installable on {host.get('label')}"
                   + (f", {len(advisories)} named by a recent advisory: {', '.join(advisories)}"
                      if advisories else ", none named by a recent advisory"))

    if pending and commands:
        steps.append({
            "action": "Refresh the metadata and check what would change, without installing anything",
            "command": commands["stage"],
            "risk": "low",
            "downtime": "none (nothing installed)",
            "why": why_updates + ". " + commands["stage_why"],
            "verify": commands["verify"],
            "reversal": "nothing changed to reverse",
        })
        steps.append({
            "action": "Install the updates",
            "command": commands["apply"],
            "risk": "medium",
            "downtime": "1–3 min; services restart as their packages require",
            "why": ("full-upgrade and not upgrade: a new kernel is a new package, which upgrade "
                    "keeps back (rule 4)." if commands is COMMANDS["apt"] else
                    "upgrade moves every installed package, kernel included; refresh so the "
                    "metadata is not stale."),
            "verify": commands["verify"],
            "reversal": commands["reversal"],
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
            # the previous id is recorded in the scan, so it is named here rather than described
            "reversal": "docker compose down && docker run --detach " + str(image.get("local") or "")
                        + "   # the previous image id, recorded in the scan this plan came from",
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
    # Ubuntu keeps the ported proposal text (it is what the daily routine prints); any other
    # family gets its steps joined, because verdict.proposal() speaks apt by design.
    if str(host.get("adapter") or "apt") == "apt":
        proposal_text = verdict.proposal(host.get("label") or "", host.get("pending") or [],
                                        _kernel_facts(host)["verdict"] or "",
                                        host.get("images") or [])
    else:
        proposal_text = "\n".join(step["command"] for step in steps) or "(nothing)"
    return {"host": host.get("label"), "measured_at": host.get("measured_at"),
            "steps": steps, "refusals": refusals, "proposal_text": proposal_text}
