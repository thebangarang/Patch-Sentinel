"""The gate: the one place this plugin can change a machine.

Four requirements, from ``docs/design.md`` (*Apply gate*) and decision D6, and all four are in
this file or it refuses:

1. **A typed host name.** :func:`apply` refuses unless ``confirm`` equals the host label exactly.
   A model cannot type for a person, and a forgotten flag fails closed.
2. **A stage before anything changes.** The metadata refresh / download-only pass runs first and
   its failure stops the sequence — an apply window that begins by waiting on a mirror is how a
   busy machine is left half-upgraded.
3. **A receipt.** Every attempt that reaches the host writes a line to ``receipts.jsonl``: host,
   action, versions before → after, how it was verified, when, and whether it was a dry run.
4. **Verification by effect.** A re-probe after the apply, so the receipt says what the machine
   *is*, not what the command claimed: ``uname -r`` and the apt/dnf pending list, re-measured.

``dry_run`` defaults to **true**: the tool stages, prints the commands, verifies the host was
reachable, and stops. Applying for real needs ``dry_run=false`` *and* the typed host name.
"""
from __future__ import annotations

import datetime as dt
import time

from . import store
from .sources import dispatch, shell

STAGE_TIMEOUT = 300
APPLY_TIMEOUT = 900
TAIL = 700                      # bytes of output kept per step


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _tail(text: str) -> str:
    text = (text or "").strip()
    return text[-TAIL:] if len(text) > TAIL else text


def _step(action: str, command: str, target: str | None, timeout: int,
          ok_codes: tuple[int, ...] = (0,)) -> dict:
    started = time.monotonic()
    code, out = shell.run(command, target, timeout=timeout)
    return {"action": action, "command": command, "rc": code,
            "duration_s": round(time.monotonic() - started, 1),
            "output": _tail(out), "ok": code in ok_codes}


def preflight(target: str | None) -> dict:
    """Can this user run sudo without a prompt, on this host? A prompt would hang the tool call."""
    code, out = shell.run("sudo -n true", target, timeout=30)
    ok = code == 0
    return {"ok": ok, "detail": _tail(out) or f"rc={code}",
            "why": "" if ok else (
                "this user cannot run sudo without a password on that host, so an apply would "
                "hang or fail. Grant a NOPASSWD sudoers rule for the user on that host (the "
                "operator's decision, not the plugin's), or run the plan yourself")}


# The stage command's success codes differ per family, and reading one as a failure is how a
# perfectly good host gets refused: `dnf check-upgrade` exits 100 *because* updates exist (measured
# on Fedora 45: rc=100 with 109 updates pending). apt's simulation-and-download exits 0.
COMMANDS = {
    "apt": {
        "stage": "sudo apt-get update && sudo apt-get -y --download-only full-upgrade",
        "stage_ok": (0,),
        "apply": "sudo apt-get -y full-upgrade",
        "apply_ok": (0,),
    },
    "dnf": {
        "stage": "sudo dnf -y check-upgrade --refresh",
        "stage_ok": (0, 100),
        "apply": "sudo dnf -y upgrade --refresh",
        "apply_ok": (0,),
    },
}


def _before(host_entry: dict) -> dict:
    kernel = host_entry.get("kernel") or {}
    return {"kernel_running": kernel.get("running"),
            "kernel_installed": kernel.get("installed"),
            "pending_count": host_entry.get("pending_count"),
            "measured_at": host_entry.get("measured_at")}


def _after(result: dict) -> dict:
    return {"kernel_running": result.get("running"),
            "kernel_installed": result.get("newest_installed"),
            "kernel_verdict": result.get("kernel"),
            "pending_count": len(result.get("pending") or []),
            "measured_at": result.get("measured_at")}


def apply(host_entry: dict, target: str | None, confirm: str, dry_run: bool = True,
          timeout: int = APPLY_TIMEOUT) -> dict:
    """Run the gate for one measured host. Returns a payload; never raises, never half-applies.

    *host_entry* is that host's entry from ``cve_scan`` — the measurement the plan came from, so
    the receipt can say what changed against what was measured.
    """
    label = str(host_entry.get("label") or "").strip()
    family = str(host_entry.get("adapter") or "")
    typed = (confirm or "").strip()
    before = _before(host_entry)
    base = {"applied": False, "dry_run": bool(dry_run), "host": label,
            "target": target or "local", "started_at": _now(), "before": before, "steps": []}

    # 1. the typed name
    if not label:
        return {**base, "reason": "no host label to confirm against"}
    if typed != label:
        return {**base, "reason": f"the gate is armed by typing {label!r} exactly — got {typed!r}. "
                                  "Nothing was run."}

    commands = COMMANDS.get(family)
    if commands is None:
        return {**base, "reason": f"no apply commands for adapter {family!r} — the plan is all "
                                  "this host supports"}

    pending = int(host_entry.get("pending_count") or 0)
    kernel = (host_entry.get("kernel") or {}).get("verdict")
    if not pending and kernel not in ("kernel-update-available", "kernel-reboot-needed"):
        return {**base, "reason": "nothing to apply on this host, as measured",
                "measured_at": host_entry.get("measured_at")}

    # 3a. reachability + privilege, before anything else runs
    check = preflight(target)
    steps = []
    if not check["ok"]:
        receipt = _receipt(base, steps, check["why"], dry_run)
        return {**base, "reason": check["why"], "preflight": check, "receipt": receipt}

    # 2. the stage, always
    steps.append(_step("stage", commands["stage"], target, min(timeout, STAGE_TIMEOUT),
                       ok_codes=commands["stage_ok"]))
    if not steps[-1]["ok"]:
        why = "the stage failed, so nothing was applied (this is the half-upgraded-machine guard)"
        receipt = _receipt(base, steps, why, dry_run)
        return {**base, "reason": why, "steps": steps, "preflight": check, "receipt": receipt}

    if dry_run:
        why = ("dry run: the stage ran, the apply did not. Re-call with dry_run=false to apply, "
               "with the host name typed again")
        receipt = _receipt(base, steps, why, True)
        return {**base, "reason": why, "would_run": commands["apply"], "steps": steps,
                "preflight": check, "receipt": receipt}

    # 2b. apply
    steps.append(_step("apply", commands["apply"], target, timeout,
                       ok_codes=commands["apply_ok"]))
    applied_ok = steps[-1]["ok"]

    # 4. verify by effect, then write the receipt
    result = dispatch.probe(label, target, timeout=180)
    after = _after(result) if result.get("ok") else {"error": result.get("why")}
    if not result.get("ok"):
        why = "the apply finished but the host could not be re-read, so the change is UNVERIFIED"
    elif applied_ok:
        why = "applied and re-measured"
    else:
        why = "the apply command failed — see steps[].output; the host was re-measured"
    receipt = _receipt({**base, "after": after}, steps, why, False, applied=applied_ok)
    return {**base, "applied": applied_ok, "reason": why, "after": after,
            "verified_by": "uname -r + the package manager's pending list, re-measured",
            "reboot_required": after.get("kernel_verdict") == "kernel-reboot-needed",
            "steps": steps, "preflight": check, "receipt": receipt}


def _receipt(base: dict, steps: list[dict], why: str, dry_run: bool,
             applied: bool = False) -> dict:
    """The line that goes in ``receipts.jsonl`` — written for attempts that reached the host."""
    row = {"host": base.get("host"), "target": base.get("target"),
           "action": "full-upgrade" if base.get("before") else "none",
           "dry_run": bool(dry_run), "applied": bool(applied),
           "before": base.get("before"), "after": base.get("after"),
           "verified_by": "re-measured after the run" if base.get("after") else "not verified",
           "steps": [{"action": s["action"], "rc": s["rc"], "duration_s": s["duration_s"]}
                     for s in steps],
           "outcome": why, "at": _now()}
    try:
        store.append_receipt(row)
    except OSError as exc:                                # a receipt that cannot be written is a
        row["receipt_write_failed"] = str(exc)            # fact the caller must see
    return row
