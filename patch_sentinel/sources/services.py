"""Is the patch in effect, or only installed?

The plugin's first rule is that *installed ≠ running* — the kernel case is handled by comparing `uname -r`
with the installed package. Userland has the same problem and its own conventions, which this module
reads:

* **`/var/run/reboot-required`** and `reboot-required.pkgs` (Debian and Ubuntu): the packaging system
  records that a reboot is owed and which packages asked for it. A file's existence is a fact; its
  content names the reason.
* **`needrestart -b`**: machine-readable output — `NEEDRESTART-KSTA` for the kernel state and one
  `NEEDRESTART-SVC:` line per service still mapping a library that has been replaced on disk. A service
  running an old libc is a service that did not get the patch, whatever `dpkg` says.
* **`needs-restarting -r`** (dnf/yum): exit code 1 means a reboot is required, 0 means not.

Two refusals keep it honest. `needrestart` inspects processes, so what it can see depends on the account
running it — the payload says which account that was, and a non-root reading is not presented as
complete. And a tool that is not installed is `unavailable`, never "nothing to restart".
"""
from __future__ import annotations

import re

MARK_FLAGS = "--flags--"
MARK_NEEDRESTART = "--nr--"
MARK_NEEDS_RESTARTING = "--nrs--"

#: One round trip, three readings. The markers keep the sections apart without a parser for prose.
PROBE = (
    f"echo {MARK_FLAGS}; "
    "if [ -f /var/run/reboot-required ]; then echo REBOOT-REQUIRED; "
    "cat /var/run/reboot-required.pkgs 2>/dev/null; fi; "
    f"echo {MARK_NEEDRESTART}; "
    "if command -v needrestart >/dev/null 2>&1; then needrestart -b 2>/dev/null; "
    "else echo NO-NEEDRESTART; fi; "
    f"echo {MARK_NEEDS_RESTARTING}; "
    "if command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r >/dev/null 2>&1; "
    "echo NEEDSRC=$?; else echo NO-NEEDS-RESTARTING; fi"
)

#: needrestart's kernel codes: 1 is current, 2 a new kernel is installed, 3 the booted kernel differs.
KERNEL_STATE = {0: "unknown", 1: "current", 2: "reboot-owed", 3: "reboot-owed"}


def parse(text: str) -> dict:
    """Split the three sections and read each one. Never raises."""
    state = {"reboot_required": None, "reboot_packages": [], "services": [],
             "kernel_state": None, "needrestart": "unavailable", "needs_restarting": "unavailable",
             "outcome": "unavailable"}
    sections = {"flags": [], "nr": [], "nrs": []}
    current = None
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped == MARK_FLAGS:
            current = "flags"
            continue
        if stripped == MARK_NEEDRESTART:
            current = "nr"
            continue
        if stripped == MARK_NEEDS_RESTARTING:
            current = "nrs"
            continue
        if current:
            sections[current].append(stripped)

    flags = [line for line in sections["flags"] if line]
    if "REBOOT-REQUIRED" in flags:
        state["reboot_required"] = True
        state["reboot_packages"] = [line for line in flags
                                    if line != "REBOOT-REQUIRED" and not line.startswith("/")][:20]
        state["outcome"] = "ok"

    for line in sections["nr"]:
        if line.startswith("NEEDRESTART-KSTA:"):
            try:
                code = int(line.split(":", 1)[1].strip())
            except ValueError:
                continue
            state["kernel_state"] = KERNEL_STATE.get(code, f"code-{code}")
            state["needrestart"] = "ok"
            state["outcome"] = "ok"
            if state["kernel_state"] == "reboot-owed":
                state["reboot_required"] = True
        elif line.startswith("NEEDRESTART-SVC:"):
            service = line.split(":", 1)[1].strip()
            if service and service not in state["services"]:
                state["services"].append(service)

    for line in sections["nrs"]:
        match = re.match(r"NEEDSRC=(\d+)", line)
        if not match:
            continue
        state["needs_restarting"] = "ok"
        state["outcome"] = "ok"
        if match.group(1) == "1":
            state["reboot_required"] = True
    return state


def collect(target: str | None, timeout: int = 60) -> dict:
    """Read the three signals on one host. A host that answers nothing is `unavailable`."""
    from . import shell

    code, out = shell.run(PROBE, target, timeout=timeout, path_prefix=shell.SYSTEM_PATH_PREFIX)
    state = parse(out)
    if state["outcome"] == "unavailable":
        state["why"] = (f"neither reboot-required nor needrestart nor needs-restarting answered "
                        f"(rc={code}) — whether a patch is in effect is unmeasured here")
    elif state["reboot_required"] is None:
        state["reboot_required"] = False
    state["runs_as"] = "the account the plugin runs as"
    if state["needrestart"] == "ok" and not state["services"]:
        state["services_note"] = ("needrestart saw no service to restart; it inspects processes, so a "
                                  "non-root reading may see fewer")
    return state
