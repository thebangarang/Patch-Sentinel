"""Which update pockets this host is actually subscribed to.

"There is an update but this machine does not get it" has two very different causes, and they used to
read the same in the pane:

* **the vendor has not published it** — vendor lag, a fact about the world;
* **this host is not configured for the pocket that carries it** — `-security` disabled, no
  `esm-apps`, `updates` repo switched off. A fact about the machine, and the one an operator can fix
  in a minute.

This module reads the configuration only: no `apt update`, no network, nothing enabled or disabled. A
host whose configuration cannot be read is `unavailable`, never "subscribed to nothing".
"""
from __future__ import annotations

import re

APT_FILES = ("cat /etc/apt/sources.list 2>/dev/null; "
             "cat /etc/apt/sources.list.d/*.list 2>/dev/null; "
             "cat /etc/apt/sources.list.d/*.sources 2>/dev/null")
RPM_REPOS = ("(dnf -q repolist --enabled 2>/dev/null || zypper -q lr 2>/dev/null) | head -60")

#: A pocket is identified by what the line says, not by what it should say.
POCKETS = {
    "security": (re.compile(r"-security|security\.debian\.org|esm-apps|esm-infra|esm\.ubuntu\.com|"
                            r"\bsecurity\b", re.I)),
    "updates": (re.compile(r"-updates|-update\b|esm-apps|\bupdates\b|update repo", re.I)),
    "backports": (re.compile(r"-backports|backports", re.I)),
    "proposed": (re.compile(r"-proposed|proposed-updates", re.I)),
}


def parse_apt(text: str) -> dict:
    enabled = {name: False for name in POCKETS}
    lines = [line.strip() for line in (text or "").splitlines()]
    for index, line in enumerate(lines):
        if not line or line.startswith("#") or line.startswith("deb-src"):
            continue
        if line.startswith("deb ") or line.startswith("deb\t"):
            for pocket, pattern in POCKETS.items():
                if pattern.search(line):
                    enabled[pocket] = True
        elif line.lower().startswith("uris:") or line.lower().startswith("suites:"):
            # deb822: the suite names the pocket ("resolute-security")
            if "Disabled:" in text and "Disabled: yes" in text:
                pass
            for pocket, pattern in POCKETS.items():
                if pattern.search(line):
                    enabled[pocket] = True
        elif line.lower().startswith("enabled:") and line.lower().endswith("no"):
            continue
    return enabled


def parse_repos(text: str) -> dict:
    enabled = {name: False for name in POCKETS}
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("repo id", "Repo-id", "#", "—")):
            continue
        low = stripped.lower()
        for pocket, pattern in POCKETS.items():
            if pattern.search(low):
                enabled[pocket] = True
    return enabled


def collect(target: str | None, family: str, timeout: int = 60) -> dict:
    """``{"pockets": {...}, "outcome": "ok"|"unavailable", "why": ...}`` for one host."""
    from . import shell

    if family in ("dnf", "zypper", "pacman"):
        command, parser = RPM_REPOS, parse_repos
    else:
        command, parser = APT_FILES, parse_apt
    code, out = shell.run(command, target, timeout=timeout, path_prefix=shell.SYSTEM_PATH_PREFIX)
    if not (out or "").strip():
        return {"pockets": {}, "outcome": "unavailable",
                "why": f"the package sources could not be read (rc={code}) — whether this host is "
                       f"subscribed to the pocket that carries the fix is unmeasured"}
    pockets = parser(out)
    note = ""
    if not pockets.get("security"):
        note = ("no security pocket is enabled on this host: a fix the vendor published may simply "
                "not be delivered here, which is a configuration fact, not a vendor delay")
    return {"pockets": pockets, "outcome": "ok", "note": note}
