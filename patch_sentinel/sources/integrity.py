"""Is what is installed still what was installed?

Patch state answers "is there a newer version". It cannot answer "has someone changed this box", because
an intrusion does not move a version number: it replaces a binary, preloads a library, adds a key, opens
a port. Three readings cover the cheap, high-signal half of that question, and all three are honest about
what they cannot see:

* **tamper** — `dpkg -V`, `rpm -Va`, `apk audit`: every package-managed file whose content no longer
  matches the checksum its package shipped. Files flagged `c` are conffiles, which are *meant* to be
  edited, so they are counted apart and never reported as tampering.
* **preload hook** — `/etc/ld.so.preload` is non-empty. Almost nothing legitimate uses it, and it is the
  first thing an injected library needs.
* **listeners** — the set of listening sockets, compared with the set this plugin recorded last time. A
  new port is the door an intrusion needs; it is also how a developer's `python -m http.server` looks, so
  the finding says "not in the baseline" and names it, rather than accusing.

What none of this can see: a rootkit that hides from `ss`/`dpkg`, a fileless attack, a kernel compromise,
anything that tampered and then restored the checksums. The verdict therefore never says "not
compromised" — it says **no evidence of tampering in the surfaces that were read**, and names the
surfaces. That sentence is the whole point of the section.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from . import shell

MARK_DB = "--ps-db--"
MARK_PRELOAD = "--ps-preload--"
MARK_LISTEN = "--ps-listen--"
MARK_TAMPER = "--ps-tamper--"
MARK_END = "--ps-end--"

#: One round trip. `head` bounds each section so a host with 4 000 changed files cannot flood the call.
PROBE = (
    "echo " + MARK_DB + "; "
    "echo WHOAMI=$(id -un 2>/dev/null) UID=$(id -u 2>/dev/null); "
    "for t in dpkg rpm apk; do command -v $t >/dev/null 2>&1 && echo HAVE-$t; done; "
    "echo " + MARK_PRELOAD + "; "
    "if [ -s /etc/ld.so.preload ]; then cat /etc/ld.so.preload; else echo NO-PRELOAD; fi; "
    "echo " + MARK_LISTEN + "; "
    "(ss -lntuH 2>/dev/null || ss -lntu 2>/dev/null || netstat -lntu 2>/dev/null) | head -300; "
    "echo " + MARK_TAMPER + "; "
    "if command -v dpkg >/dev/null 2>&1; then dpkg -V 2>/dev/null | head -400; "
    "elif command -v rpm >/dev/null 2>&1; then rpm -Va 2>/dev/null | head -400; "
    "elif command -v apk >/dev/null 2>&1; then apk audit --system 2>/dev/null | head -400; "
    "else echo NO-PACKAGE-DB; fi; "
    "echo " + MARK_END
)

PRIVATE_DIRS = ("/etc/", "/root/", "/usr/sbin/", "/usr/bin/", "/boot/")

#: The whole set needs the account that can read every packaged file. The pane is one process and does
#: not elevate, so it hands the command over rather than claiming a reading it could not take.
FULL_COMMAND = {"dpkg -V": "sudo dpkg -V", "rpm -Va": "sudo rpm -Va",
                "apk audit": "sudo apk audit --system"}

#: A conffile is marked `c` by dpkg/rpm: it is expected to differ after an operator edits it.
CONFFILE = re.compile(r"^(\S+)\s+c?\s*(/.*)$")


def _section(text: str, mark: str, next_mark: str) -> list[str]:
    out, inside = [], False
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped == mark:
            inside = True
            continue
        if stripped == next_mark:
            inside = False
            continue
        if inside:
            out.append(line.rstrip())
    return out


def parse_listeners(lines: list[str]) -> list[str]:
    """`tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(...)` → `tcp:22`.

    The address is reduced to the port on purpose: a baseline that broke when the machine moved from
    `0.0.0.0` to `127.0.0.1` would report a finding for every service after any config change.
    """
    seen = set()
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        # `ss` puts the local address in a different column than `netstat`, and `-H` only removes the
        # header: take the first token that ends in `:port` after the protocol, which is the local
        # address in both tools (`udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*`, `ss` spaces collapsed).
        match = re.search(r"(\S+):(\d+)(?:\s|$)", line[len(parts[0]):])
        if not match:
            continue
        port = match.group(2)
        if not port.isdigit():
            continue
        seen.add(("tcp" if proto.startswith("tcp") else "udp") + ":" + port)
    return sorted(seen, key=lambda s: (s.split(":")[0], int(s.split(":")[1])))


def parse_dpkg(lines: list[str]) -> dict:
    """`??5?????? c /etc/ssh/sshd_config` → changed files, conffiles counted apart."""
    changed, conffiles, unreadable, missing = [], [], [], []
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        flags = parts[0]
        conffile = len(parts) >= 3 and parts[1] == "c"
        # the path is the token that starts with '/', not the last one: a permission note follows it
        # (`missing     /var/cache/cups/rss (Permission denied)`), and reading parts[-1] named `denied)`
        path = next((token for token in parts[1:] if token.startswith("/")), "")
        if not path:
            continue
        # `dpkg -V` writes `?????????` when it *could not read* the file (every slot unknown), and
        # `5` in the md5 slot when the content genuinely differs. Counting the first as tampering is
        # how a non-root scan produces eleven "modified" kernel images on a healthy machine.
        if set(flags) == {"?"}:
            unreadable.append(path)
            continue
        if flags == "missing":
            if "Permission denied" in line:
                unreadable.append(path)
            else:
                missing.append(path)
            continue
        if "5" in flags:
            (conffiles if conffile else changed).append(path)
        elif conffile:
            conffiles.append(path)
    return {"changed": changed, "conffiles": conffiles, "unreadable": unreadable,
            "missing": missing, "tool": "dpkg -V"}


def parse_rpm(lines: list[str]) -> dict:
    """`S.5....T.  c /etc/foo` → the '5' slot is a digest mismatch; 'T' alone is an mtime, which lies."""
    changed, conffiles, unreadable = [], [], []
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        flags = parts[0]
        path = next((token for token in parts[1:] if token.startswith("/")), "")
        if not path:
            continue
        conffile = len(parts) >= 3 and parts[1] == "c"
        if conffile:
            conffiles.append(path)
            continue
        if "5" in flags:
            changed.append(path)
        elif "missing" in line or not os.path.exists(path) and "?" in flags:
            unreadable.append(path)
    return {"changed": changed, "conffiles": conffiles, "unreadable": unreadable,
            "missing": [], "tool": "rpm -Va"}


def parse_apk(lines: list[str]) -> dict:
    """`apk audit` prints one path per line for a file that no longer matches its package."""
    changed = [l.strip() for l in lines if l.strip().startswith("/")]
    return {"changed": changed, "conffiles": [], "unreadable": [], "missing": [],
            "tool": "apk audit"}


def _read_baseline(data_dir: str, host: str) -> dict | None:
    try:
        payload = json.loads((Path(data_dir or ".") / "integrity.json").read_text())
    except (OSError, ValueError):
        return None
    record = (payload or {}).get("hosts", {}).get(str(host).lower())
    return record if isinstance(record, dict) else None


def write_baseline(data_dir: str, host: str, listeners: list[str]) -> dict:
    """Record the current listening set. Called on the first scan, and by an explicit re-baseline."""
    path = Path(data_dir or ".") / "integrity.json"
    try:
        payload = json.loads(path.read_text())
        if not isinstance(payload.get("hosts"), dict):
            payload["hosts"] = {}
    except (OSError, ValueError):
        payload = {"hosts": {}}
    record = {"listeners": sorted(listeners), "at": time.time(), "count": len(listeners)}
    payload["hosts"][str(host).lower()] = record
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return record


def parse(text: str, host: str, data_dir: str) -> dict:
    """Read the probe. Every section is either measured or says why it is not."""
    db = _section(text, MARK_DB, MARK_PRELOAD)
    who = " ".join(db)
    account = re.search(r"WHOAMI=(\S+)", who)
    uid_zero = "UID=0" in who
    tools = {name for name in ("dpkg", "rpm", "apk") if f"HAVE-{name}" in who}

    preload_lines = [l for l in _section(text, MARK_PRELOAD, MARK_LISTEN) if l.strip()]
    has_preload = not (len(preload_lines) == 1 and preload_lines[0].strip() == "NO-PRELOAD")
    preload_entries = [l.split()[0] for l in preload_lines if l.strip() and "NO-PRELOAD" not in l]

    listeners = parse_listeners(_section(text, MARK_LISTEN, MARK_TAMPER))
    tamper_raw = _section(text, MARK_TAMPER, MARK_END)

    if "dpkg" in tools:
        tamper = parse_dpkg(tamper_raw)
    elif "rpm" in tools:
        tamper = parse_rpm(tamper_raw)
    elif "apk" in tools:
        tamper = parse_apk(tamper_raw)
    else:
        tamper = {"changed": [], "conffiles": [], "tool": None}

    changed = tamper.get("changed") or []
    missing = tamper.get("missing") or []
    unreadable = tamper.get("unreadable") or []
    if not tools:
        tamper_state, tamper_reason = "unmeasured", (
            "no package database on this host (dpkg, rpm, apk) — the content of installed files "
            "cannot be compared with what was shipped, so this surface is not measured")
    elif changed or missing:
        tamper_state, tamper_reason = "finding", ""
    else:
        tamper_state, tamper_reason = "ok", ""

    who = account.group(1) if account else "this account"
    command = FULL_COMMAND.get(tamper.get("tool") or "", "")
    note = ""
    if unreadable:
        # the pane cannot elevate, so "run it as root" is not something it can do — it hands over the
        # exact command instead, the same way APPLY hands over its commands when sudo has no NOPASSWD
        # complete and standalone: the model relays this sentence, and the pane renders the part
        # between backticks as the command to run
        note = (f"{who}: {len(unreadable)} packaged file(s) could not be read, so this check cannot "
                f"see them. The pane runs as {who} and does not elevate — run `{command}` on that host "
                f"to cover them, or scan a host you reach as root over SSH.")

    baseline = _read_baseline(data_dir, host)
    if not listeners:
        listen_state = "unmeasured"
        listen_reason = "no listening sockets were listed — `ss`/`netstat` unavailable or refused"
        new_ports = []
    elif baseline is None:
        record = write_baseline(data_dir, host, listeners)
        listen_state = "baseline"
        listen_reason = (f"baseline recorded now with {len(listeners)} socket(s) — the next scan "
                         f"compares against it, so a port that opens later is visible")
        new_ports = []
        baseline = record
    else:
        known = set(baseline.get("listeners") or [])
        new_ports = [p for p in listeners if p not in known]
        listen_state = "finding" if new_ports else "ok"
        listen_reason = ""

    preload_state = "finding" if has_preload else "ok"

    states = [tamper_state, listen_state, preload_state]
    if "finding" in states:
        state = "finding"
    elif all(s in ("ok", "baseline") for s in states):
        state = "ok"
    else:
        state = "unmeasured"

    return {
        "state": state,
        "note": note,
        "account": account.group(1) if account else None,
        "root": uid_zero,
        "tamper": {"state": tamper_state, "reason": tamper_reason, "tool": tamper["tool"],
                   "command": command,
                   "changed_count": len(changed), "conffile_count": len(tamper.get("conffiles") or []),
                   "missing_count": len(missing), "unreadable_count": len(unreadable),
                   "changed": (changed + missing)[:12], "conffiles": (tamper.get("conffiles") or [])[:6],
                   "unreadable": unreadable[:6]},
        "preload": {"state": preload_state, "path": "/etc/ld.so.preload",
                    "entries": preload_entries[:6],
                    "reason": ("a preloaded library is the first thing an injected library needs — "
                               "it is read at every process start") if has_preload else ""},
        "listeners": {"state": listen_state, "reason": listen_reason,
                      "count": len(listeners), "new": new_ports[:12], "set": listeners[:200],
                      "baseline_at": (baseline or {}).get("at"),
                      "baseline_count": (baseline or {}).get("count")},
    }


def collect(target: str | None, data_dir: str, host: str, timeout: int = 120) -> dict:
    """Run the probe on a host and read it. Never raises: a host that cannot answer says so."""
    code, out = shell.run(PROBE, target, timeout=timeout)
    if code == 124:
        return {"state": "unmeasured", "reason": "the host did not answer within the timeout — "
                                                 "integrity is unmeasured here, not clean"}
    if not out.strip():
        return {"state": "unmeasured",
                "reason": f"the probe returned nothing (exit {code}) — integrity is unmeasured here"}
    try:
        return parse(out, host, data_dir)
    except Exception as err:  # a parser bug must not become a green tick
        return {"state": "unmeasured", "reason": f"the probe output could not be read: {err}"}


def save_result(data_dir: str, host: str, state: dict) -> dict:
    """Keep the last reading, so the pane can show it without paying 40 seconds again."""
    path = Path(data_dir or ".") / "integrity.json"
    try:
        payload = json.loads(path.read_text())
        if not isinstance(payload.get("hosts"), dict):
            payload["hosts"] = {}
    except (OSError, ValueError):
        payload = {"hosts": {}}
    payload["hosts"].setdefault(str(host).lower(), {})
    payload["hosts"][str(host).lower()]["last"] = {"at": time.time(), "state": state}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return {"at": time.time(), "state": state}


def read_result(data_dir: str, host: str) -> dict | None:
    """The last reading, with the time it was taken — an old reading is labelled old, never hidden."""
    try:
        payload = json.loads((Path(data_dir or ".") / "integrity.json").read_text())
    except (OSError, ValueError):
        return None
    record = ((payload or {}).get("hosts", {}).get(str(host).lower()) or {}).get("last")
    return record if isinstance(record, dict) else None


def summarise(state: dict) -> str:
    """One sentence, in the order that matters: tampering, then listeners, then the hook."""
    if not state or state.get("state") == "unmeasured":
        return "integrity: not measured — " + str((state or {}).get("reason") or "no reason given")
    tamper, listen, preload = state.get("tamper", {}), state.get("listeners", {}), state.get("preload", {})
    if tamper.get("state") == "finding":
        count = tamper.get("changed_count", 0) + tamper.get("missing_count", 0)
        first = (tamper.get("changed") or ["?"])[0]
        main = (f"integrity: {count} package-managed file(s) no longer match (or are gone) — "
                f"first: {first}")
    elif preload.get("state") == "finding":
        main = ("integrity: /etc/ld.so.preload is not empty ("
                + ", ".join(preload.get("entries") or []) + ") — a preloaded library runs in every "
                "process; that is a hook, not a normal setting")
    elif listen.get("state") == "finding":
        main = ("integrity: " + str(len(listen.get("new") or [])) + " listening socket(s) not in the "
                "baseline — " + ", ".join(listen.get("new") or []))
    else:
        main = ("integrity: no evidence of tampering in the surfaces read (package checksums, "
                "preload hook, listening sockets)")
    # the state of the baseline is a fact about the reading, not a replacement for its verdict
    if listen.get("state") == "baseline" and listen.get("reason"):
        main += " · " + str(listen["reason"])
    # the note is not repeated here: the pane prints it once, next to the command that lifts it, and
    # the answer line is the sentence the model relays
    return main


def answers(state: dict) -> list[dict]:
    """The rows the pane and the summary line both read."""
    if not state:
        return []
    rows = []
    tamper, listen, preload = state.get("tamper", {}), state.get("listeners", {}), state.get("preload", {})
    rows.append({"check": "package checksums", "state": tamper.get("state"),
                 "detail": (f"{tamper.get('changed_count', 0)} file(s) changed"
                            + (f", {tamper.get('conffile_count')} conffile(s) edited by the operator"
                               if tamper.get("conffile_count") else "")
                            if tamper.get("state") != "unmeasured"
                            else tamper.get("reason") or ""),
                 "items": tamper.get("changed") or []})
    rows.append({"check": "preload hook", "state": preload.get("state"),
                 "detail": (", ".join(preload.get("entries") or [])
                            if preload.get("state") == "finding" else "/etc/ld.so.preload is empty"),
                 "items": []})
    rows.append({"check": "listening sockets", "state": listen.get("state"),
                 "detail": (listen.get("reason") or
                            (f"{len(listen.get('new') or [])} not in the baseline"
                             if listen.get("state") == "finding"
                             else f"{listen.get('count', 0)} socket(s), all in the baseline")),
                 "items": listen.get("new") or []})
    return rows
