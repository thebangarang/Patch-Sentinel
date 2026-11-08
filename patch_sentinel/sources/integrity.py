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
MARK_PROC = "--ps-proc--"
MARK_TAMPER = "--ps-tamper--"
MARK_END = "--ps-end--"

#: One round trip. `head` bounds each section so a host with 4 000 changed files cannot flood the call.
PROBE = (
    "echo " + MARK_DB + "; "
    "echo WHOAMI=$(id -un 2>/dev/null) UID=$(id -u 2>/dev/null); "
    "for t in dpkg rpm apk pacman; do command -v $t >/dev/null 2>&1 && echo HAVE-$t; done; "
    "echo " + MARK_PRELOAD + "; "
    "if [ -s /etc/ld.so.preload ]; then cat /etc/ld.so.preload; else echo NO-PRELOAD; fi; "
    "echo " + MARK_LISTEN + "; "
    "cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null; "
    "(ss -lntupH 2>/dev/null || ss -lntup 2>/dev/null || ss -lntuH 2>/dev/null "
    "|| netstat -lntup 2>/dev/null) | head -300; "
    # pid → command line, so a socket the operator did not expect can name the program that holds it
    "echo " + MARK_PROC + "; "
    "ps -eo pid=,args= 2>/dev/null | cut -c1-140 | head -400; "
    "echo " + MARK_TAMPER + "; "
    "if command -v dpkg >/dev/null 2>&1; then dpkg -V 2>/dev/null | head -400; "
    "elif command -v rpm >/dev/null 2>&1; then rpm -Va 2>/dev/null | head -400; "
    "elif command -v apk >/dev/null 2>&1; then apk audit --system 2>/dev/null | head -400; "
    "elif command -v pacman >/dev/null 2>&1; then pacman -Qkk 2>&1 | head -400; "
    "else echo NO-PACKAGE-DB; fi; "
    "echo " + MARK_END
)

PRIVATE_DIRS = ("/etc/", "/root/", "/usr/sbin/", "/usr/bin/", "/boot/")

#: The whole set needs the account that can read every packaged file. The pane is one process and does
#: not elevate, so it hands the command over rather than claiming a reading it could not take.
#: The full reading needs the account that can read every packaged file. The pane is one process and
#: does not elevate, so it hands the command over rather than claiming a reading it could not take.
#: One elevation prefix, in one place — a scanner (and a reader) should see a single elevation site.
ELEVATE = "sudo {}"
FULL_COMMAND = {name: ELEVATE.format(command) for name, command in {
    "dpkg -V": "dpkg -V", "rpm -Va": "rpm -Va",
    "apk audit": "apk audit --system", "pacman -Qkk": "pacman -Qkk"}.items()}

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


DEFAULT_EPHEMERAL = (32768, 60999)

#: Paths the packaging system empties on purpose: apt cleans its cache, logs rotate, lists are rebuilt.
#: `dpkg -V` reports them as `missing`, and counting that as tampering is how a fresh Debian accused
#: itself of four deleted files that no package ever promised to keep.
VOLATILE = ("/var/cache/", "/var/log/", "/var/lib/apt/lists/", "/var/lib/dpkg/info/",
            "/var/lib/systemd/", "/run/", "/tmp/", "/var/tmp/")


def read_listeners(lines: list[str]) -> list[dict]:
    """`tcp LISTEN 0 128 127.0.0.1:48997 0.0.0.0:* users:(("hermes",pid=1,fd=7))` → one record.

    Three facts per socket, because a port alone cannot be judged:

    * **id** — `tcp:22`, the identity the baseline compares;
    * **scope** — `loopback` or `any`. A socket on `0.0.0.0`/`::` is reachable from the network and is a
      door; one on `127.0.0.1` is only for this machine. That difference is the whole difference
      between "someone opened a service" and "a local process found a free port";
    * **owner** — the process name when this account is allowed to see it. It turns "tcp:4444" into
      "tcp:4444 · python", which is the difference between a mystery and a decision.
    """
    records: dict[str, dict] = {}
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
        address, port_text = match.group(1), match.group(2)
        if not port_text.isdigit():
            continue
        port = int(port_text)
        owner = re.search(r'users:\(\("([^"]+)"(?:,pid=(\d+))?', line)
        loopback = (address.startswith("127.") or address in ("::1", "[::1]", "::1%lo")
                    or "%lo" in address or address.startswith("[::ffff:127."))
        key = ("tcp" if proto.startswith("tcp") else "udp") + ":" + str(port)
        records[key] = {"id": key, "proto": key.split(":")[0], "port": port, "address": address,
                        "scope": "loopback" if loopback else "any",
                        "owner": owner.group(1) if owner else None,
                        "pid": int(owner.group(2)) if owner and owner.group(2) else None}
    return sorted(records.values(), key=lambda r: (r["proto"], r["port"]))


def parse_listeners(lines: list[str]) -> list[str]:
    """The ids only — kept for the baseline, which compares identities, not addresses."""
    return [record["id"] for record in read_listeners(lines)]


def ephemeral_range(text: str) -> tuple[int, int]:
    """`32768\t60999` from /proc — the ports a machine hands out for a few seconds at a time."""
    match = re.search(r"(\d{2,5})\s+(\d{2,5})", text or "")
    if not match:
        return DEFAULT_EPHEMERAL
    low, high = int(match.group(1)), int(match.group(2))
    return (low, high) if low < high else DEFAULT_EPHEMERAL


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


def parse_pacman(lines: list[str]) -> dict:
    """`pacman -Qkk` → changed files, with the three reasons that are not tampering kept apart.

    Arch prefixes the two kinds differently, which is the whole trick:

    * `backup file: filesystem: /etc/group (SHA256 checksum mismatch)` — a **conffile** pacman's
      package marks as `backup`. It is *meant* to differ; every image build changes fstab, group,
      shadow. Counted apart, never called tampering.
    * `warning: audit: /etc/libaudit.conf (failed to calculate SHA256 checksum)` — the file could not
      be read by this account. Unreadable, not changed.
    * `warning: x: /usr/bin/y (Size mismatch)` / `(SHA256 checksum mismatch)` — a packaged file whose
      content no longer matches. That is the finding.
    """
    changed, conffiles, unreadable = set(), set(), set()
    for line in lines:
        text = line.strip()
        match = re.search(r"(/\S+)\s*\(([^)]*)\)$", text)
        if not match:
            continue
        where, reason = match.group(1), match.group(2).lower()
        if "failed to calculate" in reason or "permission denied" in reason:
            unreadable.add(where)
        elif text.startswith("backup file:"):
            conffiles.add(where)
        elif ("modification time" in reason or "file type mismatch" in reason
              or "uid mismatch" in reason or "gid mismatch" in reason):
            conffiles.add(where)      # rebuilt timestamps, and the symlink drift /etc/resolv.conf has
        elif "size mismatch" in reason or "checksum mismatch" in reason:
            changed.add(where)
    return {"changed": sorted(changed - conffiles), "conffiles": sorted(conffiles),
            "unreadable": sorted(unreadable), "missing": [], "tool": "pacman -Qkk"}


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


def write_baseline(data_dir: str, host: str, listeners) -> dict:
    """Record the current listening set. Called on the first read, and by an explicit re-baseline.

    Accepts socket records or bare ids. The scope is stored with each id: without it, a service that
    moved from `127.0.0.1` to `0.0.0.0` keeps the same id and the change is invisible.
    """
    if listeners and isinstance(listeners[0], dict):
        ids = [item["id"] for item in listeners]
        scopes = {item["id"]: item.get("scope") or "any" for item in listeners}
    else:
        ids = list(listeners)
        scopes = {key: "any" for key in ids}
    path = Path(data_dir or ".") / "integrity.json"
    try:
        payload = json.loads(path.read_text())
        # a file that parses but is not an object (a list, a bare string) must not become an
        # AttributeError halfway through a write
        if not isinstance(payload, dict):
            payload = {}
        if not isinstance(payload.get("hosts"), dict):
            payload["hosts"] = {}
    except (OSError, ValueError):
        payload = {"hosts": {}}
    record = {"listeners": sorted(ids), "scopes": scopes, "at": time.time(), "count": len(ids)}
    payload["hosts"][str(host).lower()] = record
    _store(path, payload)
    return record


def parse(text: str, host: str, data_dir: str) -> dict:
    """Read the probe. Every section is either measured or says why it is not."""
    db = _section(text, MARK_DB, MARK_PRELOAD)
    who = " ".join(db)
    account = re.search(r"WHOAMI=(\S+)", who)
    uid_zero = "UID=0" in who
    tools = {name for name in ("dpkg", "rpm", "apk", "pacman") if f"HAVE-{name}" in who}

    preload_lines = [l for l in _section(text, MARK_PRELOAD, MARK_LISTEN) if l.strip()]
    has_preload = not (len(preload_lines) == 1 and preload_lines[0].strip() == "NO-PRELOAD")
    preload_entries = [l.split()[0] for l in preload_lines if l.strip() and "NO-PRELOAD" not in l]

    listen_lines = _section(text, MARK_LISTEN, MARK_PROC)
    processes = {}
    for line in _section(text, MARK_PROC, MARK_TAMPER):
        head, _, cmd = line.strip().partition(" ")
        if head.isdigit():
            processes[int(head)] = cmd.strip()
    range_lines = [l for l in listen_lines if re.fullmatch(r"\s*\d{2,5}\s+\d{2,5}\s*", l)]
    ephemeral = ephemeral_range(range_lines[0] if range_lines else "")
    sockets = read_listeners([l for l in listen_lines if l not in range_lines])
    listeners = [s["id"] for s in sockets]
    tamper_raw = _section(text, MARK_TAMPER, MARK_END)

    if "dpkg" in tools:
        tamper = parse_dpkg(tamper_raw)
    elif "rpm" in tools:
        tamper = parse_rpm(tamper_raw)
    elif "apk" in tools:
        tamper = parse_apk(tamper_raw)
    elif "pacman" in tools:
        tamper = parse_pacman(tamper_raw)
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
        note = (f"{who}: {len(unreadable)} packaged file(s) could not be verified, so this check "
                f"cannot see them. The pane runs as {who} and does not elevate — run `{command}` on "
                f"that host to cover them, or scan a host you reach as root over SSH.")

    baseline = _read_baseline(data_dir, host)
    exposed, stable_new, drift, widened = [], [], [], []
    if not sockets:
        listen_state = "unmeasured"
        listen_reason = "no listening sockets were listed — `ss`/`netstat` unavailable or refused"
    elif baseline is None:
        record = write_baseline(data_dir, host, sockets)
        listen_state = "baseline"
        listen_reason = (f"baseline recorded now with {len(sockets)} socket(s) — the next read "
                         f"compares against it, so a socket that opens later is visible")
        baseline = record
    else:
        known = set(baseline.get("listeners") or [])
        scopes = baseline.get("scopes") or {}
        fresh = [s for s in sockets if s["id"] not in known]
        # A socket reachable from the network is a door; a loopback socket on a port the kernel hands
        # out for seconds at a time is a process finding a free port (the agent's own port, a browser's
        # QUIC socket). Calling the second a finding is how a security panel teaches people to ignore
        # it — so it is reported, counted, and not raised as a finding.
        exposed = [s for s in fresh
                   if s["port"] < 1024 or (s["scope"] == "any" and s["proto"] == "tcp")]
        # A UDP socket bound to 0.0.0.0 on an ephemeral port is what a *client* does when it registers
        # for a reply: QEMU's user-mode DNS, a browser's STUN, mDNS. They close within seconds, and
        # calling them "reachable from the network" is how the operator's own lab VM turned into three
        # phantom findings. They are reported as churn with their owner, and a TCP listen on 0.0.0.0
        # — a real service — is always a finding.
        ephemeral_drift = [s for s in fresh if ephemeral[0] <= s["port"] <= ephemeral[1]]
        drift = [s for s in ephemeral_drift if s not in exposed]
        stable_new = [s for s in fresh if s not in exposed and s not in drift]
        # the same port, now reachable from outside: the change that matters most, and it is not a
        # new id, so it would slip through a diff that compared ids only
        widened = [s for s in sockets
                   if s["id"] in known and scopes.get(s["id"]) == "loopback" and s["scope"] == "any"]
        listen_state = "finding" if (exposed or stable_new or widened) else "ok"
        listen_reason = ""
    new_ports = [s["id"] for s in (exposed + stable_new + widened)]
    drift_ports = [s["id"] for s in drift]

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
                   "missing_count": len(missing), "missing": missing[:20],
                   "unreadable_count": len(unreadable),
                   "changed": (changed + missing)[:12], "conffiles": (tamper.get("conffiles") or [])[:6],
                   "unreadable": unreadable[:6]},
        "preload": {"state": preload_state, "path": "/etc/ld.so.preload",
                    "entries": preload_entries[:6],
                    "reason": ("a preloaded library is the first thing an injected library needs — "
                               "it is read at every process start") if has_preload else ""},
        "listeners": {
            "state": listen_state, "reason": listen_reason,
            "count": len(sockets), "new": new_ports[:12], "set": listeners[:200],
            "records": sockets[:200],
            "baseline_at": (baseline or {}).get("at"),
            "baseline_count": (baseline or {}).get("count"),
            # three buckets, because they mean three different things to the person reading them
            "exposed": [_describe(s, processes) for s in exposed[:12]],
            "stable": [_describe(s, processes) for s in stable_new[:12]],
            "widened": [_describe(s, processes) for s in widened[:12]],
            "drift": [_describe(s, processes) for s in drift[:12]],
            "drift_count": len(drift),
            "drift_public": [d["id"] for d in
                             [_describe(s, processes) for s in drift] if d["address"] in ("0.0.0.0", "[::]")],
            "ephemeral_range": list(ephemeral),
        },
        # the last root run the operator pasted, with its own timestamp — it survives new readings
        "root_coverage": read_root_coverage(data_dir, host),
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
        state = parse(out, host, data_dir)
    except Exception as err:  # a parser bug must not become a green tick
        return {"state": "unmeasured", "reason": f"the probe output could not be read: {err}"}
    return _split_missing(state, target, timeout)


def _split_missing(state: dict, target: str | None, timeout: int) -> dict:
    """`dpkg -V` says `missing` for a directory it owns too — `/var/cache/apt/archives` on a cleaned
    Debian, `/var/lib/apt/lists/partial` everywhere. A directory that is not there is not tampering; a
    *file* that is not there is. One `test -d` per path settles it, and the reading stops contradicting
    itself ("4 files no longer match" next to "0 files changed")."""
    tamper = state.get("tamper") or {}
    paths = list(tamper.get("missing") or [])
    if not paths:
        return state
    volatile = [p for p in paths if p.startswith(VOLATILE)]
    paths = [p for p in paths if not p.startswith(VOLATILE)]
    tamper["missing_volatile"] = volatile[:20]
    tamper["missing_volatile_count"] = len(volatile)
    tamper["missing"] = paths
    tamper["missing_count"] = len(paths)
    if not paths:
        # nothing left outside the packaging system's own scratch space
        if not tamper.get("changed_count"):
            tamper["state"] = "ok"
        states = [tamper.get("state"), (state.get("listeners") or {}).get("state"),
                  (state.get("preload") or {}).get("state")]
        state["state"] = ("finding" if "finding" in states
                          else "ok" if all(s in ("ok", "baseline") for s in states) else "unmeasured")
        return state
    quoted = " ".join("'" + p.replace("'", "'\\''") + "'" for p in paths)
    command = (f"for p in {quoted}; do if [ -d \"$p\" ]; then echo DIR:$p; "
               f"else echo FILE:$p; fi; done")
    code, out = shell.run(command, target, timeout=timeout)
    if not out.strip():
        return state                     # the answer did not come; leave the finding as it was
    dirs = [line[4:] for line in out.splitlines() if line.startswith("DIR:")]
    files = [line[5:] for line in out.splitlines() if line.startswith("FILE:")]
    tamper["missing"] = files
    tamper["missing_count"] = len(files)
    tamper["missing_dirs"] = dirs[:20]
    tamper["missing_dir_count"] = len(dirs)
    if files:
        tamper["state"] = "finding"
        tamper["changed"] = (tamper.get("changed") or []) + files[:12]
    elif not tamper.get("changed_count"):
        tamper["state"] = "ok"
    states = [tamper.get("state"), (state.get("listeners") or {}).get("state"),
              (state.get("preload") or {}).get("state")]
    state["state"] = ("finding" if "finding" in states
                      else "ok" if all(s in ("ok", "baseline") for s in states) else "unmeasured")
    return state


PARSERS = {"dpkg -V": parse_dpkg, "rpm -Va": parse_rpm, "apk audit": parse_apk,
           "pacman -Qkk": parse_pacman}


def merge_pasted(state: dict, output: str, now: float | None = None,
                 data_dir: str | None = None, host: str | None = None) -> dict:
    """Take a reading the operator ran as root and paste-read it.

    The plugin cannot elevate, so the full set is one command away and out of its reach. Reading that
    output is still worth doing — and it is labelled for what it is: *pasted by the operator*, not
    measured by this process. A clean paste covers the files the plugin could not read; a paste that
    names changed files is a finding, because the evidence is right there.
    """
    tool = (state.get("tamper") or {}).get("tool")
    parser = PARSERS.get(tool or "")
    if parser is None:
        return {"ok": False,
                "reason": "this reading did not come from a package database this plugin knows, so a "
                          "pasted output cannot be placed against it"}
    text = str(output or "")
    if not text.strip():
        # an empty `dpkg -V` is the clean result; an empty *paste* is indistinguishable from it, and
        # saying so is better than accepting a blank as a clean host
        return {"ok": False,
                "reason": "the paste is empty — note that a clean `dpkg -V` also prints nothing, so "
                          "press paste only after a run that produced no lines at all"}
    parsed = parser([line for line in text.splitlines() if line.strip()])
    reading = {"at": now or time.time(), "tool": tool, "source": "pasted by the operator",
               "changed_count": len(parsed["changed"]), "conffile_count": len(parsed["conffiles"]),
               "unreadable_count": len(parsed.get("unreadable") or []),
               "changed": parsed["changed"][:20], "conffiles": parsed["conffiles"][:10]}
    state["root_reading"] = reading
    if data_dir and host:
        # kept apart from the reading it arrived with: a later non-root read must not erase the one
        # piece of evidence that covered the files this account cannot read
        save_root_coverage(data_dir, host, reading)
    tamper = state.setdefault("tamper", {})
    if parsed["changed"] or parsed.get("missing"):
        # a root run that names mismatches is evidence, and it outranks the limited reading
        tamper.update(state="finding", covered=False)
        tamper["changed_count"] = len(parsed["changed"]) + len(parsed.get("missing") or [])
        tamper["changed"] = (parsed["changed"] + (parsed.get("missing") or []))[:12]
        state["state"] = "finding"
    else:
        tamper["covered"] = True
        state["note"] = (
            f"coverage completed by a root reading pasted on "
            f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(reading['at']))}: "
            f"0 file(s) changed, {len(parsed['conffiles'])} conffile(s) edited by the operator. "
            f"That part of the reading was run by you, not by this plugin.")
    return {"ok": True, "root_reading": reading,
            "answer": (f"pasted root reading: {len(parsed['changed'])} file(s) changed, "
                       f"{len(parsed['conffiles'])} conffile(s) edited — "
                       + ("a finding" if parsed["changed"] else "coverage is complete"))}


def _describe(socket: dict, processes: dict) -> dict:
    """A socket plus what it is: the process name, its pid, and the command line that started it."""
    command = processes.get(socket.get("pid") or -1) if socket.get("pid") else None
    return {"id": socket["id"], "address": socket["address"], "owner": socket.get("owner"),
            "pid": socket.get("pid"), "command": (command or "")[:120] or None}


def _sockets(rows: list[dict]) -> str:
    """`tcp:4444 (python), tcp:8080` — the port and, when it is visible, who owns it."""
    names = []
    for row in rows[:3]:
        names.append(row["id"] + (f" ({row['owner']})" if row.get("owner") else ""))
    more = len(rows) - len(names)
    return ", ".join(names) + (f" and {more} more" if more > 0 else "")


class CannotStore(RuntimeError):
    """The data directory cannot be written — a reading taken here would be lost the moment it ended."""


def _store(path: Path, payload: dict) -> None:
    """Write atomically, and turn a filesystem refusal into one sentence the caller can report."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except OSError as exc:
        raise CannotStore(f"cannot write {path}: {exc.strerror or exc}") from exc


def save_root_coverage(data_dir: str, host: str, reading: dict) -> dict:
    """Keep the last root run the operator pasted, apart from the reading it arrived with."""
    path = Path(data_dir or ".") / "integrity.json"
    try:
        payload = json.loads(path.read_text())
        # a file that parses but is not an object (a list, a bare string) must not become an
        # AttributeError halfway through a write
        if not isinstance(payload, dict):
            payload = {}
        if not isinstance(payload.get("hosts"), dict):
            payload["hosts"] = {}
    except (OSError, ValueError):
        payload = {"hosts": {}}
    payload["hosts"].setdefault(str(host).lower(), {})["root"] = reading
    _store(path, payload)
    return reading


def read_root_coverage(data_dir: str, host: str) -> dict | None:
    try:
        payload = json.loads((Path(data_dir or ".") / "integrity.json").read_text())
    except (OSError, ValueError):
        return None
    record = ((payload or {}).get("hosts", {}).get(str(host).lower()) or {}).get("root")
    return record if isinstance(record, dict) else None


def save_result(data_dir: str, host: str, state: dict) -> dict:
    """Keep the last reading, so the pane can show it without paying 40 seconds again."""
    path = Path(data_dir or ".") / "integrity.json"
    try:
        payload = json.loads(path.read_text())
        # a file that parses but is not an object (a list, a bare string) must not become an
        # AttributeError halfway through a write
        if not isinstance(payload, dict):
            payload = {}
        if not isinstance(payload.get("hosts"), dict):
            payload["hosts"] = {}
    except (OSError, ValueError):
        payload = {"hosts": {}}
    payload["hosts"].setdefault(str(host).lower(), {})
    payload["hosts"][str(host).lower()]["last"] = {"at": time.time(), "state": state}
    _store(path, payload)
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
        parts = []
        if listen.get("exposed"):
            parts.append(_sockets(listen["exposed"]) + " reachable from the network")
        if listen.get("widened"):
            parts.append(_sockets(listen["widened"]) + " now reachable from the network, loopback before")
        if listen.get("stable"):
            parts.append(_sockets(listen["stable"]) + " on a local fixed port")
        main = "integrity: " + "; ".join(parts) + " — none of these were listening when the baseline " \
               "was taken"
    elif listen.get("drift_count"):
        main = ("integrity: no evidence of tampering in the surfaces read (package checksums, "
                "preload hook, listening sockets)")
    else:
        main = ("integrity: no evidence of tampering in the surfaces read (package checksums, "
                "preload hook, listening sockets)")
    # the state of the baseline is a fact about the reading, not a replacement for its verdict
    if listen.get("drift_count"):
        reach = len(listen.get("drift_public") or [])
        main += (f" · {listen['drift_count']} socket(s) on ephemeral ports "
                 f"({listen.get('ephemeral_range', ['?', '?'])[0]}–"
                 f"{listen.get('ephemeral_range', ['?', '?'])[1]}), "
                 + (f"{reach} of them bound to 0.0.0.0 as clients do — " if reach else "")
                 + "they close by themselves, not counted")
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
    def shaped(bucket: str) -> list[str]:
        return [row["id"] + " · " + ("reachable from the network" if row.get("address")
                                     in ("0.0.0.0", "[::]", "::", "*") else row.get("address", "?"))
                + (" · " + row["owner"] if row.get("owner") else "")
                for row in (listen.get(bucket) or [])]

    if listen.get("state") == "finding":
        bits = []
        if listen.get("exposed"):
            bits.append(str(len(listen["exposed"])) + " reachable from the network")
        if listen.get("widened"):
            bits.append(str(len(listen["widened"])) + " now reachable, loopback before")
        if listen.get("stable"):
            bits.append(str(len(listen["stable"])) + " on a local fixed port")
        if listen.get("drift_count"):
            bits.append(str(listen["drift_count"]) + " local churn ignored")
        detail = " · ".join(bits)
        first = (listen.get("exposed") or listen.get("stable") or listen.get("widened") or [{}])[0]
        port = str(first.get("id", "0").split(":")[-1])
        owner = first.get("owner")
        who = ""
        if first.get("command"):
            who = ("Held by " + (owner or "a process") + (f" (pid {first['pid']})" if first.get("pid") else "")
                   + ": `" + first["command"] + "`. ")
        elif owner:
            who = "Held by " + owner + ". "
        advice = (who + "If you did not start that, look closer — `sudo ss -lntup | grep -F ':" + port
                  + "'` names the program and its pid. If you did, re-baseline so these stop being new.")
        items = shaped("exposed") + shaped("widened") + shaped("stable")
    elif listen.get("state") == "baseline":
        detail = listen.get("reason") or ""
        advice = ""
        items = []
    elif listen.get("state") == "unmeasured":
        detail = listen.get("reason") or ""
        advice = ""
        items = []
    else:
        detail = f"{listen.get('count', 0)} socket(s), all in the baseline"
        if listen.get("drift_count"):
            detail += (f" · {listen['drift_count']} local socket(s) appeared on ephemeral ports and "
                       f"went away again — reported, not counted")
        advice = ""
        items = []
    rows.append({"check": "listening sockets", "state": listen.get("state"),
                 "detail": detail, "items": items, "advice": advice})
    return rows
