"""Why a server did not answer — one stage at a time, in the order ssh fails.

"the probe failed" is not a diagnosis. Adding a server is the first thing a user does with this plugin,
and each way it can fail has a different fix: a typo in the name, a host that is down, a key that was
never copied, a first connection whose host key nobody accepted, a shell that is not bash. This module
turns ssh's own message into the stage that failed and the exact command that unblocks it.

It runs the smallest possible command (``true``) with the same options the scan uses, so what it
reports is what the scan would hit — not an idealised check that passes while the scan fails.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from . import shell

SSH = shutil.which("ssh") or "ssh"
CONNECT_TIMEOUT = 8

#: (regex on ssh's stderr, stage, what to do next). Order matters: the first match wins.
SIGNATURES = [
    (r"could not resolve hostname|could not resolve", "dns",
     "the name does not resolve from this machine — check the spelling, or use the IP address"),
    (r"connection refused", "tcp",
     "nothing is listening on that port — is sshd running, and is the port right?"),
    (r"connection timed out|operation timed out|no route to host", "tcp",
     "the machine did not answer in 8 s — a firewall, or the host is down"),
    (r"permission denied \(publickey,password|permission denied \(keyboard-interactive",
     "auth",
     "that host wants a password, and this plugin never handles one: copy a key with the command "
     "below, or point the entry at an ssh alias that already uses a key"),
    (r"permission denied", "auth",
     "the host answered but rejected the key — append this machine's public key to the target's "
     "authorized_keys (the command is below)"),
    (r"host key verification failed", "hostkey",
     "this is the first connection to that host: accept its key once from a terminal, then test again"),
    (r"remote host identification has changed", "hostkey",
     "the host's key changed since you last connected — verify it before trusting the new one"),
    (r"no such file or directory|command not found|not found|syntax error", "shell",
     "the host has no /bin/bash — the probe needs a POSIX shell"),
]


def public_key() -> str:
    """The key a user should copy, as a ready-to-paste line. Never the private one.

    Looks for the conventional names first, then any ``*.pub``: a machine that only has a project key
    (this lab has ``id_ed25519_patchlab.pub``) still gets a usable command instead of a shrug.
    """
    ssh_dir = Path.home() / ".ssh"
    candidates = [ssh_dir / name for name in ("id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub")]
    candidates += sorted(ssh_dir.glob("*.pub")) if ssh_dir.is_dir() else []
    for candidate in candidates:
        try:
            text = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text.startswith(("ssh-", "ecdsa-")):
            return text
    return ""


def diagnose(target: str | None) -> dict:
    """Run one trivial command and report the stage, the reason and the next command to try.

    Returns ``{"ok": bool, "stage": str, "reason": str, "hint": str, "fix": str}``.
    ``fix`` is a paste-ready command when one exists, otherwise empty.
    """
    if not target:
        return {"ok": True, "stage": "local", "reason": "", "hint": "", "fix": ""}
    # the port lives in the target as `host:port`; ssh wants it as -p. Passing the target through
    # unchanged makes ssh read "127.0.0.1:2299" as a hostname and report a DNS failure — measured.
    host, port = shell.split_target(target)
    argv = [SSH, "-o", "BatchMode=yes", "-o", f"ConnectTimeout={CONNECT_TIMEOUT}"]
    if port:
        argv += ["-p", port]
    argv += [host, "true"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=CONNECT_TIMEOUT + 12)
    except subprocess.TimeoutExpired:
        return {"ok": False, "stage": "tcp", "reason": "the connection hung past the timeout",
                "hint": "a firewall is dropping the packets, or the host is unreachable",
                "fix": f"ssh {target}"}
    if proc.returncode == 0:
        return {"ok": True, "stage": "ok", "reason": "", "hint": "", "fix": ""}

    text = (proc.stderr or proc.stdout or "").strip()
    lowered = text.lower()
    for pattern, stage, hint in SIGNATURES:
        if re.search(pattern, lowered):
            return {"ok": False, "stage": stage, "reason": text.splitlines()[0][:200] if text else "",
                    "hint": hint, "fix": _fix_for(stage, target)}
    return {"ok": False, "stage": "unknown", "reason": text[:200], "hint":
            "ssh refused without a message this plugin recognises", "fix": f"ssh -v {target}"}


def _fix_for(stage: str, target: str) -> str:
    """The command that unblocks that stage, when there is one."""
    user_host = target.split()[0] if target else ""
    port = ""
    host, sep, tail = user_host.rpartition(":")
    if sep and tail.isdigit():
        user_host, port = host, tail
    port_flag = f" -p {port}" if port else ""
    key = public_key()
    if stage == "auth":
        if key:
            return f"ssh-copy-id -i ~/.ssh/{_key_name()}{port_flag} {user_host}"
        return f"ssh {user_host} 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'  # then paste a key"
    if stage == "hostkey":
        host_only = user_host.split("@")[-1].strip("[]")
        return f"ssh-keygen -R {host_only} && ssh{port_flag} {user_host} true"
    if stage in ("dns", "tcp"):
        return f"ssh{port_flag} {user_host} true"
    return ""


def _key_name() -> str:
    ssh_dir = Path.home() / ".ssh"
    for name in ("id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub"):
        if (ssh_dir / name).exists():
            return name
    for candidate in sorted(ssh_dir.glob("*.pub")) if ssh_dir.is_dir() else []:
        return candidate.name
    return "id_ed25519.pub"
