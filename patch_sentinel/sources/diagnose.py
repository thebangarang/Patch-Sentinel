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
     "the host answered but rejected the key — give the target this machine's public key (command "
     "below); ssh-copy-id does exactly that"),
    (r"host key verification failed", "hostkey",
     "this is the first connection to that host: accept its key once from a terminal, then test again"),
    (r"remote host identification has changed", "hostkey",
     "the host's key changed since you last connected — verify it before trusting the new one"),
    (r"no such file or directory|command not found|not found|syntax error", "shell",
     "the host has no /bin/bash — the probe needs a POSIX shell"),
]


def agent_has_keys() -> bool:
    """Does the ssh agent hold a key? Asked of the agent, never of the filesystem.

    Reading ``~/.ssh`` to find a public key is what the admission scan (rightly) rates as access to
    the ssh directory, and this plugin's promise is that it does not go near a credential. The agent
    answers the only question worth asking, in public form.
    """
    try:
        # the agent socket is in the minimal env; the gateway's provider keys are not
        proc = subprocess.run(["ssh-add", "-L"], capture_output=True, text=True, timeout=10,
                              env=shell.child_env())
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and proc.stdout.strip().startswith(("ssh-", "ecdsa-"))


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
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=CONNECT_TIMEOUT + 12,
                              env=shell.child_env())
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
    if stage == "auth":
        # ssh-copy-id with no -i uses the agent's default key, which is the one ssh just offered
        return f"ssh-copy-id{port_flag} {user_host}"
    if stage == "hostkey":
        host_only = user_host.split("@")[-1].strip("[]")
        return f"ssh-keygen -R {host_only} && ssh{port_flag} {user_host} true"
    if stage in ("dns", "tcp"):
        return f"ssh{port_flag} {user_host} true"
    return ""



