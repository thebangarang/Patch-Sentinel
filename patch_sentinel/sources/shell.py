"""Run one command locally or on a remote host — the only place this plugin shells out.

Read-only in the scan: the simulation (`apt-get -s`), `uname`, `dpkg-query`, `apt-cache`,
`docker ps|inspect|buildx imagetools`. Nothing here writes, installs or restarts anything;
the apply path is deliberately absent from v0.1 (D6/D9).

Failure is a value, never an exception: a command that could not run returns a non-zero code
plus its text, and the caller turns that into an `unknown` outcome with a reason
(design rule 5 — a refused source is never "clean").
"""
from __future__ import annotations

import subprocess

# The scan is read-only, so a hung `apt-get -s` must not hang the agent: 180s, like the routine.
DEFAULT_TIMEOUT = 180
SSH_CONNECT_TIMEOUT = 12

# The OS probe wants the system's own tools, and only those: `apt-get` and `dpkg-query` must be the
# distribution's, never a user-installed stub earlier on the PATH.
SYSTEM_PATH_PREFIX = "export PATH=/usr/sbin:/usr/bin:/sbin:/bin; "

# Language tooling is the opposite case: npm, pip3 and version-manager shims live in the user's own
# directories, so this prefix keeps whatever PATH the caller had and only adds the places a login
# shell would have (measured here: pip3 sits in a Hermes tool dir that a system PATH never sees).
USER_PATH_PREFIX = "export PATH=$HOME/.local/bin:$HOME/bin:$PATH:/usr/sbin:/usr/bin:/sbin:/bin; "

_PATH_PREFIX = SYSTEM_PATH_PREFIX


def split_target(target: str) -> tuple[str, str | None]:
    """``user@host:2222`` → (``user@host``, ``2222``). ssh takes the port as ``-p``, not in the host.

    A non-numeric suffix is left alone, so a mangled entry fails as an ssh error (a refusal) rather
    than silently scanning the wrong host.
    """
    host, sep, port = target.rpartition(":")
    if sep and host and port.isdigit():
        return host, port
    return target, None


def run(cmd: str, target: str | None = None, timeout: int = DEFAULT_TIMEOUT,
        path_prefix: str | None = None) -> tuple[int, str]:
    """Execute *cmd* locally (``target is None``) or over ssh; return ``(returncode, stdout)``.

    BatchMode=yes so an unkeyed host fails immediately instead of prompting into a void — a
    prompt would hang the tool call, and a scan must answer.
    """
    if target:
        host, port = split_target(target)
        argv = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT}"]
        if port:
            argv += ["-p", port]
        argv += [host, (path_prefix or _PATH_PREFIX) + cmd]
    else:
        argv = ["/bin/bash", "-c", (path_prefix or _PATH_PREFIX) + cmd]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except (OSError, ValueError) as exc:          # no bash, no ssh binary, bad target string
        return 127, f"{type(exc).__name__}: {exc}"
    text = (proc.stdout or "").strip()
    if proc.returncode != 0 and not text:
        # ssh's own complaint is the reason a host was unreachable; without it the payload says
        # "rc=255" and nothing else, which is not a reason a person can act on.
        text = (proc.stderr or "").strip()
    return proc.returncode, text
