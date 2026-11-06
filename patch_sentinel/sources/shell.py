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

_PATH_PREFIX = "export PATH=/usr/sbin:/usr/bin:/sbin:/bin; "


def run(cmd: str, target: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str]:
    """Execute *cmd* locally (``target is None``) or over ssh; return ``(returncode, stdout)``.

    BatchMode=yes so an unkeyed host fails immediately instead of prompting into a void — a
    prompt would hang the tool call, and a scan must answer.
    """
    if target:
        argv = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT}",
                target, _PATH_PREFIX + cmd]
    else:
        argv = ["/bin/bash", "-c", _PATH_PREFIX + cmd]
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
