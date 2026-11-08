"""Everything the pane measures, taken once, in order, and kept as one bundle.

The pane used to offer a button per surface — rescan, check libraries, read integrity, plan — and each
one wrote its own answer somewhere else. That is four controls for one question, and the operator said
so: *one button, one section of things to do, one section of commands*. This module is the backend half
of that change: a single run that walks the surfaces in a fixed order, writes the bundle after each one
(so the pane can render what has landed while the rest is still being measured) and records how long
each stage took.

Nothing here decides anything. It calls the same handlers the individual tools call, in the same
process, and stores their payloads verbatim.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

FILE = "rescan.json"

#: the order the pane promises: packages first (the cheapest and the one people ask about), then the
#: language stack, then the integrity reading, then the commands those three imply.
STAGES = ("scan", "libraries", "integrity", "plans")


def path(data_dir: str) -> Path:
    return Path(data_dir or ".") / FILE


def read(data_dir: str) -> dict:
    """The last bundle, or an empty one. A corrupt file is a bundle that was never written."""
    try:
        payload = json.loads(path(data_dir).read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, dict):
        return {}
    if not isinstance(payload.get("stages"), list):
        payload["stages"] = []
    return payload


def start(data_dir: str) -> dict:
    """A fresh bundle, written before any stage runs, so a half-finished run is visible as such."""
    bundle = {"started_at": time.time(), "finished_at": None, "stage": "starting",
              "stages": [], "scan": None, "libraries": None, "integrity": None, "plans": {}}
    write(data_dir, bundle)
    return bundle


def write(data_dir: str, bundle: dict) -> dict:
    """Atomic, 0600, and never fatal: a read-only data directory costs the storage, not the run."""
    target = path(data_dir)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(bundle, handle, indent=2, sort_keys=True)
        os.replace(tmp, target)
    except OSError:
        return bundle
    return bundle
