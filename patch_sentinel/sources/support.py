"""Is this release still getting fixes at all?

A feed that stopped moving and a vendor that stopped publishing look identical in a lag row, and they
mean opposite things: one is a stale mirror, the other is a machine nobody is going to patch again
without a reinstall. openSUSE Leap 15.6's OVAL last moved in June 2026; that is not a slow vendor.

Two inputs, both local and both free:

* a **lifecycle table** — the published end of standard support per release, stamped with the date it
  was compiled. A release not in the table is `unknown`, never "supported";
* **Ubuntu Pro / ESM state**, when `pro` is installed: a release past standard support can still be
  patched through ESM, and that changes the advice from "upgrade the OS" to "attach the subscription".

Nothing here guesses: an entry past its date is `end-of-life`, an entry inside it is `supported`, and
the stamp says how old the judgement is.
"""
from __future__ import annotations

import json

#: Compiled 2026-11-07 from each project's published lifecycle. Dates are the *end of standard
#: support*, not of extended support.
COMPILED = "2026-11-07"
LIFECYCLE: dict[str, dict[str, str]] = {
    "ubuntu": {"18.04": "2023-05-31", "20.04": "2025-05-31", "22.04": "2027-04-30",
               "24.04": "2029-04-30", "26.04": "2031-04-30"},
    "debian": {"10": "2024-06-30", "11": "2026-08-31", "12": "2028-06-30", "13": "2030-06-30"},
    "fedora": {"41": "2026-01-07", "42": "2026-05-13", "43": "2026-11-25", "44": "2027-05-19",
               "45": "2027-11-17", "46": "2028-05-17"},
    "alpine": {"3.19": "2025-11-01", "3.20": "2026-04-01", "3.21": "2026-11-01",
               "3.22": "2027-05-01", "3.23": "2027-11-01", "3.24": "2028-05-01"},
    "opensuse-leap": {"15.5": "2024-12-31", "15.6": "2025-12-31", "16.0": "2027-10-31"},
    "sles": {"15.6": "2028-07-31", "16.0": "2031-07-31"},
}


def _major(os_id: str, release: str) -> str:
    """Which lifecycle entry a host's VERSION_ID maps to (Ubuntu uses x.y, Alpine x.y, Fedora x)."""
    value = (release or "").strip()
    if not value:
        return ""
    if os_id in ("ubuntu", "alpine", "opensuse-leap"):
        return ".".join(value.split(".")[:2])
    return value.split(".")[0]


def state(os_id: str, release: str, today: str | None = None) -> dict:
    """``{"state": "supported"|"end-of-life"|"unknown", "ends": date|None, "why": str}``."""
    key = ((os_id or "").strip().lower(), _major(os_id, release))
    table = LIFECYCLE.get(key[0])
    if not table:
        return {"state": "unknown", "ends": None,
                "why": f"no lifecycle is recorded for {os_id or 'this distribution'} — unknown, not "
                       f"assumed supported"}
    ends = table.get(key[1])
    if not ends:
        return {"state": "unknown", "ends": None,
                "why": f"{os_id} {release} is not in the lifecycle table (compiled {COMPILED}) — "
                       f"unknown, not assumed supported"}
    now = today or _today()
    if now <= ends:
        return {"state": "supported", "ends": ends,
                "why": f"standard support ends {ends} (table compiled {COMPILED})"}
    return {"state": "end-of-life", "ends": ends,
            "why": f"standard support ended {ends} (table compiled {COMPILED}): the vendor publishes "
                   f"no new fixes for this release, so an empty pending list here means nobody is "
                   f"going to publish one"}


def _today() -> str:
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


def pro_status(target: str | None, timeout: int = 30) -> dict:
    """Ubuntu Pro / ESM state, when the client is installed. Absent is `unavailable`, not "no ESM"."""
    from . import shell

    code, out = shell.run("command -v pro >/dev/null 2>&1 && pro status --format json 2>/dev/null",
                          target, timeout=timeout, path_prefix=shell.SYSTEM_PATH_PREFIX)
    text = (out or "").strip()
    if not text:
        return {"outcome": "unavailable"}
    try:
        data = json.loads(text)
    except ValueError:
        return {"outcome": "unavailable", "why": "the pro client answered something that is not JSON"}
    services = ((data.get("services") or []) if isinstance(data, dict) else [])
    enabled = sorted(str(service.get("name")) for service in services
                     if isinstance(service, dict) and service.get("status") == "enabled"
                     and service.get("name"))
    return {"outcome": "ok", "attached": bool(data.get("attached")) if isinstance(data, dict) else None,
            "enabled": enabled}
