"""Acknowledgements: an operator's "I know, and I accept it", written down.

A finding that nobody has fixed is not a task, and a list that keeps reprinting it is a list people
stop reading. The control that fixes this is not a filter — it is a record: *who* acknowledged *which
advisory*, *why*, and *until when*.

Two rules keep this from becoming a way to lie:

* **an acknowledgement names an advisory id, not a package.** A new advisory against the same version
  is a new finding and reappears at once;
* **it expires.** 90 days by default, 365 at most, and the row comes back by itself — nobody has to
  remember to look again.

Nothing is deleted: the acknowledged rows travel in the payload with their reason, and the pane shows
them under their own line.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

DEFAULT_DAYS = 90
MAX_DAYS = 365
FILE = "acks.json"


def _path(data_dir: str) -> Path:
    return Path(data_dir or ".") / FILE


def _read(data_dir: str) -> list[dict]:
    path = _path(data_dir)
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError):
        return []
    rows = payload.get("acks") if isinstance(payload, dict) else None
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def _write(data_dir: str, rows: list[dict]) -> None:
    path = _path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    # 0600: an acknowledgement names what an operator decided about their own machine
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump({"acks": rows}, handle, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _key(host: str, ecosystem: str, package: str, version: str, advisory: str) -> tuple:
    return (str(host).lower(), ecosystem or "", package or "", version or "", advisory or "")


def split(data_dir: str, host: str, rows: list[dict], now: float | None = None) -> tuple[list, list]:
    """Return (still-open rows, acknowledged rows) — an expired record covers nothing."""
    now = time.time() if now is None else now
    active = {_key(a.get("host", ""), a.get("ecosystem", ""), a.get("package", ""),
                   a.get("version", ""), a.get("advisory", "")): a
              for a in _read(data_dir)
              if float(a.get("until") or 0) > now}
    kept, acked = [], []
    for row in rows:
        record = active.get(_key(host, row.get("ecosystem", ""), row.get("package", ""),
                                 row.get("version", ""), row.get("id", "")))
        if record is None:
            kept.append(row)
            continue
        acked.append({**row, "ack": {"reason": record.get("reason"),
                                     "at": record.get("at"),
                                     "until": record.get("until"),
                                     "days": record.get("days")}})
    return kept, acked


def acknowledge(data_dir: str, host: str, ecosystem: str, package: str, version: str,
                advisory: str, reason: str, days: int = DEFAULT_DAYS) -> dict:
    reason = " ".join(str(reason or "").split())
    if not reason:
        # an acknowledgement with no reason is just a hidden finding
        return {"ok": False,
                "reason": "an acknowledgement needs a reason — the point is that the decision is "
                          "written down for the next person who reads this screen"}
    # `days or DEFAULT` would turn an explicit 0 into 90 — a record meant to last a day would last a
    # quarter. Only a missing value takes the default.
    days = max(1, min(int(DEFAULT_DAYS if days is None else days), MAX_DAYS))
    now = time.time()
    rows = [a for a in _read(data_dir)
            if _key(a.get("host", ""), a.get("ecosystem", ""), a.get("package", ""),
                    a.get("version", ""), a.get("advisory", ""))
            != _key(host, ecosystem, package, version, advisory)]
    record = {"host": str(host).lower(), "ecosystem": ecosystem, "package": package,
              "version": version, "advisory": advisory, "reason": reason,
              "at": now, "until": now + days * 86400, "days": days}
    rows.append(record)
    _write(data_dir, rows)
    return {"ok": True, "ack": record,
            "answer": f"{package} {version} · {advisory} acknowledged for {days} days — "
                      f"it comes back on its own, and a new advisory against this version is never "
                      f"covered by this record"}


def release(data_dir: str, host: str, ecosystem: str, package: str, version: str,
            advisory: str) -> dict:
    target = _key(host, ecosystem, package, version, advisory)
    rows = _read(data_dir)
    kept = [a for a in rows
            if _key(a.get("host", ""), a.get("ecosystem", ""), a.get("package", ""),
                    a.get("version", ""), a.get("advisory", "")) != target]
    if len(kept) == len(rows):
        return {"ok": False, "reason": "no acknowledgement matches that row"}
    _write(data_dir, kept)
    return {"ok": True, "answer": f"{package} {version} · {advisory} is open again"}
