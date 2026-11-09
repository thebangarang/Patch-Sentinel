"""Where a measurement is kept so the next question does not have to re-measure.

Two files, both private to this plugin and outside the repository when installed:

* ``last_scan.json`` — the last scan payload, so ``cve_plan`` and ``cve_coverage`` answer from
  the same measurement ``cve_scan`` showed, quoted with the time it was taken (rule 8);
* ``receipts.jsonl`` — one line per applied action, written by the apply path (v0.2; the file
  and its format exist now so the demo can show the line a receipt will have).

Mode 600, directory 700: this is the host's patch posture, and on the operator's own rule it
does not become readable to anyone else by accident.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path

_SCAN = "last_scan.json"
_RECEIPTS = "receipts.jsonl"
_SETTINGS = "settings.json"
_settings: dict = {}


def configure(settings: dict) -> None:
    """Called once from ``register()`` with the resolved plugin config."""
    global _settings
    _settings = dict(settings or {})


def hermes_home() -> Path:
    """The Hermes home this process is serving — per profile, when a gateway multiplexes several.

    ``HERMES_HOME`` in the environment is one process-wide value, so a multi-profile gateway would
    write every profile's scans into the first one's directory. ``hermes_constants.get_hermes_home``
    resolves the *active* profile (a context-local override first, then the env var, then the
    platform default), which is what a plugin should follow. The import is optional: the plugin also
    runs outside Hermes (the portability probe, the tests), where the env var and the default are all
    there is.
    """
    try:
        from hermes_constants import get_hermes_home          # type: ignore[import-not-found]
        resolved = get_hermes_home()
        if resolved:
            return Path(resolved)
    except Exception:                                          # noqa: BLE001 - not inside Hermes
        pass
    return Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))


def data_dir() -> Path:
    """``PATCH_SENTINEL_DATA`` / config ``data_dir``, else ``<hermes home>/patch-sentinel``."""
    override = (os.environ.get("PATCH_SENTINEL_DATA") or _settings.get("data_dir") or "").strip()
    if override:
        path = Path(override).expanduser()
    else:
        path = hermes_home() / "patch-sentinel"
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def save_scan(payload: dict) -> Path:
    """Write the scan atomically; a half-written state file is worse than an old one."""
    path = data_dir() / _SCAN
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)
    return path


def load_scan() -> dict | None:
    """The last scan, or None. A corrupt file is None, not an exception."""
    try:
        data = json.loads((data_dir() / _SCAN).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def scan_age_seconds(scan: dict | None = None) -> float | None:
    """How old the stored measurement is, in seconds — None when there is none or it is undated."""
    scan = scan if scan is not None else load_scan()
    at = ((scan or {}).get("scan") or {}).get("at")
    if not at:
        return None
    try:
        taken = dt.datetime.fromisoformat(at)
    except ValueError:
        return None
    if taken.tzinfo is None:
        taken = taken.replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - taken).total_seconds()


def save_settings(settings: dict) -> Path:
    """Persist the settings ``register()`` resolved, so the pane runs the same configuration.

    The agent side has ``ctx.get_config``; the dashboard router has no ``ctx`` at all. Rather than
    reaching into a private Hermes config API from the router, the side that *does* have the config
    writes it down here (mode 600), and the router reads it back. One source of truth, no coupling.
    """
    path = data_dir() / _SETTINGS
    path.write_text(json.dumps(settings or {}, indent=1, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def load_settings() -> dict:
    try:
        data = json.loads((data_dir() / _SETTINGS).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def append_receipt(row: dict) -> Path:
    """Append one receipt line. Kept for the apply path; nothing writes it in v0.1."""
    path = data_dir() / _RECEIPTS
    row = {"at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), **row}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def load_receipts(limit: int = 20) -> list[dict]:
    try:
        lines = (data_dir() / _RECEIPTS).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
