"""The pane's backend: a router under ``/api/plugins/patch-sentinel``.

It calls the same handlers the model calls, and returns their payloads unchanged — the pane and
the agent must never disagree about what was measured. Two consequences worth stating:

* ``GET /status`` never scans. It reads the stored measurement and says how old it is, because a
  pane that quietly re-measures every time it is opened is a pane that contradicts the answer the
  model gave a minute ago. ``POST /scan`` is the explicit refresh.
* Every route is read-only except ``POST /apply``, which passes straight through to ``cve_apply``:
  the operator's typed host name is the gate, and the pane must not have a shorter route to
  changing a machine than the agent has (see ``docs/design.md`` *Apply gate*, decision D6).

The engine is loaded with ``importlib.util.spec_from_file_location`` — never by putting the plugin
directory on ``sys.path`` — so the module identity here is the same one the tool layer uses.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter

_ROOT = Path(__file__).resolve().parent.parent
_PKG = _ROOT / "patch_sentinel"

if "patch_sentinel" not in sys.modules:
    _spec = importlib.util.spec_from_file_location(
        "patch_sentinel", _PKG / "__init__.py", submodule_search_locations=[str(_PKG)])
    if _spec is None or _spec.loader is None:          # pragma: no cover - broken install
        raise ImportError(f"cannot load the engine from {_PKG}")
    _module = importlib.util.module_from_spec(_spec)
    sys.modules["patch_sentinel"] = _module
    _spec.loader.exec_module(_module)

from patch_sentinel import store, tools                # noqa: E402  (after the loader above)

# A router gets no ``ctx``, so it cannot call ``ctx.get_config``; it reads back what register()
# resolved instead (see store.save_settings). Before the plugin has ever registered, this is empty
# and the defaults apply — which is the same thing the agent would have used.
tools.configure(store.load_settings())
router = APIRouter()


def _payload(handler, args: dict) -> dict:
    """Handlers return a JSON string by contract; the pane wants the object back."""
    raw = handler(args or {})
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return {"error": "the tool returned something that is not JSON", "raw": str(raw)[:400]}


@router.get("/status")
def status() -> dict:
    """The last stored measurement, with its age. Never scans."""
    scan = store.load_scan()
    age = store.scan_age_seconds(scan)
    if scan is None:
        return {"scan": None, "age_seconds": None, "hosts": {}, "blind": [],
                "exit_code": None, "job": _job_state("scan"),
                "note": "no measurement yet — press Refresh, or ask the agent 'are we patched?'"}
    return {"scan": scan.get("scan"), "age_seconds": age, "hosts": scan.get("hosts") or {},
            "blind": scan.get("blind") or [], "exit_code": scan.get("exit_code"),
            "answer": scan.get("answer"), "threat": scan.get("threat"),
            "job": _job_state("scan")}


# --------------------------------------------------------------------------- long jobs
# The desktop's bridge gives a renderer call 30 seconds. A scan of two servers takes 40-60 (an ssh
# round trip, `dpkg` for every advisory-named package, and a distro upgrade check on each), and a real
# apply took 105 s on the Fedora VM. Answering inside the request means the pane reports a timeout
# while the machine is being patched — the worst possible moment to tell someone it failed. So these
# two routes start a thread and answer at once; the pane follows the job.
_JOBS: dict[str, dict] = {}


def _job(name: str) -> dict:
    return _JOBS.setdefault(name, {"running": False, "started_at": None, "seconds": None,
                                   "error": None, "result": None, "finished_at": None})


def _job_state(name: str) -> dict:
    job = _job(name)
    return {"running": job["running"],
            "seconds": round(time.time() - job["started_at"], 1) if job["running"] and job["started_at"] else job["seconds"],
            "error": job["error"], "finished_at": job["finished_at"]}


def _run_job(name: str, handler, args: dict) -> None:
    job = _job(name)
    try:
        job["result"] = _payload(handler, args)
    except Exception as exc:                     # a thread that raises must not look like success
        job["error"] = f"{type(exc).__name__}: {exc}"[:400]
        job["result"] = None
    finally:
        job["seconds"] = round(time.time() - (job["started_at"] or time.time()), 1)
        job["finished_at"] = time.time()
        job["running"] = False


def _start(name: str, handler, args: dict) -> dict:
    """Start one job, or say it is already running. Never two of the same at once."""
    job = _job(name)
    if job["running"]:
        return {"started": False, **_job_state(name),
                "note": f"a {name} is already running — it started {_job_state(name)['seconds']} s ago"}
    job.update(running=True, started_at=time.time(), error=None, result=None, finished_at=None)
    threading.Thread(target=_run_job, args=(name, handler, args), daemon=True).start()
    return {"started": True, **_job_state(name)}


@router.get("/jobs")
def jobs() -> dict:
    """What is running, and what the last run returned. The pane polls this while a job runs."""
    return {name: {**_job_state(name),
                   "result": (job["result"] if not job["running"] else None)}
            for name, job in list(_JOBS.items())}


@router.post("/scan")
def scan(body: dict | None = None) -> dict:
    """Refresh: the same call the model makes when the user asks 'are we patched?'.

    Starts the scan in a thread and answers immediately — see *long jobs* above for why.
    """
    args = {}
    if body and body.get("host"):
        args["host"] = str(body["host"])
    return _start("scan", tools.cve_scan, args)


@router.post("/plan")
def plan(body: dict | None = None) -> dict:
    """The ranked plan for one host. Never executes anything."""
    args = {}
    if body and body.get("host"):
        args["host"] = str(body["host"])
    return _payload(tools.cve_plan, args)


# --------------------------------------------------------------------------- hosts
# The inventory is editable from the pane. It holds addresses, never credentials: authentication is
# ssh's job (agent or ~/.ssh/config), which is the same rule the apply gate follows. A host can only
# be added after a probe of it succeeded, so the list never gains a row nobody has reached.


def _hosts_now() -> list[dict]:
    from patch_sentinel.sources import hosts as inventory_module
    return inventory_module.inventory(tools._settings.get("hosts"))


@router.get("/hosts")
def hosts_list() -> dict:
    return {"hosts": [{"label": h["label"], "target": h["target"] or "local"} for h in _hosts_now()]}


@router.post("/hosts/test")
def hosts_test(body: dict | None = None) -> dict:
    from patch_sentinel.sources import dispatch
    from patch_sentinel.sources import hosts as inventory_module

    payload = dict(body or {})
    label = str(payload.get("label") or "").strip()
    target = str(payload.get("target") or "").strip()
    ok, reason = inventory_module.validate(label, target)
    if not ok:
        return {"ok": False, "stage": "format", "reason": reason}
    # One stage at a time, before the full scan: which hop failed decides what the user does next.
    from patch_sentinel.sources import diagnose
    reach = diagnose.diagnose(None if inventory_module.is_local(target) else target)
    if not reach["ok"]:
        return {"ok": False, "stage": reach["stage"], "reason": reach["reason"],
                "hint": reach.get("hint") or "", "fix": reach.get("fix") or ""}
    result = dispatch.probe(label, None if inventory_module.is_local(target) else target,
                            timeout=int(tools._settings.get("timeout") or 180))
    if not result.get("ok"):
        return {"ok": False, "reason": result.get("why") or "the probe failed",
                "detail": result.get("detail") or ""}
    return {"ok": True, "adapter": result.get("family"), "os": result.get("os"),
            "kernel": {"running": result.get("running"), "verdict": result.get("kernel")},
            "pending": len(result.get("pending") or [])}


@router.post("/hosts")
def hosts_add(body: dict | None = None) -> dict:
    from patch_sentinel.sources import hosts as inventory_module

    payload = dict(body or {})
    label = str(payload.get("label") or "").strip()
    target = str(payload.get("target") or "").strip()
    ok, reason = inventory_module.validate(label, target)
    if not ok:
        return {"added": False, "reason": reason}
    entries = _hosts_now()
    if any(h["label"].lower() == label.lower() for h in entries):
        return {"added": False, "reason": f"a host labelled {label!r} is already in the inventory"}
    entries.append({"label": label,
                    "target": None if inventory_module.is_local(target) else target})
    return _save_hosts(entries, added=label)


@router.post("/hosts/remove")
def hosts_remove(body: dict | None = None) -> dict:
    from patch_sentinel.sources import hosts as inventory_module

    payload = dict(body or {})
    label = str(payload.get("label") or "").strip()
    confirm = str(payload.get("confirm") or "").strip()
    entries = _hosts_now()
    match = next((h for h in entries if h["label"].lower() == label.lower()), None)
    if match is None:
        return {"removed": False, "reason": f"there is no host labelled {label!r}"}
    if confirm != match["label"]:
        return {"removed": False,
                "reason": "type the label exactly to remove it — removing a host throws away its "
                          "measurement history"}
    remaining = [h for h in entries if h["label"].lower() != match["label"].lower()]
    if not any(inventory_module.is_local(h.get("target")) for h in remaining):
        return {"removed": False,
                "reason": "the machine this plugin runs on cannot be removed — a scan that cannot "
                          "answer for itself is not a patch posture"}
    return _save_hosts(remaining, removed=match["label"])


def _save_hosts(entries: list[dict], **extra) -> dict:
    """Persist the inventory and make it live in this process without a restart."""
    from patch_sentinel.sources import hosts as inventory_module

    settings = dict(store.load_settings() or {})
    settings["hosts"] = inventory_module.serialize(entries)
    # marks the file as edited from the pane, so register() stops overwriting it from config.yaml
    settings["hosts_source"] = "pane"
    store.save_settings(settings)
    tools.configure(settings)
    return {"hosts": [{"label": h["label"], "target": h["target"] or "local"}
                      for h in inventory_module.inventory(settings.get("hosts"))], **extra}


@router.get("/libraries")
def libraries(project: str | None = None, host: str | None = None) -> dict:
    """The language surface: machine-wide by default, or one project's lockfiles with `?project=`."""
    args = {}
    if project:
        args["project"] = project
    if host:
        args["host"] = host
    return _payload(tools.cve_libraries, args)


@router.get("/coverage")
def coverage() -> dict:
    """What answered and when, plus the standing gaps — never empty, never green."""
    return _payload(tools.cve_coverage, {})


@router.post("/apply")
def apply(body: dict | None = None) -> dict:
    """The gate. The typed host name is required; ``dry_run`` defaults to true.

    The route passes straight through to ``cve_apply`` — the pane must not have a shorter route
    to changing a machine than the agent does, and the operator's typed name is what arms it.
    """
    payload = dict(body or {})
    args = {"host": str(payload.get("host") or "").strip(),
            "confirm": str(payload.get("confirm") or ""),
            "dry_run": bool(payload.get("dry_run", True))}
    if args.get("timeout"):
        args["timeout"] = payload["timeout"]
    # an upgrade took 105 s on the Fedora VM: answering inside the request would tell the operator the
    # apply failed while it is running, and invite a second one. The pane follows `/jobs` instead.
    return _start("apply", tools.cve_apply, args)


_LOADED_AT = time.time()


def _api_state() -> dict:
    """Is the Python half the one on disk?

    The pane's routes are imported once, when the plugin host loads. Editing ``tools.py`` afterwards
    leaves the *back end* serving the previous code while the JS reloads — a count with no rows, a
    field that is simply absent. This reports it instead of letting it look like a UI bug.
    """
    try:
        current = os.path.getmtime(tools.__file__)
    except OSError:
        return {"stale": False, "loaded_at": _LOADED_AT}
    return {"stale": current > _LOADED_AT + 1,
            "loaded_at": datetime.fromtimestamp(_LOADED_AT, timezone.utc).isoformat(timespec="seconds"),
            "source_mtime": datetime.fromtimestamp(current, timezone.utc).isoformat(timespec="seconds")}


def _ui_prints() -> dict:
    """Which build of the pane is where.

    The desktop app copies ``desktop/plugin.js`` into ``$HERMES_HOME/desktop-plugins/<name>/`` and
    serves that copy. After an edit the two can differ — the classic "I don't see any change" — so
    both fingerprints are reported and the pane compares them out loud.
    """
    root = Path(__file__).resolve().parent.parent
    home = Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))
    prints = {}
    for key, path in (("repo", root / "desktop" / "plugin.js"),
                      ("served", home / "desktop-plugins" / "patch-sentinel" / "plugin.js")):
        try:
            data = path.read_bytes()
            prints[key] = {
                "sha": hashlib.sha1(data).hexdigest()[:8],
                "bytes": len(data),
                "mtime": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
                                 .isoformat(timespec="seconds"),
            }
        except OSError:
            prints[key] = None
    prints["in_sync"] = bool(prints["repo"] and prints["served"]
                             and prints["repo"]["sha"] == prints["served"]["sha"])
    return prints


@router.get("/health")
def health() -> dict:
    """Liveness for the pane, plus which build of the pane the app is actually serving."""
    return {"ok": True, "plugin": "patch-sentinel", "tools": sorted(tools.HANDLERS),
            "ui": _ui_prints(), "api": _api_state(),
            # what this *process* sees, so "why is only one host listed" has an answer in evidence
            "inventory": [host.get("label") for host in tools._inventory()],
            "data_dir": str(store.data_dir())}
