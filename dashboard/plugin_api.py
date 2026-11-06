"""The pane's backend: a router under ``/api/plugins/patch-sentinel``.

It calls the same handlers the model calls, and returns their payloads unchanged — the pane and
the agent must never disagree about what was measured. Two consequences worth stating:

* ``GET /status`` never scans. It reads the stored measurement and says how old it is, because a
  pane that quietly re-measures every time it is opened is a pane that contradicts the answer the
  model gave a minute ago. ``POST /scan`` is the explicit refresh.
* Every route is read-only in this version. ``/apply`` is deliberately absent: applying needs an
  operator-typed host name and a receipt, and shipping a route that half-does that is worse than
  shipping none (see ``docs/design.md`` *Apply gate*, decision D6).

The engine is loaded with ``importlib.util.spec_from_file_location`` — never by putting the plugin
directory on ``sys.path`` — so the module identity here is the same one the tool layer uses.
"""
from __future__ import annotations

import importlib.util
import json
import sys
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

tools.configure({})                                    # defaults + env overrides
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
                "exit_code": None,
                "note": "no measurement yet — press Refresh, or ask the agent 'are we patched?'"}
    return {"scan": scan.get("scan"), "age_seconds": age, "hosts": scan.get("hosts") or {},
            "blind": scan.get("blind") or [], "exit_code": scan.get("exit_code"),
            "answer": scan.get("answer")}


@router.post("/scan")
def scan(body: dict | None = None) -> dict:
    """Refresh: the same call the model makes when the user asks 'are we patched?'."""
    args = {}
    if body and body.get("host"):
        args["host"] = str(body["host"])
    return _payload(tools.cve_scan, args)


@router.post("/plan")
def plan(body: dict | None = None) -> dict:
    """The ranked plan for one host. Never executes anything."""
    args = {}
    if body and body.get("host"):
        args["host"] = str(body["host"])
    return _payload(tools.cve_plan, args)


@router.get("/libraries")
def libraries() -> dict:
    """The language surface for this machine (npm global tree, pip on PATH)."""
    return _payload(tools.cve_libraries, {})


@router.get("/coverage")
def coverage() -> dict:
    """What answered and when, plus the standing gaps — never empty, never green."""
    return _payload(tools.cve_coverage, {})


@router.post("/apply")
def apply(body: dict | None = None) -> dict:
    """The gate, and only the gate: 0.1.0 refuses to change a machine.

    A real apply is a design in ``docs/design.md`` (*Apply gate*) with four requirements —
    the host name typed by the operator, a staged download before anything restarts, a receipt
    written with what changed, and a verification by effect. Implementing three of the four is
    how a patching tool becomes the reason a box is down, so this route refuses and shows the
    exact commands it would have run.
    """
    host_label = str((body or {}).get("host") or "").strip()
    typed = str((body or {}).get("confirm") or "").strip()
    if not host_label:
        return {"applied": False, "reason": "no host given"}
    if typed != host_label:
        return {"applied": False,
                "reason": f"the gate is armed only by typing {host_label!r} exactly — got {typed!r}"}
    plan = _payload(tools.cve_plan, {"host": host_label})
    return {"applied": False, "host": host_label,
            "reason": "applying is not enabled in 0.1.0 — the plan is the deliverable. A real "
                      "apply needs a staged download, a receipt and a verify-by-effect (D6).",
            "would_run": [step.get("command") for step in (plan.get("steps") or [])],
            "measured_at": plan.get("measured_at")}


@router.get("/health")
def health() -> dict:
    """Cheap liveness for the pane: the router is mounted and the engine imports."""
    return {"ok": True, "plugin": "patch-sentinel", "tools": sorted(tools.HANDLERS)}
