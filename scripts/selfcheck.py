#!/usr/bin/env python3
"""Prove, in one run, that each surface of Patch Sentinel actually measured something.

The question this answers is the operator's: *"how do I know the language check and the update
proposal really work, rather than just rendering?"* Trust is not a feature; a re-runnable check is.

    python3 scripts/selfcheck.py                     # this machine
    python3 scripts/selfcheck.py --host fedora-lab   # a declared host, and its plan
    python3 scripts/selfcheck.py --json              # the same table, machine-readable

Exit code: 0 when every surface answered (findings are not failures — an unmeasured surface is),
2 when at least one surface could not look. Same contract as the tools themselves.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from patch_sentinel import store, tools  # noqa: E402


def _rows() -> list[dict]:
    rows: list[dict] = []
    return rows


def check_scan(rows: list[dict], host: str | None) -> None:
    """1. Does the OS adapter read this machine, and does the kernel verdict make sense?"""
    started = time.time()
    payload = json.loads(tools.cve_scan({"hosts": host or ""}))
    took = round(time.time() - started, 1)
    for label, entry in (payload.get("hosts") or {}).items():
        kernel = entry.get("kernel") or {}
        rows.append({
            "surface": f"os scan · {label}",
            "outcome": "measured" if not entry.get("blind") else "could not look",
            "detail": (f"{entry.get('adapter')} · {entry.get('os', {}).get('id')}/"
                       f"{entry.get('os', {}).get('codename')} · {entry.get('pending_count')} pending · "
                       f"kernel {kernel.get('running')} → {kernel.get('verdict')}"),
            "seconds": took,
        })
    for blind in payload.get("blind") or []:
        rows.append({"surface": f"os scan · {blind.get('host')}", "outcome": "could not look",
                     "detail": blind.get("reason"), "seconds": None})


def check_libraries(rows: list[dict]) -> None:
    """2. Does the language check reach OSV, and does it name what it found?"""
    started = time.time()
    payload = json.loads(tools.cve_libraries({}))
    took = round(time.time() - started, 1)
    outcomes = payload.get("outcomes") or {}
    vulnerable = payload.get("vulnerable") or []
    rows.append({
        "surface": "language check",
        "outcome": "measured" if all(v == "ok" for v in outcomes.values()) and outcomes else "could not look",
        "detail": (f"{payload.get('components', 0)} package(s) read "
                   f"({', '.join(f'{k}: {v}' for k, v in outcomes.items())}) "
                   f"via {', '.join((payload.get('details') or {}).values()) or 'unknown'} · "
                   f"{len(vulnerable)} vulnerable · "
                   + (", ".join(sorted({v['package'] for v in vulnerable})) or "no findings")),
        "seconds": took,
    })
    for item in vulnerable[:3]:
        rows.append({"surface": f"  ↳ {item['package']} {item['version']}", "outcome": "finding",
                     "detail": f"{item['id']} ({', '.join(item.get('aliases') or [])}) — "
                               f"fixed in {', '.join(item.get('fixed') or []) or 'no fix listed'}",
                     "seconds": None})
    for name, why in (payload.get("unmeasured") or {}).items():
        rows.append({"surface": f"  ↳ {name}", "outcome": "could not look", "detail": why,
                     "seconds": None})


def check_plan(rows: list[dict], host: str) -> None:
    """3. Does the plan turn a measurement into commands with a way back?"""
    started = time.time()
    payload = json.loads(tools.cve_plan({"host": host}))
    took = round(time.time() - started, 1)
    steps = payload.get("steps") or []
    if steps:
        outcome, detail = "measured", f"{len(steps)} step(s) for {payload.get('pending_count')} pending update(s)"
    else:
        outcome = "measured"
        detail = ("no steps — " + "; ".join(r.get("reason", "") for r in payload.get("refusals") or [])
                  + " (a clean host is a valid answer, not a broken plan)")
    rows.append({"surface": f"update proposal · {host}", "outcome": outcome, "detail": detail,
                 "seconds": took})
    for step in steps:
        rows.append({"surface": f"  ↳ {step['action']}", "outcome": "step",
                     "detail": f"{step['command']} · risk {step['risk']} · "
                               f"reverse: {step.get('reversal') or '—'}",
                     "seconds": None})


def check_advisories(rows: list[dict]) -> None:
    """4. Is the advisory feed answering (the only source that names a CVE for a pending update)?"""
    stored = store.load_scan() or {}
    scan = stored.get("scan") or {}
    if not scan:
        rows.append({"surface": "advisory feed", "outcome": "could not look",
                     "detail": "no scan on disk yet", "seconds": None})
        return
    ok = scan.get("usn_ok")
    rows.append({
        "surface": "advisory feed",
        "outcome": "measured" if ok else "could not look",
        "detail": f"{scan.get('usn_url')} · fetched {scan.get('usn_fetched_at')}",
        "seconds": None,
    })


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove each Patch Sentinel surface measured something")
    parser.add_argument("--host", default=None,
                        help="a declared host label to scan and plan for (default: this machine)")
    parser.add_argument("--json", action="store_true", help="machine-readable rows")
    args = parser.parse_args()

    tools.configure(store.load_settings())
    # a local host has no target (None), a remote one carries user@host:port
    host = args.host or next((h["label"] for h in tools._inventory()
                              if h.get("target") in (None, "", "local")), "")

    rows: list[dict] = []
    check_scan(rows, args.host)
    check_libraries(rows)
    check_plan(rows, host)
    check_advisories(rows)

    if args.json:
        print(json.dumps({"host": host, "rows": rows}, indent=1))
    else:
        width = max(len(r["surface"]) for r in rows)
        print(f"\npatch-sentinel self-check · {time.strftime('%Y-%m-%d %H:%M:%S')} · host {host}\n")
        for row in rows:
            mark = {"measured": "ok  ", "finding": "find", "step": "    ",
                    "could not look": "BLIND"}.get(row["outcome"], "?   ")
            took = f"{row['seconds']}s" if row["seconds"] is not None else ""
            print(f"  [{mark}] {row['surface'].ljust(width)}  {row['detail']}  {took}")
        blind = sum(1 for r in rows if r["outcome"] == "could not look")
        print(f"\n  {len(rows) - blind} surface(s) answered, {blind} could not look"
              + ("  → exit 2" if blind else "  → exit 0") + "\n")

    return 2 if any(r["outcome"] == "could not look" for r in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
