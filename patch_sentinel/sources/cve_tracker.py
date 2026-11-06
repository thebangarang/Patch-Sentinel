"""Ubuntu's CVE tracker, per CVE — **context only**.

Design rule 2 and decision D3: this page may never be the sole input to a verdict. It is read
for the narrative and for the versions it *intends* to ship, while the archive (the apt
simulation) decides what is true here, now. The incident it comes from is in this repository's
own history: the tracker read `pending` for the kernel fix for a week after that exact version
was published, installable and running.

So the payload this module produces is labelled `context_only` and carries the tracker's own
words; the caller compares it against the measurement and says when the two disagree.
"""
from __future__ import annotations

import datetime as dt
import json
import urllib.error
import urllib.request

from .. import verdict

CVE_URL = "https://ubuntu.com/security/cves/{cve_id}.json"
USER_AGENT = "hermes patch-sentinel (github.com/thebangarang/Patch-Sentinel)"
# statuses that mean "not fixed in this release yet", in the tracker's own vocabulary
OPEN_STATUSES = ("pending", "needed", "deferred", "active", "unknown")


def fetch(cve_id: str, timeout: int = 20) -> dict:
    """Fetch one CVE record. Returns a typed result; never raises."""
    url = CVE_URL.format(cve_id=cve_id)
    fetched_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        why = ("no such CVE in Ubuntu's tracker" if exc.code == 404
               else f"tracker answered HTTP {exc.code}")
        return {"ok": False, "why": why, "url": url, "fetched_at": fetched_at}
    except Exception as exc:                                    # noqa: BLE001 - never raise
        return {"ok": False, "why": f"tracker fetch failed: {type(exc).__name__}: {exc}",
                "url": url, "fetched_at": fetched_at}
    if not isinstance(payload, dict):
        return {"ok": False, "why": "tracker answered an unexpected shape",
                "url": url, "fetched_at": fetched_at}
    return {"ok": True, "record": payload, "url": url, "fetched_at": fetched_at}


def parse(record: dict, release: str) -> dict:
    """The facts worth quoting, for one release: per-package status and the version it names."""
    statuses = []
    for package in (record.get("packages") or []):
        name = package.get("name")
        for entry in (package.get("statuses") or []):
            if entry.get("release_codename") != release:
                continue
            status = str(entry.get("status") or "").strip()
            if not status or status.upper() == "DNE":
                continue                       # does not exist in this release: not a fact about us
            statuses.append({"package": name, "status": status,
                             "version": entry.get("description") or "",
                             "pocket": entry.get("pocket") or "",
                             "open": status.lower() in OPEN_STATUSES})
    return {
        "id": record.get("id"),
        "status": record.get("status"),
        "priority": record.get("priority"),
        "cvss3": record.get("cvss3"),
        "published": record.get("published"),
        "updated_at": record.get("updated_at"),
        "description": (record.get("description") or "").strip()[:800],
        "notices_ids": record.get("notices_ids") or [],
        "release": release,
        "statuses": statuses,
        "open_statuses": [s for s in statuses if s["open"]],
    }


def compare_to_measurement(parsed: dict, host: dict) -> dict:
    """Where the tracker and the measurement disagree — the one thing this source is for.

    Compares only kernels this host could actually be running: the tracker's flavour-agnostic
    ``linux`` source package and the package matching the running kernel's own flavour. Another
    flavour's fix says nothing about this host, and claiming otherwise is the over-claim this
    plugin exists not to make — those are listed in ``not_compared`` instead.
    """
    kernel = host.get("kernel") or {}
    running = str(kernel.get("running") or "")
    installed = str(kernel.get("installed") or "")
    packages = kernel.get("installed_packages") or {}
    flavour = running.split("-", 3)[3] if running.count("-") >= 3 else ""
    ours_dpkg = packages.get(installed) or packages.get(running) or ""

    findings, not_compared = [], []
    for slot in parsed.get("statuses") or []:
        package = str(slot.get("package") or "")
        if not package.startswith("linux"):
            continue
        relevant = package == "linux" or (flavour and package == f"linux-{flavour}")
        if not relevant:
            not_compared.append({"package": package, "tracker_status": slot.get("status"),
                                 "version": slot.get("version"),
                                 "why": f"this host runs the {flavour or 'unknown'} flavour"})
            continue
        version = str(slot.get("version") or "")
        if not version or not running:
            continue
        same_version = bool(ours_dpkg) and ours_dpkg == version
        newer_abi = verdict.abi(ours_dpkg or installed) >= verdict.abi(version) > ((), 0)
        if slot.get("open") and (same_version or newer_abi):
            findings.append({
                "package": package,
                "tracker_status": slot.get("status"),
                "tracker_names_version": version,
                "we_run": running,
                "we_have_installed": ours_dpkg or installed,
                "certainty": "exact version" if same_version else "same or newer kernel release",
                "reading": "the tracker's own fix version is already installed and running here, "
                           "while its status still reads open — the archive is ahead of the page "
                           "(rule 2: the archive wins)",
                "verified_by": "uname -r / dpkg-query on the host, at the scan's timestamp",
            })
    return {"disagreements": findings, "not_compared": not_compared,
            "basis": "kernel packages only: the scan records those, not every installed package"}


def narrative(parsed: dict) -> str:
    if not parsed.get("statuses"):
        return f"the tracker records no {parsed.get('release')} status for this CVE"
    bits = [f"{s['package']}: {s['status']}" + (f" ({s['version']})" if s.get("version") else "")
            for s in parsed["statuses"][:6]]
    return "; ".join(bits)
