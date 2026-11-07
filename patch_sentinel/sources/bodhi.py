"""Fedora's advisory feed: Bodhi.

Fedora has no single per-release "fixed version" document like Ubuntu's USN feed or Debian's OSV
ranges. What it does have is Bodhi — the update system every Fedora package goes through — and its
public API answers one precise question: *which stable security updates exist for this release, and
which build versions do they push?*

That is exactly the vendor-lag comparison:

    Bodhi says openssl-3.2.5 is stable and security   (the vendor shipped a fix)
    the archive on this host offers 3.2.4 or nothing   (this machine cannot have it yet)
    → vendor lag, with the FEDORA-… alias and the CVEs it carries

The query is bounded: the newest ``pages × rows`` stable security updates for the host's release,
indexed by package. One HTTP call per page, cached by the caller. Release names are Bodhi's short
tags (``F45``); a host that reports ``Tumbleweed``-style names gets a refusal, not a guess.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

from .vendor import compare

BASE = "https://bodhi.fedoraproject.org/updates/"
DEFAULT_PAGES = 4
DEFAULT_ROWS = 100
CACHE_HOURS = 6
#: A Fedora update can close dozens of CVEs; a row quotes a sample and counts the rest.
MAX_CVES = 6


def release_tag(version_id: str) -> str | None:
    """``45`` → ``F45``; ``rawhide`` → ``rawhide``. Anything else is refused, not guessed."""
    value = (version_id or "").strip()
    if not value:
        return None
    if value.lower() in ("rawhide", "eln"):
        return value.lower()
    major = value.split(".")[0]
    return "F" + major if major.isdigit() else None


def _split_nvr(nvr: str) -> tuple[str, str] | None:
    """``ansible-core-2.22.0~b2-1.eln159`` → (``ansible-core``, ``2.22.0~b2``).

    The name may itself contain dashes, so the split is from the right — release, then version.
    """
    parts = (nvr or "").rsplit("-", 2)
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return None
    return parts[0], parts[1]


def advisories(version_id: str, pages: int = DEFAULT_PAGES, rows: int = DEFAULT_ROWS,
               timeout: int = 60, cache_dir: str | None = None) -> dict[str, dict]:
    """``{package: {version, notice, cves}}`` — the newest stable security build per package.

    Raises on a network or shape error so the caller can record *unmeasured*; never returns an empty
    dict to mean "nothing published", which would read as "no vendor lag".

    A page of 100 updates takes about ten seconds at Bodhi, so the index is cached: a second scan in
    the same day answers from disk.
    """
    tag = release_tag(version_id)
    if tag is None:
        raise ValueError(f"{version_id!r} is not a Fedora release name")

    cache = Path(cache_dir or os.path.join(os.path.expanduser("~"), ".cache", "patch-sentinel"))
    cache = cache / "bodhi"
    cache.mkdir(parents=True, exist_ok=True)
    cached = cache / f"{tag}.json"
    if cached.is_file():
        try:
            payload = json.loads(cached.read_text())
            if time.time() - float(payload.get("fetched_at") or 0) < CACHE_HOURS * 3600:
                return payload["index"]
        except (ValueError, KeyError):
            pass

    index: dict[str, dict] = {}
    for page in range(1, max(1, pages) + 1):
        query = urllib.parse.urlencode({"type": "security", "status": "stable", "releases": tag,
                                        "rows_per_page": max(1, rows), "page": page})
        with urllib.request.urlopen(BASE + "?" + query, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        updates = payload.get("updates") or []
        if not updates:
            break
        for update in updates:
            if update.get("status") != "stable" or update.get("type") != "security":
                continue
            alias = update.get("alias") or ""
            cves = [cve for cve in (update.get("cves") or []) if cve]
            for build in update.get("builds") or []:
                split = _split_nvr(build.get("nvr") or "")
                if not split:
                    continue
                name, version = split[0].lower(), split[1]
                known = index.get(name)
                if known is None or compare(version, known["version"]) > 0:
                    index[name] = {"version": version, "notice": alias,
                                   "cves": (cves or [alias])[:MAX_CVES]}
    cached.write_text(json.dumps({"fetched_at": time.time(), "release": tag,
                                  "updates_read": len(index), "index": index}))
    return index
