"""Ubuntu Security Notices — the distribution's own statement of what it fixed, and in which
version. This is the advisory source; the archive (the apt simulation) is the one that decides
what is installable here, and the archive wins when the two disagree (design rule 2, D3).

The feed refuses `limit` above 20 with HTTP 422 (measured 2026-11-06), so the limit is clamped
here rather than being a surprise at call time.

Nothing is fetched at import: `fetch()` runs when a tool handler runs.
"""
from __future__ import annotations

import datetime as dt
import json
import urllib.error
import urllib.request

FEED_URL = "https://ubuntu.com/security/notices.json"
MAX_LIMIT = 20            # 25+ = HTTP 422, measured
USER_AGENT = "hermes patch-sentinel (github.com/thebangarang/Patch-Sentinel)"


def fetch(release: str, limit: int = MAX_LIMIT, timeout: int = 25) -> dict:
    """Fetch recent notices for *release*. Returns a typed result; never raises."""
    limit = max(1, min(int(limit or MAX_LIMIT), MAX_LIMIT))
    url = f"{FEED_URL}?release={release}&limit={limit}"
    fetched_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"ok": False, "why": f"USN feed HTTP {exc.code}", "notices": [],
                "url": url, "fetched_at": fetched_at, "release": release}
    except Exception as exc:                              # noqa: BLE001 - reported, never raised
        return {"ok": False, "why": f"USN feed failed: {type(exc).__name__}: {exc}",
                "notices": [], "url": url, "fetched_at": fetched_at, "release": release}
    notices = data.get("notices") if isinstance(data, dict) else None
    if not isinstance(notices, list):
        return {"ok": False, "why": "USN feed answered an unexpected shape", "notices": [],
                "url": url, "fetched_at": fetched_at, "release": release}
    return {"ok": True, "notices": notices, "url": url, "fetched_at": fetched_at,
            "release": release, "total_results": data.get("total_results")}


def fixed_versions(notice: dict, release: str) -> list[dict]:
    """The packages and fixed versions one notice names for *release*."""
    out = []
    for entry in ((notice.get("release_packages") or {}).get(release) or []):
        name, version = entry.get("name"), entry.get("version")
        if name and version:
            out.append({"package": name, "version": version,
                        "is_source": bool(entry.get("is_source", False))})
    return out


def for_cve(notices: list, cve_id: str) -> list[dict]:
    """Every notice that names this CVE — the advisory trail, not the CVE page's status word."""
    wanted = (cve_id or "").strip().upper()
    if not wanted:
        return []
    hits = []
    for notice in notices:
        ids = {str(x).upper() for x in (notice.get("cves_ids") or [])}
        if wanted in ids:
            hits.append({"id": notice.get("id"), "title": notice.get("title"),
                         "published": notice.get("published"),
                         "summary": (notice.get("summary") or "").strip()[:400]})
    return hits


def nearest(notices: list, cve_id: str, release: str, limit: int = 5) -> list[str]:
    """Advisory ids in the same feed that share a prefix with *cve_id* — for a refusal's `nearest`."""
    wanted = (cve_id or "").strip().upper()
    year = wanted.split("-")[1] if len(wanted.split("-")) > 1 else ""
    out = []
    for notice in notices:
        for cid in (notice.get("cves_ids") or []):
            if year and f"-{year}-" in str(cid).upper():
                out.append(notice.get("id"))
                break
    return sorted(set(x for x in out if x))[:limit]
