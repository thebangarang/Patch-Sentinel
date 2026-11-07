"""Is this actually being exploited, and how likely — two public feeds that answer it.

A list of CVEs sorted by severity is a list. What decides whether an operator drops everything tonight
is whether the vulnerability is *being exploited right now*, and these two feeds say so:

* **CISA KEV** (``known_exploited_vulnerabilities.json``, ~1.8 MB, refreshed daily) — the authoritative
  list of CVEs with evidence of exploitation in the wild, each with the date it was added, the action
  the vendor requires and, for federal agencies, a remediation deadline. No key, no quota.
* **EPSS** (``api.first.org``) — the probability that a CVE is exploited in the next 30 days, from the
  FIRST consortium. Batched, no key; the percentile is what makes a 0.03 score legible ("lower than
  94 % of CVEs").

Both are cached: KEV for 12 hours on disk (a daily feed, and a scan must not re-download 1.8 MB on
every click), EPSS in memory for the process. **A feed that could not be read is reported as
unmeasured**, never as "nothing is exploited" — the same rule the rest of this plugin lives by.
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path

from .. import store

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_MAX_AGE = 12 * 3600          # the feed is daily; 12 h keeps a scan honest without hammering it
TIMEOUT = 30
EPSS_CHUNK = 50


def _get(url: str, timeout: int = TIMEOUT) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "patch-sentinel/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as answer:
        return answer.read()


def kev(force: bool = False) -> dict:
    """``{cve: {name, vendor, product, added, due, ransomware, action}}``, cached 12 h on disk.

    Returns ``{}`` when the feed could not be read — callers must treat that as *unmeasured*, and the
    payload says so with ``state: "unmeasured"``.
    """
    cache = Path(store.data_dir()) / "kev.json"
    try:
        if not force and cache.exists() and (time.time() - cache.stat().st_mtime) < KEV_MAX_AGE:
            raw = cache.read_bytes()
        else:
            raw = _get(KEV_URL)
            cache.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache.with_suffix(".tmp")
            tmp.write_bytes(raw)
            tmp.replace(cache)                    # atomic: a half-written feed must never be read
    except Exception:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    entries = {}
    for item in data.get("vulnerabilities") or []:
        cve = (item.get("cveID") or "").strip().upper()
        if not cve:
            continue
        entries[cve] = {
            "name": item.get("vulnerabilityName"),
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "added": item.get("dateAdded"),
            "due": item.get("dueDate"),
            "ransomware": (item.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "action": item.get("requiredAction"),
            "description": item.get("shortDescription"),
        }
    return entries


_EPSS_CACHE: dict[str, dict] = {}


def epss(cves: list[str], timeout: int = TIMEOUT) -> dict:
    """``{cve: {score, percentile, date}}`` for the CVEs the caller asks about.

    Batched 50 at a time; a chunk that fails is simply absent from the answer, which each caller
    renders as "no score", never as zero risk.
    """
    wanted = [c for c in dict.fromkeys(c.strip().upper() for c in cves or []) if c]
    missing = [c for c in wanted if c not in _EPSS_CACHE]
    for start in range(0, len(missing), EPSS_CHUNK):
        chunk = missing[start:start + EPSS_CHUNK]
        try:
            payload = json.loads(_get(f"{EPSS_URL}?cve={','.join(chunk)}", timeout).decode() or "{}")
        except Exception:
            continue
        for row in payload.get("data") or []:
            cve = (row.get("cve") or "").upper()
            if not cve:
                continue
            try:
                score = float(row.get("epss"))
            except (TypeError, ValueError):
                continue
            _EPSS_CACHE[cve] = {"score": score,
                                "percentile": float(row.get("percentile") or 0),
                                "date": row.get("date")}
    return {c: _EPSS_CACHE[c] for c in wanted if c in _EPSS_CACHE}


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def cve_ids(finding: dict) -> list[str]:
    """Every CVE-shaped id a finding carries, from its own id and its aliases."""
    ids = []
    for value in [finding.get("id")] + list(finding.get("aliases") or []):
        text = str(value or "").strip().upper()
        if CVE_RE.match(text):
            ids.append(text)
        elif text.startswith(("DEBIAN-CVE-", "ALPINE-CVE-", "UBUNTU-CVE-", "RLSA-")):
            # distro records keep the CVE in their own id namespace
            tail = text.split("CVE-", 1)[1] if "CVE-" in text else ""
            if CVE_RE.match("CVE-" + tail):
                ids.append("CVE-" + tail)
    return list(dict.fromkeys(ids))


def annotate_rows(rows: list[dict], field: str = "cves", known: dict | None = None) -> dict:
    """Annotate rows that already carry a list of CVE ids (the vendor-lag rows do)."""
    if known is None:
        known = kev()
    flat = [{"id": cve} for row in rows for cve in (row.get(field) or [])]
    scores = epss([f["id"] for f in flat]) if flat else {}
    exploited, ransomware = [], []
    for row in rows:
        ids = [str(c).upper() for c in (row.get(field) or [])]
        hits = [c for c in ids if c in known]
        if hits:
            first = known[hits[0]]
            row["kev"] = {"cves": hits, "name": first.get("name"), "added": first.get("added"),
                          "due": first.get("due"), "action": first.get("action"),
                          "ransomware": any(known[c].get("ransomware") for c in hits)}
            exploited.extend(hits)
            if row["kev"]["ransomware"]:
                ransomware.extend(hits)
        best = max((scores[c]["score"] for c in ids if c in scores), default=None)
        if best is not None:
            row["epss"] = best
    return {"kev_state": "measured" if known else "unmeasured", "kev_catalog": len(known),
            "kev_count": len(set(exploited)), "exploited": sorted(set(exploited)),
            "ransomware": sorted(set(ransomware))}


def annotate(findings: list[dict], known: dict | None = None) -> dict:
    """Attach ``kev`` and ``epss`` to every finding, and summarise.

    Returns ``{"kev_state": "measured"|"unmeasured", "kev_count": n, "exploited": [cve...],
    "ransomware": [cve...]}``. The findings themselves are mutated in place.
    """
    if known is None:
        known = kev()
    wanted = [cve for finding in findings for cve in cve_ids(finding)]
    scores = epss(wanted) if wanted else {}
    exploited, ransomware = [], []
    for finding in findings:
        ids = cve_ids(finding)
        hits = [c for c in ids if c in known]
        if hits:
            first = known[hits[0]]
            finding["kev"] = {"cves": hits, "name": first.get("name"),
                              "added": first.get("added"), "due": first.get("due"),
                              "action": first.get("action"),
                              "ransomware": any(known[c].get("ransomware") for c in hits)}
            exploited.extend(hits)
            if finding["kev"]["ransomware"]:
                ransomware.extend(hits)
        best = max((scores[c]["score"] for c in ids if c in scores), default=None)
        if best is not None:
            finding["epss"] = best
    return {"kev_state": "measured" if known else "unmeasured",
            "kev_catalog": len(known),
            "kev_count": len(set(exploited)),
            "exploited": sorted(set(exploited)),
            "ransomware": sorted(set(ransomware)),
            "scored": sum(1 for finding in findings if finding.get("epss") is not None)}
