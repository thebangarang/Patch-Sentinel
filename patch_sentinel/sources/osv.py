"""osv.dev — the advisory source for language packages, and for distros without a first-party feed.

Why this and not a scanner binary: OSV answers "which known vulnerabilities affect version X of
package Y?" over HTTP, for npm, PyPI, crates.io, Go, NuGet, Packagist (PHP), RubyGems, Maven and
the distro ecosystems, in batches of up to 1000, with no key, no database on disk and no licence
question. Measured 2026-11-06: 0.4 s for three queries, lodash 4.17.20 returning four advisories.

What OSV is not: a verdict. It says a version is affected; it does not know that a Debian
backport fixed the issue in place, so a distro package's advisory list can over-report. That is
why the OS package verdict stays with the archive (design rule 2) and OSV is used where there is
no archive — language packages, whose "fix" is simply the next published version.

Nothing here runs at import; every call is made from a tool handler.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

API = "https://api.osv.dev/v1"
BATCH_LIMIT = 500                 # the API accepts 1000; 500 keeps the payload readable
USER_AGENT = "hermes patch-sentinel (github.com/thebangarang/Patch-Sentinel)"


def _post(url: str, payload: dict, timeout: int) -> dict:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def _get(url: str, timeout: int) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def query(components: list[dict], timeout: int = 25) -> dict:
    """``[{package, version, ecosystem}]`` → ``{"ok": True, "results": [[id, ...], ...]}``.

    The order matches the input, so a caller can zip the answers back onto its inventory.
    """
    if not components:
        return {"ok": True, "results": [], "queried": 0}
    results: list[list[str]] = []
    try:
        for start in range(0, len(components), BATCH_LIMIT):
            chunk = components[start:start + BATCH_LIMIT]
            payload = {"queries": [{"version": c["version"],
                                    "package": {"name": c["package"],
                                                "ecosystem": c["ecosystem"]}}
                                   for c in chunk]}
            answer = _post(f"{API}/querybatch", payload, timeout)
            for item in answer.get("results") or []:
                results.append([v["id"] for v in (item.get("vulns") or []) if v.get("id")])
    except urllib.error.HTTPError as exc:
        return {"ok": False, "why": f"OSV answered HTTP {exc.code}", "results": [],
                "queried": len(components)}
    except Exception as exc:                              # noqa: BLE001 - reported, never raised
        return {"ok": False, "why": f"OSV query failed: {type(exc).__name__}: {exc}",
                "results": [], "queried": len(components)}
    if len(results) != len(components):
        return {"ok": False, "why": "OSV returned a different number of results than queries",
                "results": [], "queried": len(components)}
    return {"ok": True, "results": results, "queried": len(components)}


def vuln(vuln_id: str, timeout: int = 20) -> dict | None:
    """One advisory's record, or None. The id is validated by the caller (an osv id shape)."""
    try:
        return _get(f"{API}/vulns/{vuln_id}", timeout)
    except Exception:                                     # noqa: BLE001 - enrichment, not a verdict
        return None


_VERSION_RE = re.compile(r"^\d+(\.\d+)+")   # at least one dot: a bare hash has none


def fixed_versions(record: dict, ecosystem: str, package: str) -> list[str]:
    """The versions that close this advisory for one package, from the record's own ranges.

    OSV allows a ``fixed`` event to be a **git commit** instead of a version (measured on
    urllib3 1.24.1: eleven of the twenty-six matches listed commit hashes). A commit is not a
    version an operator can install, so the payload keeps the version-shaped ones only — the
    alternative is a field that looks like advice and cannot be acted on.
    """
    out: list[str] = []
    for affected in record.get("affected") or []:
        name = ((affected.get("package") or {}).get("name") or "")
        eco = ((affected.get("package") or {}).get("ecosystem") or "")
        if ecosystem and eco and eco != ecosystem:
            continue
        if package and name and name.lower() != package.lower():
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed and _VERSION_RE.match(str(fixed)) and fixed not in out:
                    out.append(fixed)
    return out


def severity(record: dict) -> str | None:
    """A short severity reading from whatever the record carries (CVSS vector or database label)."""
    for entry in record.get("severity") or []:
        score = (entry.get("score") or "").strip()
        if score.startswith("CVSS"):
            return _cvss_band(score)
        if score:
            return score
    database = record.get("database_specific") or {}
    label = database.get("severity")
    return str(label) if label else None


def _cvss_band(vector: str) -> str:
    """The vector's base score band, without pretending to recompute the score."""
    parts = dict(piece.split(":", 1) for piece in vector.split("/") if ":" in piece)
    if parts.get("A") == "H" and parts.get("C") in ("H", "L"):
        return "high (availability impact on a network service)"
    if parts.get("C") == "H" or parts.get("I") == "H":
        return "critical (loss of confidentiality or integrity)"
    return "moderate"


_HEADING_RE = re.compile(r"^#{1,6}[^\n]*$", re.M)
_WORKAROUND_RE = re.compile(r"^#{1,6}\s*(workarounds?|mitigations?|temporary (fix|mitigation)|"
                            r"remediations?)\b", re.I | re.M)


def workaround(record: dict) -> str | None:
    """The advisory's own workaround section, when it has one.

    "Waiting for the distro to ship a patch" is not the same as "nothing can be done": many advisories
    carry a Workarounds section (disable a feature, set a flag, block a route). Those words are the
    vendor's, not ours — this quotes them rather than inventing mitigations, which is the only way a
    temporary fix can be trusted.
    """
    details = record.get("details") or ""
    if not details:
        return None
    match = _WORKAROUND_RE.search(details)
    if not match:
        return None
    rest = details[match.end():]
    following = _HEADING_RE.search(rest)
    section = (rest[:following.start()] if following else rest).strip()
    section = " ".join(line.strip() for line in section.splitlines() if line.strip())
    return section[:700] or None


def summarise(record: dict, ecosystem: str, package: str) -> dict:
    """The four things a person needs: what it is, how bad, what fixes it, what else it is called.

    Plus, when the advisory carries one, the vendor's own workaround — the temporary mitigation an
    operator can apply while the patched version is not available yet.
    """
    return {
        "id": record.get("id"),
        "aliases": [a for a in (record.get("aliases") or [])][:4],
        "summary": (record.get("summary") or record.get("details") or "").strip().split("\n")[0][:200],
        "severity": severity(record),
        "published": record.get("published"),
        "fixed": fixed_versions(record, ecosystem, package),
        "workaround": workaround(record),
        "url": f"https://osv.dev/vulnerability/{record.get('id')}" if record.get("id") else None,
    }
