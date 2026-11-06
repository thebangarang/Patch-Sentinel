"""Vendor lag on the distros that publish a machine-readable advisory feed.

Ubuntu answers through its notice feed (``sources/usn.py``) because that feed names the fixed version
per release. The other families needed their own source, and two of them are cheap and authoritative:

* **OSV, per release.** OSV carries Debian, Alpine, Rocky Linux, AlmaLinux and Red Hat advisories whose
  ranges name the version that fixes each CVE for that *release* — ``Debian:12``, ``Alpine:v3.22``,
  ``Rocky Linux:9``. That is exactly the comparison vendor lag needs: advisory says fixed in X, the
  archive offers Y, X > Y means the patch exists and this machine cannot have it yet.
* **Arch's own tracker.** ``security.archlinux.org/all.json`` (about 900 KB) lists every AVG with the
  affected and fixed versions per package. One fetch, no key.

Two families have no such feed available to this plugin and are reported as *not measured*, never as
clean: **Fedora** (Bodhi has the updates, but the CVE-to-build mapping is per-update and needs its own
adapter) and **openSUSE/SLES** (SUSE publishes CSAF/VEX documents, again a separate adapter). A scan of
those hosts says the lag is unmeasured instead of implying there is none.

The distro records key on the **source** package (``openssl``, not ``libssl3``), so installed packages
are mapped back to their source before the query and forward again for the report.
"""
from __future__ import annotations

import concurrent.futures
import json
import re
import urllib.request

from . import osv as osv_source
from . import shell
from . import vendor as verdict

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
ARCH_FEED = "https://security.archlinux.org/all.json"
MAX_QUERIES = 900              # OSV accepts 1000 per batch; stay under it
TIMEOUT = 25

#: distro id → the ecosystem string OSV indexes it under. Ubuntu is absent on purpose: its notice
#: feed already carries the per-release fixed version, and two sources for one fact is two answers.
OSV_FAMILY = {
    "debian": "Debian:{major}",
    "alpine": "Alpine:v{version}",
    "rocky": "Rocky Linux:{major}",
    "almalinux": "AlmaLinux:{major}",
    "rhel": "Red Hat:{major}",
    "centos": "Red Hat:{major}",
}


def ecosystem_for(os_id: str, version_id: str) -> str | None:
    """``debian``/``12`` → ``Debian:12``; ``alpine``/``3.22.6`` → ``Alpine:v3.22``."""
    template = OSV_FAMILY.get((os_id or "").strip().lower())
    if not template:
        return None
    version = (version_id or "").strip()
    major = version.split(".")[0] if version else ""
    if not major:
        return None
    if "{version}" in template:
        # Alpine tags its advisories by minor series (v3.22), not by patch release
        parts = version.split(".")
        series = ".".join(parts[:2]) if len(parts) >= 2 else major
        return template.format(version=series, major=major)
    return template.format(major=major, version=version)


# --------------------------------------------------------------------------- installed inventory

LIST_COMMANDS = {
    # binary package, version, source package (the field the advisories key on)
    "apt": ("dpkg-query -W -f='${Package}\\t${Version}\\t${Source}\\n' 2>/dev/null", "deb"),
    "apk": ("apk info -v 2>/dev/null", "apk"),
    "dnf": ("rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{SOURCERPM}\\n' 2>/dev/null", "rpm"),
    "pacman": ("pacman -Q 2>/dev/null", "pacman"),
}


def parse_installed(text: str, flavour: str) -> list[dict]:
    """→ ``[{package, version, source}]``. Never raises: unparsable lines are dropped."""
    rows: list[dict] = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if flavour in ("deb", "rpm"):
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            name, version = parts[0].strip(), parts[1].strip()
            source = parts[2].strip() if len(parts) > 2 else name
            # dpkg prints "src (1.2.3)" when the source version differs; the name is what matters
            source = re.sub(r"\s*\(.*\)$", "", source) or name
            source = source.split(":")[0]              # strip a multiarch qualifier
            # rpm reports "openssl-3.0.7-27.el9.src.rpm": the name is what precedes the version
            source = re.sub(r"\.src\.rpm$", "", source)
            source = re.split(r"-[0-9]", source)[0]
        elif flavour == "apk":
            # openssl-3.5.1-r0 → ("openssl", "3.5.1-r0"); the version is the first -<digit> segment
            match = re.match(r"^(.+?)-([0-9][^-]*(?:-r[0-9]+)?)$", line.strip())
            if not match:
                continue
            name, version, source = match.group(1), match.group(2), match.group(1)
        else:                                       # pacman -Q: "name version"
            parts = line.split()
            if len(parts) < 2:
                continue
            name, version, source = parts[0], parts[1], parts[0]
        rows.append({"package": name, "version": version, "source": source})
    return rows


#: Has the host refreshed the metadata a "candidate version" comes from? A stale index makes every
#: advisory look like a lag, because the archive has moved on and this machine has not looked.
FRESHNESS = {
    "apt": "find /var/lib/apt/lists -name '*.Packages*' -newermt '-48 hours' 2>/dev/null | head -1",
    "dnf": "find /var/cache/dnf -name '*.solv' -newermt '-48 hours' 2>/dev/null | head -1",
    "apk": "find /var/cache/apk -newermt '-48 hours' 2>/dev/null | head -1",
    "pacman": "find /var/lib/pacman/sync -newermt '-48 hours' 2>/dev/null | head -1",
}

CANDIDATE_COMMANDS = {
    "apt": "apt-cache policy {names} 2>/dev/null",
    "apk": "apk policy {names} 2>/dev/null",
    "dnf": "dnf -q list --available {names} 2>/dev/null",
    "pacman": "pacman -Si {names} 2>/dev/null",
}


def candidate_command(family: str, names: list[str]) -> str:
    return CANDIDATE_COMMANDS[family].format(names=" ".join(names[:80]))


def parse_candidates(text: str, family: str) -> dict[str, str]:
    """The archive's best version per package, from whichever query the family uses."""
    best: dict[str, str] = {}
    if family == "apt":
        current = None
        for line in (text or "").splitlines():
            if line and not line.startswith(" "):
                current = line.rstrip(":")
            elif current and line.strip().startswith("Candidate:"):
                version = line.split("Candidate:", 1)[1].strip()
                if version and version != "(none)":
                    best[current] = version
    elif family == "apk":
        current = None
        for line in (text or "").splitlines():
            stripped = line.strip()
            if stripped.endswith(":") and not stripped.startswith("version"):
                current = stripped.rstrip(":")
            elif current and stripped.startswith("version:"):
                best[current] = stripped.split(":", 1)[1].strip()
    elif family == "dnf":
        for line in (text or "").splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] not in ("Available", "Installed"):
                best.setdefault(parts[0].split(".")[0], parts[1])
    elif family == "pacman":
        # `pacman -Si` prints one "Key : value" block per package, name first, version later
        name = None
        for line in (text or "").splitlines():
            if ":" not in line:
                name = None
                continue
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if key == "Name":
                name = value
            elif key == "Version" and name:
                best[name] = value
                name = None
    return best


# --------------------------------------------------------------------------- advisory sources

def _post(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:
        return json.loads(answer.read().decode() or "{}")


def _get(url: str) -> str:
    with urllib.request.urlopen(url, timeout=TIMEOUT) as answer:
        return answer.read().decode()


MAX_DETAILS = 240              # per scan: each one is a detail fetch, so the budget is explicit
DETAIL_WORKERS = 8


def _fixed_for(record: dict, ecosystem: str, package: str) -> str:
    """The highest version this advisory says fixes *this* package, for this release.

    Matching on the ecosystem alone is not enough: one CVE can name several source packages, and taking
    the maximum over all of them produced ``libgnutls30 → 1:15.b-dfsg-1`` — another package's version,
    reported as a lag that does not exist.
    """
    fixed = ""
    for affected in record.get("affected") or []:
        entry_package = affected.get("package") or {}
        if entry_package.get("ecosystem") != ecosystem or entry_package.get("name") != package:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                candidate = event.get("fixed")
                if candidate and (not fixed or verdict.compare(candidate, fixed) > 0):
                    fixed = candidate
    return fixed


def osv_advisories(ecosystem: str, pairs: list[tuple[str, str]]) -> dict[str, dict]:
    """``(source package, version)`` pairs → ``{package: {version, notice, cves}}``.

    The batch endpoint answers with ``{id, modified}`` only — measured, not assumed: it is a *matching*
    API, and the fixed versions live in the record. So the ids are collected from one batch and the
    records fetched after, in parallel, under an explicit cap. Treating a batch hit as if it carried
    ``affected`` is how a host with 79 vulnerable packages reported zero advisories.
    """
    unique: dict[str, str] = {}
    for name, version in pairs:
        if name and version and name not in unique:
            unique[name] = version
    names = sorted(unique)[:MAX_QUERIES]
    if not names:
        return {}
    answer = _post(OSV_BATCH, {"queries": [
        {"package": {"ecosystem": ecosystem, "name": name}, "version": unique[name]}
        for name in names]})
    results = answer.get("results") or []
    hits: dict[str, list[str]] = {}
    for name, result in zip(names, results):
        ids = [v.get("id") for v in ((result or {}).get("vulns") or []) if v.get("id")]
        if ids:
            hits[name] = ids[:8]            # one package rarely needs more to find its fix
    wanted = sorted({vid for ids in hits.values() for vid in ids})
    records: dict[str, dict] = {}
    if wanted:
        with concurrent.futures.ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
            for vid, record in zip(wanted[:MAX_DETAILS],
                                   pool.map(lambda v: osv_source.vuln(v) or {}, wanted[:MAX_DETAILS])):
                records[vid] = record
    advisories: dict[str, dict] = {}
    for name, ids in hits.items():
        for vid in ids:
            record = records.get(vid)
            if not record:
                continue
            fixed = _fixed_for(record, ecosystem, name)
            if not fixed:
                continue            # open, with nothing published yet: not a lag, just no fix
            entry = advisories.get(name)
            if entry and verdict.compare(entry["version"], fixed) >= 0:
                entry["cves"].append(vid)
                continue
            advisories[name] = {"version": fixed, "notice": vid, "cves": [vid]}
    return advisories


def arch_advisories(text: str, installed: dict[str, str]) -> dict[str, dict]:
    """The Arch tracker's JSON → ``{package: {version, notice, cves}}`` for installed packages."""
    try:
        entries = json.loads(text)
    except ValueError:
        return {}
    advisories: dict[str, dict] = {}
    for entry in entries if isinstance(entries, list) else []:
        fixed = (entry.get("fixed") or "").strip()
        if not fixed:
            continue
        status = (entry.get("status") or "").lower()
        if status in ("not affected", "fixed"):
            # the tracker keeps resolved advisories: only a live one can be lag on this host
            continue
        for name in entry.get("packages") or []:
            if name not in installed:
                continue
            current = advisories.get(name)
            if current and verdict.compare(current["version"], fixed) >= 0:
                current["cves"].extend(entry.get("issues") or [])
                continue
            advisories[name] = {"version": fixed, "notice": entry.get("name"),
                                "cves": list(entry.get("issues") or [])[:4]}
    return advisories


# --------------------------------------------------------------------------- the comparison

def _version_id(target: str | None, timeout: int) -> str:
    """The numeric release, read from the host itself.

    The scan's OS block reports the *codename* (``bookworm``), and a codename in an ecosystem string
    queries nothing and returns nothing — which is indistinguishable from a clean host. So the number
    is asked for explicitly: ``Debian:12``, ``Alpine:v3.22``.
    """
    code, out = shell.run("(. /etc/os-release 2>/dev/null; echo ${VERSION_ID:-unknown})", target,
                          timeout=timeout, path_prefix=shell.SYSTEM_PATH_PREFIX)
    text = (out or "").strip().splitlines()
    return text[0].strip() if text else "unknown"


def assess(target: str | None, family: str, os_id: str, version_id: str,
           timeout: int = 120) -> dict:
    """Measure vendor lag on a Debian/Alpine/RHEL/Arch host.

    Returns ``{"state": "measured"|"unsupported"|"unmeasured", "vendor_lag": [...], "counts": {...},
    "reason": str}``. ``unsupported`` is a fact about the plugin, never about the host.
    """
    if not (version_id or "").strip()[:1].isdigit():
        # a codename is not a release: querying OSV with one answers nothing, quietly
        version_id = _version_id(target, timeout)
    ecosystem = ecosystem_for(os_id, version_id)
    if not ecosystem and family != "pacman":
        # a family with no feed is a fact about the plugin, not about the host: say which feed
        hint = {"fedora": "Fedora needs its Bodhi adapter",
                "opensuse-leap": "openSUSE needs its CSAF/VEX adapter",
                "opensuse-tumbleweed": "openSUSE needs its CSAF/VEX adapter",
                "sles": "SUSE needs its CSAF/VEX adapter"}.get(
                    (os_id or "").lower(), f"{os_id or 'this distribution'} publishes no feed this "
                                           f"plugin reads")
        return {"state": "unsupported", "vendor_lag": [], "counts": {},
                "reason": f"vendor lag is unmeasured here: {hint}. The rest of this scan is measured."}
    command, flavour = LIST_COMMANDS.get(family, (None, ""))
    if command is None:
        return {"state": "unsupported", "vendor_lag": [], "counts": {},
                "reason": f"no vendor-lag source for the {family or 'unknown'} family"}

    code, text = shell.run(command, target, timeout=timeout, path_prefix=shell.SYSTEM_PATH_PREFIX)
    installed = parse_installed(text, flavour)
    if not installed:
        return {"state": "unmeasured", "vendor_lag": [], "counts": {},
                "reason": f"could not list installed packages (rc={code}) — the lag is unmeasured, "
                          f"not zero"}

    if family == "pacman":
        try:
            advisories = arch_advisories(_get(ARCH_FEED),
                                         {row["package"]: row["version"] for row in installed})
        except Exception as exc:            # network, JSON, timeout — all mean unmeasured
            return {"state": "unmeasured", "vendor_lag": [], "counts": {},
                    "reason": f"the Arch tracker could not be read ({type(exc).__name__})"}
    else:
        pairs = [(row["source"], row["version"]) for row in installed]
        try:
            advisories = osv_advisories(ecosystem, pairs)
        except Exception as exc:
            return {"state": "unmeasured", "vendor_lag": [], "counts": {},
                    "reason": f"OSV could not be queried for {ecosystem} ({type(exc).__name__})"}
    if not advisories:
        return {"state": "measured", "vendor_lag": [], "counts": {"vendor_lag": 0},
                "advisories_read": 0,
                "reason": f"{len(installed)} package(s) read against "
                          f"{ecosystem or 'the Arch tracker'}: no open advisory names an "
                          f"installed version"}

    # whose binary carries it? map source → the installed binaries built from it
    binaries: dict[str, list[dict]] = {}
    for row in installed:
        binaries.setdefault(row["source"], []).append(row)

    code, out = shell.run(FRESHNESS.get(family, "true"), target, timeout=timeout,
                          path_prefix=shell.SYSTEM_PATH_PREFIX)
    index_fresh = bool((out or "").strip())

    wanted = sorted({row["package"] for name, entry in advisories.items()
                     for row in binaries.get(name, [])})
    candidates: dict[str, str] = {}
    if wanted:
        code, out = shell.run(candidate_command(family, wanted), target, timeout=timeout,
                              path_prefix=shell.SYSTEM_PATH_PREFIX)
        candidates = parse_candidates(out, family)

    rows: dict[str, dict] = {}
    needed: dict[str, dict] = {}
    for name, entry in advisories.items():
        for row in binaries.get(name, [])[:1]:        # one binary per source is enough to judge
            rows[row["package"]] = {"installed": row["version"],
                                    "candidate": candidates.get(row["package"], "")}
            needed[row["package"]] = entry
    state = verdict.classify(rows, needed)
    return {"state": "measured", "advisories_read": len(advisories),
            "index_fresh": index_fresh,
            "index_note": ("" if index_fresh else
                           "the archive index on this host is older than 48 h, so a version that "
                           "fixes this may already be published — refresh it before acting"),
            "vendor_lag": state["vendor_lag"], "counts": state["counts"],
            "already_fixed": state["already_fixed"], "fix_available": state["fix_available"],
            "reason": ""}
