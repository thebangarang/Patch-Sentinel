"""openSUSE and SUSE: OVAL.

SUSE publishes OVAL for every maintained product — one gzipped XML per release, regenerated on each
advisory and served from ``ftp.suse.com``. Unlike the CVE-centric CSAF documents (one file per
advisory, thousands of them), the OVAL is one download that already joins *CVE → package → the version
that fixes it*, which is what a vendor-lag comparison needs.

Three things this module is careful about:

* **The feed has a date, and it is quoted.** Tumbleweed and Leap 16 are refreshed daily; Leap 15.6's
  file stopped moving when the release left support. A stale feed is not a vendor delay, and saying
  which one it is changes the advice.
* **The epoch is stripped.** OVAL states read ``0:2.44-150000.3.3.1``; an installed RPM reports
  ``2.44-150000.3.3.1``. Comparing them unchanged would order every package wrongly.
* **A parse failure is unmeasured.** A truncated download that yields a partial index would silently
  hide lag rows, so the index is only returned when the document parsed end to end.

The XML is streamed with ``iterparse`` (a 12 MB download expands past 100 MB); only the four tables a
definition needs are kept, and each element is cleared as it closes.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from .vendor import compare

BASE = "https://ftp.suse.com/pub/projects/security/oval/"

#: os_id + VERSION_ID → the file SUSE publishes for it.
PRODUCTS = {
    ("opensuse-leap", "16.0"): "opensuse.leap.16.0.xml.gz",
    ("opensuse-leap", "15.6"): "opensuse.leap.15.6.xml.gz",
    ("opensuse-leap", "15.5"): "opensuse.leap.15.5.xml.gz",
    ("opensuse-tumbleweed", "tumbleweed"): "opensuse.tumbleweed.xml.gz",
    ("sles", "16.0"): "suse.sle.16.0.xml.gz",
    ("sles", "15.6"): "suse.sle.15.6.xml.gz",
}

CACHE_HOURS = 12
#: A row quotes at most this many CVE ids; the rest are counted. The kernel alone carries thousands.
MAX_CVES_PER_PACKAGE = 6
#: A feed older than this is quoted as stale. SUSE refreshes daily, so a month is a stopped feed,
#: not a quiet week.
STALE_DAYS = 30


def product_file(os_id: str, version_id: str) -> str | None:
    """Which OVAL file describes this product, or ``None`` when SUSE does not publish one."""
    key = ((os_id or "").strip().lower(), (version_id or "").strip().lower())
    if key in PRODUCTS:
        return PRODUCTS[key]
    # a Leap minor we did not enumerate, e.g. 15.7 → try the documented pattern
    if key[0] == "opensuse-leap" and re.fullmatch(r"\d+\.\d+", key[1]):
        return f"opensuse.leap.{key[1]}.xml.gz"
    if key[0] == "opensuse-tumbleweed":
        return "opensuse.tumbleweed.xml.gz"
    return None


def _local(tag: str) -> str:
    return tag.split("}")[-1]


def _strip_epoch(evr: str) -> str:
    value = (evr or "").strip()
    return value.split(":", 1)[1] if re.match(r"^\d+:", value) else value


def parse(path: Path | str) -> dict[str, dict]:
    """``{package: {version, notice, cves}}`` from an OVAL document.

    ``version`` is the *fixed* version named by the state a definition points at: the vulnerable range
    is ``evr less than X``, so X is where the fix starts.
    """
    objects: dict[str, str] = {}
    states: dict[str, str] = {}
    tests: dict[str, tuple[str, str]] = {}
    definitions: dict[str, tuple[str, list[str]]] = {}

    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for _, elem in ET.iterparse(handle, events=("end",)):
            tag = _local(elem.tag)
            if tag == "rpminfo_object":
                name = None
                for child in elem:
                    if _local(child.tag) == "name":
                        name = (child.text or "").strip()
                if name and elem.get("id"):
                    objects[elem.get("id")] = name
            elif tag == "rpminfo_state":
                evr = None
                for child in elem:
                    if _local(child.tag) == "evr":
                        evr = (child.text or "").strip()
                if evr and elem.get("id"):
                    states[elem.get("id")] = _strip_epoch(evr)
            elif tag == "rpminfo_test":
                object_ref = state_ref = None
                for child in elem:
                    if _local(child.tag) == "object":
                        object_ref = child.get("object_ref")
                    elif _local(child.tag) == "state":
                        state_ref = child.get("state_ref")
                if object_ref and state_ref and elem.get("id"):
                    tests[elem.get("id")] = (object_ref, state_ref)
            elif tag == "definition":
                title = ""
                for child in elem.iter():
                    if _local(child.tag) == "title":
                        title = (child.text or "").strip()
                        break
                if "CVE-" in title:
                    refs = [child.get("test_ref") for child in elem.iter()
                            if _local(child.tag) == "criterion"]
                    definitions[elem.get("id")] = (title, [r for r in refs if r])
                elem.clear()

    if not objects or not states or not tests:
        raise ValueError("the OVAL document has no tests — refusing to call that an empty index")

    index: dict[str, dict] = {}
    seen: dict[str, set] = {}
    for _, (cve, refs) in definitions.items():
        for ref in refs:
            pair = tests.get(ref)
            if not pair:
                continue
            package, fixed = objects.get(pair[0]), states.get(pair[1])
            if not package or not fixed:
                continue
            # an OVAL package can carry thousands of CVEs (the kernel does): the row quotes a sample
            # and counts the rest, so one package cannot flood a payload
            cves = seen.setdefault(package, set())
            known = index.get(package)
            if known is None:
                index[package] = {"version": fixed, "notice": cve, "cves": [], "cve_count": 0}
                known = index[package]
            if cve not in cves and len(known["cves"]) < MAX_CVES_PER_PACKAGE:
                known["cves"].append(cve)
            cves.add(cve)
            if compare(fixed, known["version"]) > 0:
                known["version"], known["notice"] = fixed, cve
    for package, known in index.items():
        known["cve_count"] = len(seen.get(package) or ())
    return index


def fetch(filename: str, cache_dir: str | None, timeout: int = 120) -> tuple[Path, dict]:
    """Download (or reuse) the OVAL file; return its path and its metadata."""
    directory = Path(cache_dir or os.path.join(os.path.expanduser("~"), ".cache", "patch-sentinel"))
    directory = directory / "oval"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / filename
    meta_path = directory / (filename + ".meta.json")
    meta: dict = {}
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text())
        except ValueError:
            meta = {}
    fresh = (target.is_file() and meta.get("fetched_at")
             and time.time() - float(meta["fetched_at"]) < CACHE_HOURS * 3600)
    if fresh:
        return target, meta

    url = BASE + filename
    request = urllib.request.Request(url, headers={"User-Agent": "patch-sentinel/0.2"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read()
        modified = response.headers.get("Last-Modified") or ""
    if len(payload) < 1024:
        raise ValueError(f"{url} answered {len(payload)} bytes — not an OVAL document")
    target.write_bytes(payload)
    meta = {"source_url": url, "last_modified": modified, "fetched_at": time.time(),
            "bytes": len(payload)}
    meta_path.write_text(json.dumps(meta))
    return target, meta


def advisories(os_id: str, version_id: str, cache_dir: str | None = None,
               timeout: int = 120) -> tuple[dict[str, dict], dict]:
    """The OVAL index for this product, plus what the feed's own date says about it."""
    filename = product_file(os_id, version_id)
    if filename is None:
        raise ValueError(f"SUSE publishes no OVAL for {os_id or 'this product'} {version_id or ''}".strip())
    path, meta = fetch(filename, cache_dir, timeout=timeout)
    index = parse(path)
    age_days = None
    if meta.get("last_modified"):
        try:
            parsed = time.mktime(time.strptime(meta["last_modified"], "%a, %d %b %Y %H:%M:%S %Z"))
            age_days = round((time.time() - parsed) / 86400, 1)
        except (ValueError, OverflowError):
            age_days = None
    return index, {"product": filename, "feed_date": meta.get("last_modified") or "",
                   "age_days": age_days, "stale": bool(age_days is not None and age_days > STALE_DAYS),
                   "source_url": meta.get("source_url") or BASE + filename}
