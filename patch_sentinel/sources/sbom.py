"""CycloneDX export: make the scan's inventory portable.

The plugin's own store is not an interchange format. A CycloneDX document is: Grype, OSV-Scanner,
Dependency-Track and a customer's security team all read it, which means the work this scan did can be
re-checked by another tool without trusting our verdict.

What goes in: every package this scan holds — the language stores, every virtualenv, jars on disk, and
the pending OS packages of the selected host. What does **not**: the whole installed OS package set,
because this plugin never enumerates it (it reads the update list, not `dpkg -l`). The document says so
in `metadata.properties` rather than letting a reader assume completeness — an SBOM that silently omits
half a machine is worse than no SBOM.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re

#: CycloneDX purl types per OSV ecosystem.
PURL_TYPES = {"PyPI": "pypi", "npm": "npm", "Maven": "maven", "Go": "golang", "crates.io": "cargo",
              "Packagist": "composer", "RubyGems": "gem", "NuGet": "nuget", "Pub": "pub"}

_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def _segment(value: str) -> str:
    return _SAFE.sub("-", str(value or ""))


def purl(ecosystem: str, package: str, version: str) -> str | None:
    """`Maven group:artifact` → `pkg:maven/group/artifact@version`; the rest are one-segment."""
    kind = PURL_TYPES.get(ecosystem)
    if not kind or not package:
        return None
    name = str(package)
    if kind == "maven" and ":" in name:
        group, _, artifact = name.partition(":")
        path = f"{_segment(group)}/{_segment(artifact)}"
    elif kind == "npm" and name.startswith("@") and "/" in name:
        # a scoped package keeps its scope segment: pkg:npm/%40scope/name@1.0.0
        scope, _, rest = name.partition("/")
        path = f"%40{_segment(scope[1:])}/{_segment(rest)}"
    elif kind in ("npm", "golang", "composer", "gem", "nuget", "pypi", "cargo", "pub"):
        path = _segment(name)
    else:
        path = _segment(name)
    return f"pkg:{kind}/{path}@{_segment(version)}"


def build(components: list[dict], host: str, os_label: str | None = None,
          pending: list[dict] | None = None, extra_properties: dict | None = None) -> dict:
    """A CycloneDX 1.5 document from whatever the scan holds."""
    seen, items = set(), []
    for row in components:
        key = (row.get("ecosystem"), row.get("package"), row.get("version"))
        if not key[1] or not key[2] or key in seen:
            continue
        seen.add(key)
        identifier = purl(str(row.get("ecosystem")), str(row.get("package")), str(row.get("version")))
        items.append({
            "type": "library",
            "name": str(row.get("package")),
            "version": str(row.get("version")),
            **({"purl": identifier} if identifier else {}),
            "properties": [{"name": "patch-sentinel:source", "value": str(row.get("source") or "")},
                           {"name": "patch-sentinel:ecosystem",
                            "value": str(row.get("ecosystem") or "")}],
        })
    for row in pending or []:
        key = ("os", row.get("package"), row.get("to"))
        if not row.get("package") or not row.get("to") or key in seen:
            continue
        seen.add(key)
        items.append({
            "type": "library",
            "name": str(row["package"]),
            "version": str(row["to"]),
            "properties": [{"name": "patch-sentinel:source", "value": "pending-os-update"},
                           {"name": "patch-sentinel:installed", "value": str(row.get("from") or "")}],
        })
    seed = json.dumps(sorted(f"{item['name']}@{item.get('version')}" for item in items))
    serial = hashlib.sha256((host + seed).encode()).hexdigest()[:32]
    properties = [{"name": "patch-sentinel:host", "value": host},
                  {"name": "patch-sentinel:complete", "value": "false"},
                  {"name": "patch-sentinel:not-included",
                   "value": "the full installed OS package set (this plugin reads the update list, not "
                            "the whole dpkg/rpm database)"}]
    for key, value in (extra_properties or {}).items():
        properties.append({"name": f"patch-sentinel:{key}", "value": str(value)})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-"
                        f"{serial[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "tools": [{"vendor": "patch-sentinel", "name": "cve_sbom", "version": "0.2"}],
            "component": {"type": "operating-system", "name": os_label or host},
            "properties": properties,
        },
        "components": items,
    }
