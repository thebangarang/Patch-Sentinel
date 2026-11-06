"""The language and framework layer: what the machine's own package managers have installed.

This is the half of the attack surface an OS package manager cannot see — npm, PyPI (and the
ecosystems added the same way: crates.io, Packagist, NuGet, RubyGems, Go, Maven). Each one is a
local command whose output is JSON we parse, so there is no binary to install and no database to
keep in date (the advisories come from :mod:`patch_sentinel.sources.osv`).

What is measured, and what is only claimed:

* **measured**: packages the tool reports as installed for the machine's own user — npm's global
  tree, the first ``python3`` on PATH. That is what a shell can see, so that is what we say.
* **not measured**: per-project dependency trees (a lockfile per repository), virtualenvs other
  than that interpreter, vendor directories, and anything inside a container image. Those are
  named gaps in ``cve_coverage``, not silent passes.

A missing tool is an outcome (``missing``), never an empty list read as clean.
"""
from __future__ import annotations

import datetime as dt
import json

from . import shell

MISSING = "__MISSING__"

# These tools are user-installed as often as system-installed: `npm` typically lives in
# ~/.local/bin, /usr/local/bin or an nvm shim, none of which the scan's system PATH sees. The
# probe exports a PATH that includes them, and asks `command -v` / the tool's own --version
# whether it exists — never the exit code of the listing command, which is non-zero for
# perfectly healthy trees (npm ls exits 1 on a missing peer, not on a missing npm).
# Language tooling lives in the user's directories, not the system's: this asks for the inherited
# PATH plus the places a login shell would add, and nothing more. (A login shell cannot be relied on
# here: measured, `bash -lc 'echo $PATH'` from inside a non-interactive ssh or plugin process
# returned a 63-character system PATH — the user's shims were not in it.)
TOOL_PATH = shell.USER_PATH_PREFIX

INVENTORIES: dict[str, dict] = {
    "npm": {
        "label": "npm (global packages)",
        "candidates": [
            {"detect": "command -v npm", "command": "npm ls -g --json --depth=0",
             "label": "npm's global tree"},
        ],
        "missing_detail": "npm is not on PATH on this host",
    },
    "PyPI": {
        "label": "pip (the interpreter on PATH)",
        # python3 carrying its own pip, then a standalone pip3: measured here, the first python3
        # on PATH can be a uv-managed interpreter with no pip module, while pip3 works.
        "candidates": [
            {"detect": "python3 -m pip --version", "command": "python3 -m pip list --format=json",
             "label": "python3 -m pip"},
            {"detect": "pip3 --version", "command": "pip3 list --format=json",
             "label": "pip3"},
        ],
        "missing_detail": "no python interpreter with pip is on PATH on this host",
    },
}

# The rest of the toolchains, added one reader at a time. Each is a local command whose output is
# either JSON or a stable table — no binaries, no database, and a missing tool is an outcome.
INVENTORIES["Packagist"] = {
    "label": "composer (global packages)",
    "candidates": [{"detect": "command -v composer",
                    "command": "composer global show --format=json",
                    "label": "composer's global vendor"}],
    "missing_detail": "composer is not on PATH on this host",
}
INVENTORIES["RubyGems"] = {
    "label": "gem (local gems)",
    "candidates": [{"detect": "command -v gem", "command": "gem list --local",
                    "label": "gem's local list"}],
    "missing_detail": "ruby/gem is not on PATH on this host",
}
INVENTORIES["crates.io"] = {
    "label": "cargo (installed binaries)",
    "candidates": [{"detect": "command -v cargo", "command": "cargo install --list",
                    "label": "cargo's installed binaries"}],
    "missing_detail": "cargo is not on PATH on this host",
}
INVENTORIES["NuGet"] = {
    "label": "dotnet (global tools)",
    "candidates": [{"detect": "command -v dotnet", "command": "dotnet tool list -g",
                    "label": "dotnet's global tools"}],
    "missing_detail": "dotnet is not on PATH on this host",
}

MAX_COMPONENTS = 600          # bounds the OSV query and the payload


def parse_npm(text: str) -> list[dict]:
    """``npm ls -g --json`` → components. npm's tree puts the name in the key, version inside."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    out = []
    for name, meta in (data.get("dependencies") or {}).items():
        version = (meta or {}).get("version")
        if name and version:
            out.append({"package": name, "version": str(version)})
    return out


def parse_pip(text: str) -> list[dict]:
    """``pip list --format=json`` → components."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        name, version = (item or {}).get("name"), (item or {}).get("version")
        if name and version:
            out.append({"package": str(name), "version": str(version)})
    return out


def parse_composer(text: str) -> list[dict]:
    """``composer global show --format=json`` → components (``installed[]``, name + version)."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    items = data.get("installed") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return []
    out = []
    for item in items:
        name, version = (item or {}).get("name"), (item or {}).get("version")
        if name and version:
            out.append({"package": str(name), "version": str(version)})
    return out


def parse_gem(text: str) -> list[dict]:
    """``gem list --local`` → components. Ruby prints ``name (1.2.3, 1.2.4)`` and may print several
    versions of one gem at once; each pair is a separate row because each is a separate answer from
    OSV."""
    out, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("*") or " (" not in line or not line.endswith(")"):
            continue
        name, _, rest = line.partition(" (")
        for version in rest.rstrip(")").split(","):
            version = version.strip()
            # default gems are printed "name (default: 1.2.3)": the version OSV knows is 1.2.3
            if version.startswith("default:"):
                version = version[len("default:"):].strip()
            if not name or not version or (name, version) in seen:
                continue
            seen.add((name, version))
            out.append({"package": name.strip(), "version": version})
    return out


def parse_cargo(text: str) -> list[dict]:
    """``cargo install --list`` → components. Lines are ``name v1.2.3:`` followed by the binaries."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.endswith(":") or " v" not in line:
            continue
        name, _, version = line.rstrip(":").partition(" v")
        if name and version:
            out.append({"package": name.strip(), "version": version.strip()})
    return out


def parse_dotnet(text: str) -> list[dict]:
    """``dotnet tool list -g`` → components. A fixed-width table: Package Id / Version / Commands,
    with a dashed separator. Header and separator are skipped by shape, not by name."""
    out = []
    for line in text.splitlines():
        if "  " not in line or set(line.strip()) <= set("- "):
            continue
        cells = [cell for cell in line.split("  ") if cell.strip()]
        if len(cells) < 2:
            continue
        name, version = cells[0].strip(), cells[1].strip()
        if name.lower().startswith("package") or not version[:1].isdigit():
            continue
        out.append({"package": name, "version": version})
    return out


PARSERS = {"npm": parse_npm, "PyPI": parse_pip, "Packagist": parse_composer,
           "RubyGems": parse_gem, "crates.io": parse_cargo, "NuGet": parse_dotnet}


def collect(target: str | None = None, timeout: int = 90) -> dict:
    """List the installed packages of every ecosystem whose tool exists on *host*.

    Returns ``{"components": [{package, version, ecosystem}], "outcomes": {...},
    "measured_at": ..., "truncated": bool}``. Never raises.
    """
    measured_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    components: list[dict] = []
    outcomes: dict[str, str] = {}
    details: dict[str, str] = {}
    for ecosystem, spec in INVENTORIES.items():
        outcome, detail, parsed = "missing", spec["missing_detail"], []
        for candidate in spec["candidates"]:
            command = (TOOL_PATH + f"if {candidate['detect']} >/dev/null 2>&1; "
                       f"then {candidate['command']} 2>/dev/null; else echo {MISSING}; fi")
            code, out = shell.run(command, target, timeout=timeout, path_prefix=TOOL_PATH)
            if MISSING in out or code == 127:
                continue
            if code != 0 and not out:
                outcome, detail = "unreadable", f"{candidate['label']} refused (rc={code})"
                continue
            parsed = PARSERS[ecosystem](out)
            if parsed:
                outcome, detail = "ok", candidate["label"]
                break
            outcome = "empty" if out.strip() in ("", "{}", "[]") else "unreadable"
            detail = (f"{candidate['label']} reported no packages" if outcome == "empty"
                      else f"{candidate['label']} answered something unparseable")
        outcomes[ecosystem] = outcome
        details[ecosystem] = detail
        if outcome != "ok":
            continue
        for item in parsed:
            components.append({**item, "ecosystem": ecosystem})
    truncated = len(components) > MAX_COMPONENTS
    if truncated:
        components = components[:MAX_COMPONENTS]
    return {"components": components, "outcomes": outcomes, "details": details,
            "measured_at": measured_at, "truncated": truncated,
            "by_ecosystem": {eco: sum(1 for c in components if c["ecosystem"] == eco)
                             for eco in INVENTORIES}}
