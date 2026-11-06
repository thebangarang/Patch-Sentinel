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
        "label": "pip, pipx and uv (the python stores on PATH)",
        # python3 carrying its own pip, then a standalone pip3: measured here, the first python3
        # on PATH can be a uv-managed interpreter with no pip module, while pip3 works.
        "candidates": [
            {"detect": "python3 -m pip --version", "command": "python3 -m pip list --format=json",
             "label": "python3 -m pip"},
            {"detect": "pip3 --version", "command": "pip3 list --format=json",
             "label": "pip3"},
        ],
        # pipx and uv keep their own environments: a tool installed by either is invisible to
        # `pip list`, so all three answer and the results are merged (see below).
        "missing_detail": "no python interpreter with pip, pipx or uv is on PATH on this host",
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
# Java has no global install list either — but Maven keeps every artifact it has ever resolved in
# ~/.m2/repository, laid out as group/path/artifact/version/. That store IS machine-wide, and it is
# what a build will reuse, so it is honest to read it: the coordinates OSV wants are group:artifact.
INVENTORIES["Maven"] = {
    "label": "maven (local repository)",
    "candidates": [{"detect": "test -d \"$HOME/.m2/repository\"",
                    "command": "find \"$HOME/.m2/repository\" -name '*.pom' 2>/dev/null "
                               "| sed 's|.*/repository/||'",
                    "label": "~/.m2/repository"}],
    "missing_detail": "no ~/.m2/repository on this host",
}
# Go installs binaries, not a package store: `go version -m` on each binary in GOPATH/bin reports the
# modules it was built from, which is the only machine-wide module list that exists.
INVENTORIES["Go"] = {
    "label": "go (installed binaries)",
    "candidates": [{"detect": "command -v go",
                    "command": "for b in \"$(go env GOPATH 2>/dev/null)/bin\"/*; do "
                               "[ -x \"$b\" ] && go version -m \"$b\" 2>/dev/null; done "
                               r"| sed -n 's/^[[:space:]]*dep[[:space:]]\{1,\}\([^[:space:]]\{1,\}\)"
                               r"[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1 \2/p'",
                    "label": "GOPATH/bin binaries"}],
    "missing_detail": "go is not on PATH on this host",
}
# NuGet has two machine-wide stores and they answer different questions: `dotnet tool list -g` lists
# the global *tools*, while ~/.nuget/packages holds every package a restore has ever extracted — the
# real dependency surface. The store's directory names are lowercased ids, which OSV would miss, so
# the id is read back from each package's own .nuspec: measured, that is what keeps "Newtonsoft.Json"
# from being queried as "newtonsoft.json" and coming back falsely clean.
INVENTORIES["NuGet"] = {
    "label": "nuget (global tools and the package store)",
    "candidates": [
        {"detect": "test -d \"$HOME/.nuget/packages\"",
         "command": "for f in \"$HOME/.nuget/packages\"/*/*/*.nuspec; do "
                    "id=$(sed -n 's:.*<id>\\(.*\\)</id>.*:\\1:p' \"$f\" | head -1); "
                    "v=$(basename \"$(dirname \"$f\")\"); "
                    "[ -n \"$id\" ] && echo \"$id|$v\"; done",
         "label": "~/.nuget/packages (ids read from each .nuspec)", "parser": "nuget_store"},
        {"detect": "command -v dotnet", "command": "dotnet tool list -g",
         "label": "dotnet's global tools"},
    ],
    "missing_detail": "neither ~/.nuget/packages nor the dotnet CLI is on this host",
}

# Dart/Flutter keeps its global packages in PUB_CACHE, listed by the tool itself.
INVENTORIES["Pub"] = {
    "label": "dart (global packages)",
    "candidates": [{"detect": "command -v dart", "command": "dart pub global list",
                    "label": "dart pub global"}],
    "missing_detail": "dart is not on PATH on this host",
}

INVENTORIES["PyPI"]["candidates"] += [
    {"detect": "command -v pipx", "command": "pipx list --short",
     "label": "pipx's venvs", "parser": "pipx"},
    {"detect": "command -v uv", "command": "uv tool list",
     "label": "uv's tool store", "parser": "uv"},
]

# Gradle keeps the same kind of machine-wide artifact cache as Maven, one directory deeper:
# files-2.1/<group>/<artifact>/<version>/<sha1>/<artifact>-<version>.jar
INVENTORIES["Maven"]["candidates"].append({
    "detect": "test -d \"$HOME/.gradle/caches/modules-2/files-2.1\"",
    "command": "find \"$HOME/.gradle/caches/modules-2/files-2.1\" -name '*.jar' "
               "-not -name '*-sources.jar' -not -name '*-javadoc.jar' 2>/dev/null "
               "| sed 's|.*/files-2.1/||'",
    "label": "~/.gradle/caches", "parser": "gradle"})

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
    """``cargo install --list`` → components.

    Two shapes exist and both are real: a crates.io install prints ``ripgrep v13.0.0:``, while a
    ``cargo install --path .`` prints ``mybin v0.1.0 (/tmp/t):`` — same line with the source in
    parentheses. Taking the first whitespace-delimited token of the version keeps both, and keeps the
    path out of a field OSV will be queried with.
    """
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.endswith(":") or " v" not in line:
            continue
        name, _, rest = line.rstrip(":").partition(" v")
        version = rest.split()[0] if rest.split() else ""
        if name and version:
            out.append({"package": name.strip(), "version": version})
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


def parse_maven_poms(text: str) -> list[dict]:
    """``find ~/.m2/repository -name '*.pom'`` → Maven coordinates as OSV wants them (group:artifact).

    Path shape: ``org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom`` — so the last
    two segments before the file are version and artifact, everything before them is the group.
    """
    out, seen = [], set()
    for line in text.splitlines():
        parts = [part for part in line.strip().split("/") if part and not part.endswith(".pom")]
        if len(parts) < 3:
            continue
        version, artifact, group = parts[-1], parts[-2], ".".join(parts[:-2])
        if not group or not artifact or not version:
            continue
        coordinate = f"{group}:{artifact}"
        if (coordinate, version) in seen:
            continue
        seen.add((coordinate, version))
        out.append({"package": coordinate, "version": version})
    return out


def parse_go_modules(text: str) -> list[dict]:
    """``go version -m <binary>`` dep lines → module + version (``golang.org/x/tools v0.1.0``)."""
    out, seen = [], set()
    for line in text.splitlines():
        # accepts both the raw `go version -m` line ("\tdep\tmodule\tversion\th1:…") and the
        # two-field form the probe's sed produces, so a quoting change cannot silently empty this
        bits = line.replace("\t", " ").split()
        if bits[:1] == ["dep"] and len(bits) >= 3:
            module, version = bits[1], bits[2]
        elif len(bits) == 2:
            module, version = bits
        else:
            continue
        if "/" not in module or not version.startswith("v"):
            continue
        if (module, version) in seen:
            continue
        seen.add((module, version))
        out.append({"package": module, "version": version})
    return out


def parse_nuget_store(text: str) -> list[dict]:
    """``id|version`` pairs from a walk of ``~/.nuget/packages`` → components (original casing)."""
    out, seen = [], set()
    for line in text.splitlines():
        name, _, version = line.strip().partition("|")
        if not name or not version or (name, version) in seen:
            continue
        seen.add((name, version))
        out.append({"package": name, "version": version})
    return out


def parse_pipx(text: str) -> list[dict]:
    """``pipx list --short`` → components. One line per venv: ``pycowsay 0.0.0.2``."""
    out = []
    for line in text.splitlines():
        bits = line.split()
        if len(bits) == 2 and bits[1][:1].isdigit():
            out.append({"package": bits[0], "version": bits[1]})
    return out


def parse_uv_tools(text: str) -> list[dict]:
    """``uv tool list`` → components. ``ruff v0.17.4`` followed by an indented ``- ruff`` line."""
    out = []
    for line in text.splitlines():
        if not line or line[0].isspace() or line.startswith("-"):
            continue
        bits = line.split()
        if len(bits) >= 2 and bits[1].startswith("v"):
            out.append({"package": bits[0], "version": bits[1].lstrip("v")})
    return out


def parse_pub_global(text: str) -> list[dict]:
    """``dart pub global list`` → components. One line per package: ``args 2.5.0``."""
    out = []
    for line in text.splitlines():
        bits = line.split()
        if len(bits) >= 2 and bits[1][:1].isdigit():
            out.append({"package": bits[0], "version": bits[1]})
    return out


def parse_gradle(text: str) -> list[dict]:
    """``files-2.1/<group>/<artifact>/<version>/<sha1>/<artifact>-<version>.jar`` → coordinates."""
    out, seen = [], set()
    for line in text.splitlines():
        parts = [part for part in line.strip().split("/") if part]
        if len(parts) < 5:
            continue
        group, artifact, version = ".".join(parts[:-4]), parts[-4], parts[-3]
        coordinate = f"{group}:{artifact}"
        if (coordinate, version) in seen:
            continue
        seen.add((coordinate, version))
        out.append({"package": coordinate, "version": version})
    return out


PARSERS = {"npm": parse_npm, "PyPI": parse_pip, "Packagist": parse_composer,
           "RubyGems": parse_gem, "crates.io": parse_cargo, "NuGet": parse_dotnet,
           "Maven": parse_maven_poms, "Go": parse_go_modules,
           "nuget_store": parse_nuget_store, "pipx": parse_pipx, "uv": parse_uv_tools,
           "gradle": parse_gradle, "Pub": parse_pub_global}


def collect(target: str | None = None, timeout: int = 90) -> dict:
    """List the installed packages of every ecosystem whose tool exists on *host*.

    Returns ``{"components": [{package, version, ecosystem}], "outcomes": {...},
    "measured_at": ..., "truncated": bool}``. Never raises.
    """
    measured_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    components: list[dict] = []
    outcomes: dict[str, str] = {}
    details: dict[str, str] = {}
    seen: set[tuple[str, str, str]] = set()
    for ecosystem, spec in INVENTORIES.items():
        # Every candidate that answers contributes. They are not fallbacks of each other: pip sees
        # the interpreter's environment, pipx its own venvs, uv its tool store, and a machine can
        # have all three. Duplicates are dropped afterwards.
        answered: list[str] = []
        failure: tuple[str, str] | None = None
        for candidate in spec["candidates"]:
            command = (TOOL_PATH + f"if {candidate['detect']} >/dev/null 2>&1; "
                       f"then {candidate['command']} 2>/dev/null; else echo {MISSING}; fi")
            code, out = shell.run(command, target, timeout=timeout, path_prefix=TOOL_PATH)
            if MISSING in out or code == 127:
                continue
            if code != 0 and not out:
                failure = failure or ("unreadable", f"{candidate['label']} refused (rc={code})")
                continue
            # a candidate may answer in a different shape than its ecosystem's default parser
            parser = PARSERS[candidate.get("parser", ecosystem)]
            parsed = parser(out)
            if parsed:
                answered.append(candidate["label"])
                for item in parsed:
                    key = (ecosystem, str(item["package"]), str(item["version"]))
                    if key in seen:
                        continue
                    seen.add(key)
                    components.append({**item, "ecosystem": ecosystem})
                continue
            empty = out.strip() in ("", "{}", "[]")
            failure = failure or (("empty" if empty else "unreadable"),
                                  f"{candidate['label']} reported no packages" if empty
                                  else f"{candidate['label']} answered something unparseable")
        if answered:
            outcomes[ecosystem], details[ecosystem] = "ok", "; ".join(answered)
        elif failure:
            outcomes[ecosystem], details[ecosystem] = failure
        else:
            outcomes[ecosystem], details[ecosystem] = "missing", spec["missing_detail"]
    truncated = len(components) > MAX_COMPONENTS
    if truncated:
        components = components[:MAX_COMPONENTS]
    return {"components": components, "outcomes": outcomes, "details": details,
            "measured_at": measured_at, "truncated": truncated,
            "by_ecosystem": {eco: sum(1 for c in components if c["ecosystem"] == eco)
                             for eco in INVENTORIES}}
