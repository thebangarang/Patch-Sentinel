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
import os
import sys
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

#: One program, reused by the Hermes-environment reader and by the ownership pass. ``pip list`` gives a
#: name and a version, which is not enough to say whose package it is: a process with the agent's own
#: environment on ``sys.path`` lists the agent's dependencies as if they were the machine's.
#: ``importlib.metadata`` answers with the location too, in one call.
_METADATA_PROGRAM = ("import importlib.metadata as m, json;"
                     "print(json.dumps({d.metadata['Name']: {'v': d.version, "
                     "'p': str(d.locate_file(''))} for d in m.distributions() "
                     "if d.metadata['Name']}))")

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
# The agent's own environment, read first and by path. Without it the answer depends on which python
# happens to be on the inherited PATH: measured on one machine, the same scan reported 130 packages in
# one process and 4 in another, and the user's three findings came from this environment. It needs no
# pip — the agent's venv has none — and it is local by definition, so it never runs on a remote host.
INVENTORIES["PyPI"]["candidates"].insert(0, {
    "detect": "true",
    "command": f"'{sys.executable}' -c \"{_METADATA_PROGRAM}\" 2>/dev/null",
    "label": "Hermes's own environment", "parser": "metadata", "local_only": True})

# Gradle keeps the same kind of machine-wide artifact cache as Maven, one directory deeper:
# files-2.1/<group>/<artifact>/<version>/<sha1>/<artifact>-<version>.jar
INVENTORIES["Maven"]["candidates"].append({
    "detect": "test -d \"$HOME/.gradle/caches/modules-2/files-2.1\"",
    "command": "find \"$HOME/.gradle/caches/modules-2/files-2.1\" -name '*.jar' "
               "-not -name '*-sources.jar' -not -name '*-javadoc.jar' 2>/dev/null "
               "| sed 's|.*/files-2.1/||'",
    "label": "~/.gradle/caches", "parser": "gradle"})

# How each store is upgraded, keyed by (ecosystem, candidate label). This exists because the advice
# has to be runnable on the machine that holds the package: "python3 -m pip install -U x" is wrong on
# a host whose system python has no pip while the package lives in a venv, and it is plain wrong for a
# pipx or uv tool, which pip cannot upgrade at all. ``{tool}`` is replaced by the absolute path of the
# binary the scan actually used, so the command cannot land in a different environment than the one
# that was measured. ``None`` means "no command on this host can fix it" — said, not guessed.
UPGRADE: dict[tuple[str, str], tuple[str, str] | None] = {
    ("npm", "npm's global tree"): ("npm", "{tool} install -g {spec}"),
    ("PyPI", "python3 -m pip"): ("python3", "{tool} -m pip install -U {spec}"),
    ("PyPI", "pip3"): ("pip3", "{tool} install -U {spec}"),
    ("PyPI", "pipx's venvs"): ("pipx", "{tool} upgrade {pkg}"),
    ("PyPI", "uv's tool store"): ("uv", "{tool} tool upgrade {pkg}"),
    # the agent's own environment: nothing here is upgraded one package at a time
    ("PyPI", "Hermes's own environment"): None,
    ("Packagist", "composer's global vendor"): ("composer", "{tool} global require {spec}"),
    ("RubyGems", "gem's local list"): ("gem", "{tool} update {pkg}"),
    ("crates.io", "cargo's installed binaries"): ("cargo", "{tool} install {pkg}"),
    ("Pub", "dart pub global"): ("dart", "{tool} pub global activate {pkg} {ver}"),
    ("NuGet", "dotnet's global tools"): ("dotnet", "{tool} tool update -g {pkg}"),
    # a maven/gradle artifact and a nuget package-store entry are build dependencies: the fix is in
    # the project's own pom/build file, not a machine-wide command
    ("Maven", "~/.m2/repository"): None,
    ("Maven", "~/.gradle/caches"): None,
    ("NuGet", "~/.nuget/packages (ids read from each .nuspec)"): None,
    # a Go entry is a module a binary was *built from*: `go install <module>@latest` only works for a
    # main package, and the module name is not one. Rebuilding is the owner's call, so this refuses
    # rather than printing a command that would fail.
    ("Go", "GOPATH/bin binaries"): None,
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


def parse_metadata(text: str) -> list[dict]:
    """The ``importlib.metadata`` dump → components. Needs no pip, which matters because the agent's
    own venv has none: measured, that venv has no ``pip`` binary and no ``pip`` module at all."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    return [{"package": name, "version": str(entry.get("v") or "")}
            for name, entry in data.items()
            if isinstance(entry, dict) and entry.get("v")]


PARSERS = {"npm": parse_npm, "PyPI": parse_pip, "metadata": parse_metadata, "Packagist": parse_composer,
           "RubyGems": parse_gem, "crates.io": parse_cargo, "NuGet": parse_dotnet,
           "Maven": parse_maven_poms, "Go": parse_go_modules,
           "nuget_store": parse_nuget_store, "pipx": parse_pipx, "uv": parse_uv_tools,
           "gradle": parse_gradle, "Pub": parse_pub_global}


def _resolve_upgrade(ecosystem: str, label: str, target: str | None, timeout: int) -> dict:
    """The absolute path of the tool behind a store, plus its upgrade template (or a refusal)."""
    if label == "Hermes's own environment":
        return {"upgrade": None, "owner": "hermes",
                "why": "part of Hermes's own environment — it ships with the agent, so it is upgraded "
                       "by `hermes update`, not package by package. Installing these by hand into the "
                       "agent's venv is how an agent stops starting."}
    spec = UPGRADE.get((ecosystem, label), "unknown")
    if spec is None:
        return {"upgrade": None, "why": "a build dependency: the fix belongs in the project's own "
                                        "manifest, not a machine-wide command"}
    tool, template = spec
    code, path = shell.run(f"command -v {tool} 2>/dev/null", target, timeout=timeout,
                           path_prefix=TOOL_PATH)
    resolved = (path or "").strip().splitlines()[0] if path and path.strip() else ""
    resolved = resolved or tool
    # Is this Hermes's own environment? Then the advice is not "pip install" — these packages ship
    # with the agent, and upgrading one by hand is how an agent stops starting. Measured: a user was
    # told `python3 -m pip install -U 'filelock>=4.2.1'` for packages living in the agent's venv,
    # which has no pip at all.
    if target is None and resolved.startswith(sys.prefix.rstrip("/") + "/"):
        return {"tool": tool, "path": resolved, "upgrade": None, "owner": "hermes",
                "why": "part of Hermes's own environment — it ships with the agent, so it is upgraded "
                       "by `hermes update`, not by pip. Overriding it by hand is how an agent stops "
                       "starting."}
    return {"tool": tool, "path": resolved, "upgrade": template}


def _distributions(python: str, target: str | None, timeout: int) -> dict[str, dict]:
    """name → {version, path} for every distribution that interpreter can see."""
    code, out = shell.run(f"{python} -c \"{_METADATA_PROGRAM}\" 2>/dev/null", target,
                          timeout=timeout, path_prefix=TOOL_PATH)
    if code != 0 or not out.strip():
        return {}
    try:
        data = json.loads(out)
    except ValueError:
        return {}
    return {str(name): value for name, value in data.items() if isinstance(value, dict)}


def _locations(target: str | None, timeout: int) -> dict[str, str]:
    """lowercased name → the directory it was installed into, on the machine this plugin runs on."""
    return {name.lower(): str(entry.get("p") or "")
            for name, entry in _distributions("python3", target, timeout).items()}


def _owner_of(location: str, home: str) -> str:
    """"hermes", "distro" or "machine" — because the three are patched by three different levers.

    A Python package installed by apt/dnf lives under /usr/lib (dist-packages on Debian, site-packages
    on Fedora) and is *maintained by the distribution*: its fixes arrive with the distro's security
    updates, and Debian backports them, so asking PyPI for advisories against the old-looking version
    produces a page of findings the operator cannot act on. Measured on a fresh Debian 12: 118
    advisories across 13 packages, every one of them a distro python3-* package.
    """
    if not location:
        return "machine"
    if location.startswith(home):
        return "hermes"
    if location.startswith("/usr/lib") and ("dist-packages" in location
                                           or "/site-packages" in location):
        return "distro"
    return "machine"


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
    installers_by_ecosystem: dict[str, dict] = {}
    for ecosystem, spec in INVENTORIES.items():
        # Every candidate that answers contributes. They are not fallbacks of each other: pip sees
        # the interpreter's environment, pipx its own venvs, uv its tool store, and a machine can
        # have all three. Duplicates are dropped afterwards.
        answered: list[str] = []
        failure: tuple[str, str] | None = None
        installers = installers_by_ecosystem.setdefault(ecosystem, {})
        for candidate in spec["candidates"]:
            if candidate.get("local_only") and target is not None:
                continue            # it names a path on this machine, not on the host being read
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
                # resolve the binary this store lives behind, once, so the fix command cannot land
                # in a different environment than the one that was measured
                resolved = _resolve_upgrade(ecosystem, candidate["label"], target, timeout)
                installers[candidate["label"]] = resolved
                for item in parsed:
                    key = (ecosystem, str(item["package"]), str(item["version"]))
                    if key in seen:
                        continue
                    seen.add(key)
                    # whose package is it? "hermes" means it belongs to the environment this agent
                    # runs in: not something a user should pip-upgrade by hand, and not their risk.
                    components.append({**item, "ecosystem": ecosystem,
                                       "source": candidate["label"],
                                       "owner": resolved.get("owner") or "machine"})
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
    # Whose package is it? One extra call, and it is the difference between "upgrade this" and "this
    # ships with the agent". Only meaningful for the machine the plugin runs on.
    if target is None and any(c["ecosystem"] == "PyPI" for c in components):
        home = os.path.expanduser("~" + os.sep + ".hermes") + os.sep
        where = _locations(target, timeout)
        for component in components:
            if component["ecosystem"] != "PyPI":
                continue
            location = where.get(str(component["package"]).lower())
            if location:
                component["owner"] = _owner_of(location, home)
    truncated = len(components) > MAX_COMPONENTS
    if truncated:
        components = components[:MAX_COMPONENTS]
    return {"components": components, "outcomes": outcomes, "details": details,
            "installers": installers_by_ecosystem,
            "measured_at": measured_at, "truncated": truncated,
            "by_ecosystem": {eco: sum(1 for c in components if c["ecosystem"] == eco)
                             for eco in INVENTORIES}}
