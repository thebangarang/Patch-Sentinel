"""Project environments: every `site-packages` on the machine, not just the agent's interpreter.

`cve_libraries` reads the stores it can list (npm's global tree, the first pip on PATH, composer's
global vendor…). That leaves the largest real surface invisible: the virtualenvs a developer actually
works in — `~/projects/*/.venv`, poetry's cache, pipx's environments. Ten projects, ten dependency
sets, none of them in a global tree.

This module finds them without executing anything. Every installed distribution leaves a
`*.dist-info` directory whose *name* is `package-version`; that is enough for an exact-version
advisory query, and it costs one `find` instead of one interpreter launch per environment. Nothing is
imported, no `pip` runs, no project code executes.

Two rules:

* **only exact versions.** An egg-info directory without a version is an editable install; it is
  counted and skipped, never guessed at.
* **the store is named.** Every component carries `env:<path>` as its source, so a finding says *which*
  project is exposed.
"""
from __future__ import annotations

import re

#: Bounded on purpose: this is a filesystem walk across the places code lives, not a crawl of `/`.
ROOTS = ("/home", "/srv", "/opt", "/var/www")
MAX_DIST_INFO = 600
MAX_COMPONENTS = 500
#: The agent's own environments are read by the machine-wide reader already, and a backup copy of a
#: home directory is a copy of environments that are not in use — neither belongs in a project count.
SKIP = ("/node_modules/", "/.cache/", "/site-packages/pip/", "/.git/", "/.hermes/",
        "/hermes-repair-backup")

#: Only *environments* count. A bare `*.dist-info` walk also finds uv's unpacked-wheel cache
#: (`~/.cache/uv/archive-v0/…`), which is 485 "environments" of nothing — the path has to name a venv.
#: `~/.local/lib/python3.11/site-packages` is the shape `pip install --user` makes, and on Debian and
#: Ubuntu (PEP 668) it is the *only* way a user may install a Python package at all. Missing it means
#: every user-installed package is invisible on the distros where the plugin started.
ENV_MARKERS = ("'*/.venv/*'", "'*/venv/*'", "'*/virtualenvs/*'", "'*/pipx/environments/*'",
               "'*/envs/*'", "'*/site-venvs/*'", "'*/.local/lib/python*/site-packages/*'")
#: The exclusions are in the walk, not only in the parser: `head` runs before Python sees a line, so a
#: filtered-out tree would otherwise eat the whole budget (a home-directory backup held 350 of 600).
_CLAUSE = r"\( " + " -o ".join("-path " + marker for marker in ENV_MARKERS) + r" \)"
_NOT = (r" \( -not -path '*/.cache/*' -not -path '*/.hermes/*'"
        r" -not -path '*/hermes-repair-backup*' -not -path '*/node_modules/*' \)")
FIND = ("find " + " ".join(ROOTS) + " -maxdepth 9 -type d -name '*.dist-info' "
        + _CLAUSE + _NOT + " 2>/dev/null | head -" + str(MAX_DIST_INFO))

#: `requests-2.31.0.dist-info` → ("requests", "2.31.0"). The version is the last dash-segment that
#: starts with a digit; a name may contain dashes (`python-dateutil-2.8.2`).
_DIST = re.compile(r"^(?P<name>.+?)-(?P<version>\d[^-]*)$")


def parse(paths: list[str]) -> list[dict]:
    """`*.dist-info` paths → components, one per distribution, with the environment as its source."""
    components: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for path in paths:
        line = (path or "").strip()
        if not line or any(skip in line for skip in SKIP):
            continue
        stem = line.rstrip("/").split("/")[-1]
        if not stem.endswith(".dist-info"):
            continue
        stem = stem[: -len(".dist-info")]
        match = _DIST.match(stem)
        if not match:
            continue
        name = match.group("name").replace("_", "-").lower()
        version = match.group("version")
        # /home/x/projects/api/.venv/lib/python3.12/site-packages → that venv
        # ~/.local/lib/python3.11/site-packages → the user site, which has no `/lib/` split point
        if "/.local/lib/" in line:
            store = line.rsplit("/", 1)[0]
        else:
            store = line.split("/lib/")[0] if "/lib/" in line else line.rsplit("/site-packages", 1)[0]
        key = (name, version, store)
        if key in seen:
            continue
        seen.add(key)
        components.append({
            "package": name, "version": version, "ecosystem": "PyPI",
            "source": "env:" + (store or "?"), "scope": "environment",
            "owner": "hermes" if "/.hermes/" in line else "machine",
        })
        if len(components) >= MAX_COMPONENTS:
            break
    return components


#: Which installer owns this environment? A venv built by `uv venv` has no pip at all, and telling the
#: operator to run a pip that is not there is the same class of bug as a fix command naming no store.
#: Three things at once: is there a pip in the environment, where is uv, and what would run it.
#: `uv` is usually *not* on a login PATH (`~/.hermes/bin`, `~/.local/bin`, `~/.cargo/bin` are common),
#: so a bare `uv` in a pasted command fails on a machine where uv is installed — which is exactly what
#: the operator hit. The absolute path is resolved here, once, at scan time.
PIP_PROBE = (
    "U=$(command -v uv 2>/dev/null); [ -n \"$U\" ] && echo \"uvbin $U\"; "
    "for p in \"$HOME/.local/bin/uv\" \"$HOME/.cargo/bin/uv\" \"$HOME/.hermes/bin/uv\" "
    "/usr/local/bin/uv /snap/bin/uv /opt/homebrew/bin/uv; do "
    "[ -x \"$p\" ] && echo \"uvbin $p\"; done; "
    "for d in {stores}; do if [ -x \"$d/bin/pip\" ]; then echo \"pip $d/bin/pip\"; "
    "elif [ -x \"$d/bin/python\" ]; then echo \"python $d/bin/python\"; fi; done")


def _installers(stores: list[str], target: str | None, timeout: int) -> dict[str, dict]:
    """``{store: manager}`` — the command that actually upgrades a package in that environment."""
    from . import shell

    if not stores:
        return {}
    quoted = " ".join("'" + store.replace("'", "'\\''") + "'" for store in stores)
    code, out = shell.run(PIP_PROBE.format(stores=quoted), target, timeout=timeout,
                          path_prefix=shell.SYSTEM_PATH_PREFIX)
    uv_path = ""
    stores_with_pip: set[str] = set()
    python_only: set[str] = set()
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[1].startswith("/"):
            continue
        if parts[0] == "uvbin":
            uv_path = uv_path or parts[1]      # the first hit is the canonical one
        elif parts[0] == "pip":
            stores_with_pip.add(parts[1].rsplit("/bin/", 1)[0])
        elif parts[0] == "python":
            python_only.add(parts[1].rsplit("/bin/", 1)[0])

    found: dict[str, dict] = {}
    for store in stores_with_pip:
        found[store] = {"tool": "pip", "path": store + "/bin/pip",
                        "upgrade": "{tool} install -U {spec}"}
    for store in python_only - stores_with_pip:
        if uv_path:
            # uv-made venvs ship an interpreter and no pip: uv installs into that interpreter
            found[store] = {"tool": "uv", "path": uv_path,
                            "upgrade": "{tool} pip install --python {python} {spec}"}
        else:
            found[store] = {"tool": None, "path": None, "upgrade": None,
                            "why": "no pip in this environment and uv is not installed on the host — "
                                   "the command would have to be run after installing one of them"}
    return found


def collect(target: str | None = None, timeout: int = 120) -> dict:
    """Walk the machine (or a remote host) once and read every environment it can name.

    Returns ``{"components": [...], "outcomes": {...}, "dirs": n}``. A host where the walk fails is an
    *outcome*, not an empty list — the same rule as every other reader here.
    """
    from . import shell

    code, out = shell.run(FIND, target, timeout=timeout, path_prefix=shell.SYSTEM_PATH_PREFIX)
    paths = [line for line in (out or "").splitlines() if line.strip()]
    components = parse(paths)
    stores = sorted({c["source"][4:] for c in components})
    installers = _installers(stores, target, timeout)
    for component in components:
        store = component["source"][4:]
        manager = installers.get(store)
        if manager:
            component["manager"] = manager
            component["installer"] = manager["tool"]
    directories = len({c["source"] for c in components})
    if not paths:
        outcome = f"no environment found (rc={code})" if code == 0 else f"unreadable (rc={code})"
    else:
        outcome = f"ok: {directories} environment(s), {len(components)} package(s)"
    return {"components": components, "dirs": directories,
            "outcomes": {"venvs": outcome}, "installers": installers,
            "truncated": len(paths) >= MAX_DIST_INFO}
