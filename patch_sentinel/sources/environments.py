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
ENV_MARKERS = ("'*/.venv/*'", "'*/venv/*'", "'*/virtualenvs/*'", "'*/pipx/environments/*'",
               "'*/envs/*'", "'*/site-venvs/*'")
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


def collect(target: str | None = None, timeout: int = 120) -> dict:
    """Walk the machine (or a remote host) once and read every environment it can name.

    Returns ``{"components": [...], "outcomes": {...}, "dirs": n}``. A host where the walk fails is an
    *outcome*, not an empty list — the same rule as every other reader here.
    """
    from . import shell

    code, out = shell.run(FIND, target, timeout=timeout, path_prefix=shell.SYSTEM_PATH_PREFIX)
    paths = [line for line in (out or "").splitlines() if line.strip()]
    components = parse(paths)
    directories = len({c["source"] for c in components})
    if not paths:
        outcome = f"no environment found (rc={code})" if code == 0 else f"unreadable (rc={code})"
    else:
        outcome = f"ok: {directories} environment(s), {len(components)} package(s)"
    return {"components": components, "dirs": directories,
            "outcomes": {"venvs": outcome}, "truncated": len(paths) >= MAX_DIST_INFO}
