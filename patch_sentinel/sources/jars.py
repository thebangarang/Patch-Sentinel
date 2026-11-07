"""Jars on disk: the Java deployments that are not in a Maven repository.

`~/.m2/repository` is a build cache; what runs on a server is a jar — a Spring Boot fat jar, a WAR in
a servlet container, an application built by CI and copied to `/opt`. Those files carry their own
identity: a Maven build writes `META-INF/maven/<groupId>/<artifactId>/pom.properties` into the jar, and
that is exactly the `group:artifact` + version OSV's Maven ecosystem keys on.

Reading it needs no Maven, no JDK and no execution: a jar is a zip, and Python reads zips.

Two honest limits, both stated in the result: a jar built without `pom.properties` (Gradle often omits
it) falls back to the file name, which is a hint rather than a fact — those rows are marked
`group: null` and are *not* sent to OSV, because a Maven advisory without a group id would match the
wrong artifact. And a fat jar reports its own coordinates, not the dozens of libraries shaded into it.
"""
from __future__ import annotations

import re
import zipfile

MAX_JARS = 400
MAX_COMPONENTS = 400
ROOTS = ("/opt", "/srv", "/var/lib", "/home", "/usr/share")
SKIP = ("/.cache/", "/node_modules/", "/.git/", "/.hermes/", "/proc/")

FIND = ("find " + " ".join(ROOTS) + " -maxdepth 8 -type f -name '*.jar' "
        + r"\( -not -path '*/.cache/*' -not -path '*/node_modules/*' -not -path '*/.hermes/*' \)"
        + " 2>/dev/null | head -" + str(MAX_JARS))

#: `spring-core-6.1.0.jar` → ("spring-core", "6.1.0"). The version is the last dash-segment that
#: starts with a digit; classifiers (`-sources`, `-tests`) are dropped.
_CLASSIFIER = re.compile(r"-(sources|javadoc|tests|shaded|all)$")
_NAME = re.compile(r"^(?P<name>.+?)-(?P<version>\d.*)$")


def parse_properties(text: str) -> dict:
    fields = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.strip().startswith("#"):
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip()
    return fields


def coordinates(path: str) -> dict | None:
    """Read one jar's own coordinates. Returns ``{group, artifact, version, origin}`` or None."""
    try:
        with zipfile.ZipFile(path) as jar:
            for name in jar.namelist():
                if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
                    fields = parse_properties(jar.read(name).decode("utf-8", "replace"))
                    if fields.get("artifactId") and fields.get("version"):
                        return {"group": fields.get("groupId") or None,
                                "artifact": fields["artifactId"],
                                "version": fields["version"], "origin": "pom.properties",
                                "source": "jar:" + path}
    except (zipfile.BadZipFile, OSError):
        return None
    stem = path.rsplit("/", 1)[-1][:-4] if path.endswith(".jar") else path
    stem = _CLASSIFIER.sub("", stem)
    match = _NAME.match(stem)
    if not match:
        return None
    return {"group": None, "artifact": match.group("name"), "version": match.group("version"),
            "origin": "file name", "source": "jar:" + path}


def collect(target: str | None = None, timeout: int = 120) -> dict:
    """Every readable jar under the code roots → Maven components (+ what could not be read)."""
    from . import shell

    code, out = shell.run(FIND, target, timeout=timeout, path_prefix=shell.SYSTEM_PATH_PREFIX)
    paths = [line.strip() for line in (out or "").splitlines() if line.strip()]
    components, unreadable, unknown_group = [], 0, 0
    seen: set[tuple[str, str, str]] = set()
    if target:                                   # remote hosts are not read file by file here
        return {"components": [], "jars": 0, "installers": {},
                "outcomes": {"jars": "not read on a remote host yet (the walk is local-only)"},
                "truncated": False}
    for path in paths:
        found = coordinates(path)
        if not found:
            unreadable += 1
            continue
        if not found["group"]:
            unknown_group += 1
            continue
        key = (found["group"], found["artifact"], found["version"])
        if key in seen:
            continue
        seen.add(key)
        components.append({"package": f"{found['group']}:{found['artifact']}",
                           "version": found["version"], "ecosystem": "Maven",
                           "source": found["source"], "scope": "jar",
                           "owner": "machine"})
        if len(components) >= MAX_COMPONENTS:
            break
    outcome = (f"ok: {len(paths)} jar(s) read, {len(components)} with Maven coordinates"
               if paths else f"no jar found (rc={code})")
    if unknown_group:
        outcome += f"; {unknown_group} jar(s) named no group and were not matched"
    if unreadable:
        outcome += f"; {unreadable} jar(s) could not be read"
    return {"components": components, "jars": len(paths), "installers": {},
            "outcomes": {"jars": outcome}, "truncated": len(paths) >= MAX_JARS}
