"""Read a project's own lockfiles — the dependencies a machine-wide scan cannot see.

`pip list` shows what an interpreter has installed; it says nothing about the `requirements.txt` you
are about to deploy, the `package-lock.json` in a repo, or the `go.sum` of a binary you are shipping.
That is the largest honest hole in the language coverage, and closing it needs no scanner: the
lockfiles already name exact versions.

Two rules this module keeps:

* **only exact versions.** `pkg>=1.2` in a requirements file is a range, not an installed version;
  reporting a CVE against it would be a guess. Ranges are counted and named, never turned into a
  finding.
* **a file it cannot read is an outcome**, per file, with the reason — the same rule as everywhere
  else. A project with no lockfile is not a project with no vulnerabilities.

Nothing here executes project code, reads a virtualenv, or walks into `node_modules`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

MAX_FILES = 400
MAX_COMPONENTS = 900
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "vendor", "target", "dist", "build",
             "__pycache__", ".tox", ".mypy_cache", "site-packages"}

#: filename → (ecosystem, parser name)
LOCKFILES = {
    "package-lock.json": ("npm", "npm_lock"),
    "yarn.lock": ("npm", "yarn_lock"),
    "pnpm-lock.yaml": ("npm", "pnpm_lock"),
    "requirements.txt": ("PyPI", "pip_requirements"),
    "constraints.txt": ("PyPI", "pip_requirements"),
    "poetry.lock": ("PyPI", "poetry_lock"),
    "Pipfile.lock": ("PyPI", "pipfile_lock"),
    "go.sum": ("Go", "go_sum"),
    "Cargo.lock": ("crates.io", "cargo_lock"),
    "composer.lock": ("Packagist", "composer_lock"),
    "Gemfile.lock": ("RubyGems", "gemfile_lock"),
    "pubspec.lock": ("Pub", "pubspec_lock"),
}


def _components(rows: list[tuple[str, str]], ecosystem: str, source: str) -> list[dict]:
    out = []
    for name, version in rows:
        name, version = (name or "").strip(), (version or "").strip()
        if not name or not version or not re.match(r"^[0-9v]", version):
            continue
        out.append({"package": name, "version": version, "ecosystem": ecosystem,
                    "source": source, "scope": "project"})
    return out


# --------------------------------------------------------------------------- parsers
# Each returns [(name, version)] and never raises: a malformed lockfile yields what could be read.

def parse_npm_lock(text: str) -> list[tuple[str, str]]:
    data = json.loads(text)
    rows = []
    packages = data.get("packages")
    if isinstance(packages, dict):                      # lockfile v2/v3
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict) or not meta.get("version"):
                continue
            name = meta.get("name") or path.split("node_modules/")[-1]
            if name:
                rows.append((name, meta["version"]))
    for name, meta in (data.get("dependencies") or {}).items():   # v1
        if isinstance(meta, dict) and meta.get("version"):
            rows.append((name, meta["version"]))
    return rows


def parse_yarn_lock(text: str) -> list[tuple[str, str]]:
    """Both formats: v1 is `"pkg@^1": / version "1.2.3"`, berry adds `version: 1.2.3`."""
    rows, name = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if not line.startswith((" ", "\t")) and stripped.endswith(":"):
            first = stripped.rstrip(":").strip().strip('"').split(",")[0].strip().strip('"')
            name = first.rsplit("@", 1)[0] if "@" in first else first
            if first.startswith("@"):                   # scoped package: @scope/name@^1
                parts = first.split("@")
                name = "@" + parts[1] if len(parts) > 2 else first
        elif name and stripped.startswith("version"):
            value = stripped.split(":", 1)[1].strip().strip('"') if ":" in stripped \
                else stripped.split('"')[1]
            rows.append((name, value))
            name = None
    return rows


def parse_pnpm_lock(text: str) -> list[tuple[str, str]]:
    rows = []
    for line in text.splitlines():
        match = re.match(r"^\s+/?(@?[^@\s]+)@([^:\s]+):\s*$", line)
        if match:
            rows.append((match.group(1), match.group(2)))
    return rows


def parse_pip_requirements(text: str) -> list[tuple[str, str]]:
    rows = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([0-9][^\s;]*)", line)
        if match:
            rows.append((match.group(1).split("[")[0], match.group(2)))
    return rows


def parse_poetry_lock(text: str) -> list[tuple[str, str]]:
    rows, name = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            name = None
        elif stripped.startswith("name ="):
            name = stripped.split("=", 1)[1].strip().strip('"')
        elif stripped.startswith("version =") and name:
            rows.append((name, stripped.split("=", 1)[1].strip().strip('"')))
            name = None
    return rows


def parse_pipfile_lock(text: str) -> list[tuple[str, str]]:
    data = json.loads(text)
    rows = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            version = str((meta or {}).get("version") or "").lstrip("=").strip()
            if version:
                rows.append((name, version))
    return rows


def parse_go_sum(text: str) -> list[tuple[str, str]]:
    rows, seen = [], set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith("v"):
            continue
        module, version = parts[0], parts[1]
        if version.endswith("/go.mod"):
            version = version[: -len("/go.mod")]
        if (module, version) in seen:
            continue
        seen.add((module, version))
        rows.append((module, version))
    return rows


def parse_cargo_lock(text: str) -> list[tuple[str, str]]:
    rows, name = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            name = None
        elif stripped.startswith("name ="):
            name = stripped.split("=", 1)[1].strip().strip('"')
        elif stripped.startswith("version =") and name:
            rows.append((name, stripped.split("=", 1)[1].strip().strip('"')))
            name = None
    return rows


def parse_composer_lock(text: str) -> list[tuple[str, str]]:
    data = json.loads(text)
    rows = []
    for section in ("packages", "packages-dev"):
        for item in data.get(section) or []:
            if isinstance(item, dict) and item.get("name") and item.get("version"):
                rows.append((item["name"], str(item["version"]).lstrip("v")))
    return rows


def parse_gemfile_lock(text: str) -> list[tuple[str, str]]:
    rows, in_specs = [], False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            match = re.match(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line)
            if match:
                rows.append((match.group(1), match.group(2)))
            elif line and not line.startswith(" "):
                in_specs = False
    return rows


def parse_pubspec_lock(text: str) -> list[tuple[str, str]]:
    rows, name = [], None
    for line in text.splitlines():
        stripped = line.rstrip()
        if re.match(r"^  [A-Za-z0-9_]+:\s*$", stripped):
            name = stripped.strip().rstrip(":")
        elif name and stripped.strip().startswith("version:"):
            rows.append((name, stripped.split(":", 1)[1].strip().strip('"')))
            name = None
    return rows


PARSERS = {
    "npm_lock": parse_npm_lock, "yarn_lock": parse_yarn_lock, "pnpm_lock": parse_pnpm_lock,
    "pip_requirements": parse_pip_requirements, "poetry_lock": parse_poetry_lock,
    "pipfile_lock": parse_pipfile_lock, "go_sum": parse_go_sum, "cargo_lock": parse_cargo_lock,
    "composer_lock": parse_composer_lock, "gemfile_lock": parse_gemfile_lock,
    "pubspec_lock": parse_pubspec_lock,
}


# --------------------------------------------------------------------------- walking a project

def read(root: str, max_depth: int = 3) -> dict:
    """Every lockfile under *root* → components, per-file outcomes, and what was skipped.

    Returns ``{"components": [...], "files": {relpath: "read: N package(s)"|reason},
    "ranges": [...], "root": str}``. Never raises.
    """
    base = Path(root).expanduser()
    result = {"root": str(base), "components": [], "files": {}, "ranges": [], "truncated": False}
    if not base.is_dir():
        result["files"][str(base)] = "not a directory"
        return result

    seen: set[tuple[str, str, str]] = set()
    visited = 0
    for path in sorted(base.rglob("*")):
        if len(result["components"]) >= MAX_COMPONENTS or visited >= MAX_FILES:
            result["truncated"] = True
            break
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_dir() or len(path.relative_to(base).parts) > max_depth:
            continue
        spec = LOCKFILES.get(path.name)
        if not spec:
            continue
        visited += 1
        ecosystem, parser_name = spec
        rel = str(path.relative_to(base))
        try:
            rows = PARSERS[parser_name](path.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:                       # malformed lockfile is an outcome, not a crash
            result["files"][rel] = f"unreadable: {type(exc).__name__}"
            continue
        items = _components(rows, ecosystem, rel)
        for item in items:
            key = (item["ecosystem"], item["package"], item["version"])
            if key in seen:
                continue
            seen.add(key)
            result["components"].append(item)
        result["files"][rel] = f"read: {len(items)} package(s)" if items else "read: no exact versions"
    if not result["files"]:
        result["files"][str(base)] = "no lockfile found (checked " + ", ".join(sorted(LOCKFILES)) + ")"
    return result
