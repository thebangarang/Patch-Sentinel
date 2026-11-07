"""Run the plugin on a machine that has never seen it, and report what it actually did.

This is the portability harness: it is copied to a foreign host, imports the plugin with the system
python, and exercises every tool a user can reach — no venv, no Hermes, no configuration beyond a
hosts line. It answers one question per surface: measured, or "could not look" with a reason.

Usage on the far side:   python3 portability_probe.py [--json out.json]
It prints one JSON object; nothing else goes to stdout.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
import traceback

ROOT = os.path.expanduser("~/ps")
sys.path.insert(0, ROOT)

from patch_sentinel import tools  # noqa: E402

DATA = os.path.join(tempfile.gettempdir(), "ps-portability")


def lockfiles(base: str) -> dict[str, str]:
    """A tiny project of each kind — the parsers are what is under test, not a toolchain install."""
    files = {
        "package-lock.json": json.dumps({
            "name": "demo", "lockfileVersion": 3,
            "packages": {"": {"name": "demo"},
                         "node_modules/lodash": {"version": "4.17.4"},
                         "node_modules/minimist": {"version": "1.2.0"}}}),
        "requirements.txt": "requests==2.19.1\njinja2==2.10\n",
        "go.sum": "github.com/gin-gonic/gin v1.7.0 h1:abc=\n",
        "Cargo.lock": '[[package]]\nname = "time"\nversion = "0.1.42"\n',
        "composer.lock": json.dumps({"packages": [
            {"name": "symfony/http-kernel", "version": "v4.4.0"}]}),
        "Gemfile.lock": "GEM\n  specs:\n    rack (2.0.0)\n",
        "pubspec.lock": "packages:\n  http:\n    version: \"0.11.0\"\n",
        "yarn.lock": 'lodash@^4.17.4:\n  version "4.17.4"\n',
    }
    written = {}
    for name, body in files.items():
        path = os.path.join(base, name)
        with open(path, "w") as handle:
            handle.write(body)
        written[name] = path
    return written


def venv(base: str) -> str | None:
    """A virtualenv with one known-vulnerable package, when the machine can make one."""
    target = os.path.join(base, "proj", ".venv")
    try:
        subprocess.run([sys.executable, "-m", "venv", target], check=True,
                       capture_output=True, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    pip = os.path.join(target, "bin", "pip")
    if not os.path.exists(pip):
        return None
    try:
        subprocess.run([pip, "install", "-q", "urllib3==1.24.1"], check=True,
                       capture_output=True, timeout=180)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return target


def summarise_scan(payload: dict) -> dict:
    host = next(iter((payload.get("hosts") or {}).values()), {})
    return {"exit": payload.get("exit_code"), "adapter": host.get("adapter"),
            "family": host.get("family"), "os": (host.get("os") or {}).get("id"),
            "release": (host.get("os") or {}).get("codename"),
            "pending": host.get("pending_count"), "kernel": (host.get("kernel") or {}).get("verdict"),
            "outcomes": host.get("outcomes"), "vendor_state": host.get("vendor_state"),
            "lag": len(host.get("vendor_lag") or []), "support": (host.get("support") or {}).get("state"),
            "blind": [b.get("class") for b in payload.get("blind") or []]}


def summarise_libraries(payload: dict) -> dict:
    return {"exit": payload.get("exit_code"), "packages": len(payload.get("packages") or []),
            "findings": payload.get("vulnerable_count"),
            "mine": sum(1 for r in payload.get("vulnerable") or [] if r.get("owner") == "machine"),
            "distro": (payload.get("distro_managed") or {}).get("advisories"),
            "by_ecosystem": {k: v for k, v in (payload.get("by_ecosystem") or {}).items() if v},
            "outcomes": payload.get("outcomes"),
            "scope": payload.get("scope") or "machine"}


def summarise_integrity(payload: dict) -> dict:
    state = payload.get("integrity") or {}
    return {"exit": payload.get("exit_code"), "state": state.get("state"),
            "tamper": (state.get("tamper") or {}).get("state"),
            "changed": (state.get("tamper") or {}).get("changed_count"),
            "conffiles": (state.get("tamper") or {}).get("conffile_count"),
            "unreadable": (state.get("tamper") or {}).get("unreadable_count"),
            "volatile": (state.get("tamper") or {}).get("missing_volatile_count"),
            "preload": (state.get("preload") or {}).get("state"),
            "sockets": (state.get("listeners") or {}).get("state"),
            "socket_count": (state.get("listeners") or {}).get("count"),
            "drift": (state.get("listeners") or {}).get("drift_count")}


def main() -> int:
    out_path = None
    if "--json" in sys.argv:
        out_path = sys.argv[sys.argv.index("--json") + 1]
    os.makedirs(DATA, exist_ok=True)
    tools.configure({"hosts": "this=local", "release": "", "usn_limit": 3,
                     "data_dir": DATA, "timeout": 90})
    report: dict = {"machine": {"python": platform.python_version(),
                                "os": platform.platform()},
                    "results": {}, "errors": {}, "notes": []}

    def run(name, fn, describe):
        try:
            payload = json.loads(fn({}))
            report["results"][name] = describe(payload)
        except Exception as err:                      # noqa: BLE001 - a crash is a result here
            report["errors"][name] = f"{type(err).__name__}: {err}"
            report["notes"].append(traceback.format_exc().splitlines()[-1])

    run("scan", tools.cve_scan, summarise_scan)
    run("libraries", tools.cve_libraries, summarise_libraries)

    base = os.path.join(os.path.expanduser("~"), "ps-portability-project")
    subprocess.run(["rm", "-rf", base], check=False)
    os.makedirs(base, exist_ok=True)
    lockfiles(base)
    try:
        payload = json.loads(tools.cve_libraries({"project": base}))
        report["results"]["project_lockfiles"] = summarise_libraries(payload)
        report["results"]["project_lockfiles"]["files"] = (payload.get("project") or {}).get("files")
    except Exception as err:                          # noqa: BLE001
        report["errors"]["project_lockfiles"] = f"{type(err).__name__}: {err}"

    virtualenv = venv(base)
    if not virtualenv:
        # the reader only parses `<name>-<version>.dist-info` directory names — it never runs the
        # interpreter, so a fabricated tree tests the same code path on a machine without venv support
        virtualenv = os.path.join(base, "proj", ".venv")
        site = os.path.join(virtualenv, "lib", f"python{platform.python_version()[:4]}", "site-packages")
        os.makedirs(os.path.join(site, "urllib3-1.24.1.dist-info"), exist_ok=True)
        os.makedirs(os.path.join(site, "jinja2-2.10.dist-info"), exist_ok=True)
        report["notes"].append("venv fabricated (no python3-venv on this host): dist-info directories only")
    if virtualenv:
        try:
            payload = json.loads(tools.cve_libraries({}))
            found = [r for r in payload.get("packages") or [] if "proj/.venv" in str(r.get("source"))]
            report["results"]["virtualenv"] = {
                "path": virtualenv, "packages_from_venv": len(found),
                "has_urllib3": any(r.get("package") == "urllib3" for r in found)}
        except Exception as err:                      # noqa: BLE001
            report["errors"]["virtualenv"] = f"{type(err).__name__}: {err}"
    else:
        report["results"]["virtualenv"] = {"skipped": "this machine cannot make a venv with pip"}

    try:
        first = json.loads(tools.cve_integrity({}))
        second = json.loads(tools.cve_integrity({}))
        report["results"]["integrity_first"] = summarise_integrity(first)
        report["results"]["integrity_second"] = summarise_integrity(second)
    except Exception as err:                          # noqa: BLE001
        report["errors"]["integrity"] = f"{type(err).__name__}: {err}"

    for name, fn in (("plan", tools.cve_plan), ("coverage", tools.cve_coverage),
                     ("sbom", tools.cve_sbom), ("image", tools.cve_image),
                     ("apply", tools.cve_apply)):
        try:
            args = {"image": "alpine:3.20"} if name == "image" else {}
            if name == "apply":
                # dry run, typed confirmation: it must refuse or answer without changing anything
                args = {"host": "this", "confirm": "this", "dry_run": True}
            payload = json.loads(fn(args))
            summary = {"exit": payload.get("exit_code"),
                       "reason": (payload.get("reason") or "")[:200],
                       "state": payload.get("state") or payload.get("status")}
            if name == "plan":
                summary.update(steps=len(payload.get("steps") or []),
                               refusals=[r.get("reason", "")[:120] for r in
                                         payload.get("refusals") or []])
            if name == "sbom":
                summary.update(path=payload.get("path"), components=payload.get("components"))
            if name == "apply":
                summary.update(applied=payload.get("applied"),
                               handoff=bool(payload.get("handoff")))
            report["results"][name] = summary
        except Exception as err:                      # noqa: BLE001
            report["errors"][name] = f"{type(err).__name__}: {err}"

    if out_path:
        with open(out_path, "w") as handle:
            json.dump(report, handle, indent=1, sort_keys=True)
    print(digest(report))
    return 0


def digest(report: dict) -> str:
    """One line per surface — enough to compare distros at a glance, nothing to wade through."""
    rows = report.get("results") or {}
    lines = [f"HOST {report['machine']['os']} · python {report['machine']['python']}"]

    scan = rows.get("scan") or {}
    if scan:
        lines.append(
            "SCAN exit={exit} adapter={adapter} os={os}/{release} pending={pending} "
            "kernel={kernel} lag={lag} vendor={vendor_state} support={support} blind={blind}".format(**scan))
    libs = rows.get("libraries") or {}
    if libs:
        lines.append(
            "LIBS packages={packages} findings={findings} mine={mine} distro={distro} "
            "eco={by_ecosystem} venvs={venvs}".format(
                venvs=(libs.get("outcomes") or {}).get("venvs"), **libs))
    project = rows.get("project_lockfiles") or {}
    if project:
        lines.append("PROJECT files={n} packages={packages} findings={findings} detail={detail}".format(
            n=len(project.get("files") or {}), packages=project.get("packages"),
            findings=project.get("findings"), detail=project.get("files")))
    venv_row = rows.get("virtualenv") or {}
    lines.append("VENV " + json.dumps(venv_row))
    first, second = rows.get("integrity_first") or {}, rows.get("integrity_second") or {}
    if first:
        lines.append("INTEGRITY first={state} tamper={tamper} changed={changed} conffiles={conffiles} "
                     "unreadable={unreadable} volatile={volatile} preload={preload} sockets={sockets}"
                     "/{socket_count} drift={drift}".format(**first))
        lines.append("INTEGRITY second={state} sockets={sockets} drift={drift}".format(**second))
    plan = rows.get("plan") or {}
    lines.append("PLAN steps={steps} refusals={refusals}".format(**plan) if plan else "PLAN none")
    for name in ("coverage", "sbom", "image", "apply"):
        if name in rows:
            lines.append(name.upper() + " " + json.dumps(rows[name]))
    if report.get("errors"):
        lines.append("ERRORS " + json.dumps(report["errors"]))
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
