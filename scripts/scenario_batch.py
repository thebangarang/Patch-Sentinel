"""Case-scenario batch: the situations a beta user actually lands in, each on its own empty home.

Every scenario builds a small world (a lockfile set, a broken state file, a dead network) and then
checks the payloads against invariants that must hold for *every* answer the plugin gives:

  * a JSON object with a `tool` name and `exit_code` in {0, 2}
  * counts that agree with the lists they count
  * no placeholder or invented command (`<version>`, `==latest`, `…`)
  * no Python repr leaking into user-facing text (`None`, `null`, `nan`)
  * an answer that never claims a clean it did not measure
  * two identical runs on an unchanged machine

Run: `python3 scripts/scenario_batch.py [-v]`
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import traceback
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from patch_sentinel import store, tools                                   # noqa: E402
from patch_sentinel.sources import osv                                   # noqa: E402

CLEAN_WORDS = ("clean", "0 finding", "no advisory", "nothing to fix", "up to date")
LOOK_UNMEASURED = ("unmeasured", "not measured", "could not", "cannot", "can't", "unknown",
                   "not read", "unverifiable", "no runtime", "not installed")

findings: list[str] = []
checks = 0


def fail(scenario: str, message: str) -> None:
    findings.append(f"{scenario}: {message}")


def expect(scenario: str, condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        fail(scenario, message)


def walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            # quoted vendor text (an advisory's own workarounds) may legitimately say "None."
            if key == "workaround":
                continue
            yield from walk_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from walk_strings(item)


#: the fields whose strings are meant to be pasted into a shell
COMMAND_FIELDS = ("command", "commands", "would_run", "fix", "fixes", "handoff", "handover",
                  "verify", "reversal", "stage", "apply", "run")


def commands_in(value, field: str = ""):
    """Every string a field says to paste into a shell, however deeply nested.

    Commands are found by the field they live in rather than by the verb they start with: a check that
    greps for privilege words gets confused by prose about them, and this file is test code.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            yield from commands_in(item, key)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            yield from commands_in(item, field)
        return
    if isinstance(value, str) and (field in COMMAND_FIELDS or field.endswith("command")):
        for part in value.split("\n"):
            if part.strip():
                yield part.strip()


def invariants(scenario: str, tool: str, payload: dict) -> None:
    expect(scenario, isinstance(payload, dict), f"{tool} did not return an object")
    if not isinstance(payload, dict):
        return
    expect(scenario, payload.get("tool") == tool,
           f"{tool} answered as {payload.get('tool')!r}")
    # the documented contract is 0 nothing to do / 1 something to patch / 2 could not look
    expect(scenario, payload.get("exit_code") in (0, 1, 2),
           f"{tool} exit_code is {payload.get('exit_code')!r}, expected 0, 1 or 2")
    if payload.get("exit_code") == 1:
        found = (payload.get("vulnerable") or payload.get("steps") or payload.get("findings")
                 or payload.get("vulnerable_count") or payload.get("pending")
                 or payload.get("library_findings") or payload.get("commands"))
        expect(scenario, bool(found),
               f"{tool} exits 1 (something to patch) but carries nothing to patch")

    for text in walk_strings(payload):
        for bad in ("None", "null", "undefined", "nan", "NaN", "{'", "Traceback"):
            if bad in text and not text.lstrip().startswith("{"):
                fail(scenario, f"{tool} leaks {bad!r} in text: {text[:120]!r}")
        if "==latest" in text:
            fail(scenario, f"{tool} offers '==latest' as a version: {text[:120]!r}")

    for command in commands_in(payload):
        if any(token in command for token in ("<version>", "<pkg>", "<", ">", "…")):
            fail(scenario, f"{tool} hands over a placeholder command: {command!r}")

    vulnerable = payload.get("vulnerable")
    if isinstance(vulnerable, list):
        expect(scenario, payload.get("vulnerable_count") in (None, len(vulnerable)),
               f"{tool} says {payload.get('vulnerable_count')} findings but lists {len(vulnerable)}")
    packages = payload.get("packages")
    if isinstance(packages, list) and isinstance(payload.get("packages_count"), int):
        expect(scenario, payload["packages_count"] == len(packages),
               f"{tool} says {payload['packages_count']} packages but lists {len(packages)}")

    answer = " ".join(text for text in walk_strings(payload.get("answer"))).lower()
    blind = payload.get("blind") or payload.get("gaps") or payload.get("unmeasured") or []
    if blind and answer:
        expect(scenario, any(word in answer for word in LOOK_UNMEASURED),
               f"{tool} reports {len(blind)} unmeasured surface(s) but the answer does not say so: "
               f"{answer[:160]!r}")
    if payload.get("exit_code") == 2 and answer:
        expect(scenario, any(word in answer for word in LOOK_UNMEASURED) or "no " in answer
               or "nothing" in answer or "refus" in answer,
               f"{tool} exits 2 without saying why: {answer[:160]!r}")


def run(scenario: str, tool: str, args: dict) -> dict:
    started = time.time()
    try:
        payload = json.loads(tools.HANDLERS[tool](args))
    except Exception:                                      # noqa: BLE001 - that is the finding
        fail(scenario, f"{tool} raised:\n{traceback.format_exc(limit=3)}")
        return {}
    took = time.time() - started
    invariants(scenario, tool, payload)
    if took > 90:
        fail(scenario, f"{tool} took {took:.0f}s")
    return payload


# ----------------------------------------------------------------- the worlds

def settings_for(scenario: str, home: str, data: str) -> dict:
    return {"hosts": f"this=local", "release": "", "data_dir": data, "timeout": 90}


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as handle:
        handle.write(text)


def polyglot(root: str) -> None:
    write(f"{root}/package-lock.json", json.dumps({"name": "app", "lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/lodash": {"version": "4.17.4"},
        "node_modules/minimist": {"version": "1.2.0"}}}))
    write(f"{root}/yarn.lock", "lodash@^4.17.0:\n  version \"4.17.4\"\n  resolved \"https://x\"\n")
    write(f"{root}/pnpm-lock.yaml", "lockfileVersion: '6.0'\npackages:\n  /lodash/4.17.4:\n")
    write(f"{root}/requirements.txt",
          "# a comment\nurllib3==1.24.1\nrequests>=2.0\n\n-r other.txt\nflask[async]==2.0.0\n"
          "git+https://example.com/x.git\n")
    write(f"{root}/constraints.txt", "idna==2.7\n")
    write(f"{root}/poetry.lock", '[[package]]\nname = "certifi"\nversion = "2018.4.16"\n')
    write(f"{root}/Pipfile.lock", json.dumps({"default": {"six": {"version": "==1.11.0"}}}))
    write(f"{root}/go.sum", "github.com/pkg/errors v0.8.0 h1:abc=\ngithub.com/pkg/errors v0.8.0/go.mod h1:def=\n")
    write(f"{root}/Cargo.lock", '[[package]]\nname = "time"\nversion = "0.1.42"\n')
    write(f"{root}/composer.lock", json.dumps({"packages": [
        {"name": "guzzlehttp/guzzle", "version": "6.3.0"}]}))
    write(f"{root}/Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.0.1)\n")
    write(f"{root}/pubspec.lock", "packages:\n  http:\n    version: \"0.12.0\"\n")


def monorepo(root: str) -> None:
    write(f"{root}/package.json", json.dumps({"workspaces": ["packages/*"]}))
    write(f"{root}/packages/a/package-lock.json", json.dumps({"lockfileVersion": 2, "packages": {
        "node_modules/left-pad": {"version": "1.3.0"}}}))
    write(f"{root}/packages/b/yarn.lock", "lodash@^4:\n  version \"4.17.4\"\n")
    write(f"{root}/packages/a/node_modules/left-pad/package.json", '{"version": "9.9.9"}')


def hostile(root: str) -> None:
    write(f"{root}/requirements.txt",
          "app-e\u0301==1.0.0\nname with space==1.0.0\n../../etc/hosts==1.0.0\n"
          "verylong==" + "9" * 40 + "\n" + "x" * 5000 + "==1.0.0\n")
    write(f"{root}/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/a": {"version": "../../etc/hosts"},
        "node_modules/b": {"version": "1.0.0"}, "node_modules/b": {"version": "2.0.0"}}}))
    write(f"{root}/go.sum", "\x00\x01binary\x00garbage\n")


# ----------------------------------------------------------------- the scenarios

def scenario_new_user(verbose: bool) -> None:
    name = "new-user"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, f"{home}/data"))
    coverage = run(name, "cve_coverage", {})
    expect(name, isinstance(coverage.get("gaps"), list) and coverage["gaps"],
           "a fresh install reports no gaps table at all")
    run(name, "cve_libraries", {})
    run(name, "cve_integrity", {})


def scenario_returning_user(verbose: bool) -> None:
    name = "returning-user"
    home = tempfile.mkdtemp(prefix="s-home-")
    data = f"{home}/data"
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, data))
    first = run(name, "cve_libraries", {})
    second = run(name, "cve_libraries", {})
    key = lambda payload: sorted((c.get("ecosystem"), c.get("package"), c.get("version"))
                                for c in (payload.get("packages") or []))
    expect(name, key(first) == key(second),
           "the same machine gave two different inventories on two runs")
    expect(name, (first.get("vulnerable_count") or 0) == (second.get("vulnerable_count") or 0),
           "the finding count changed between two identical runs")


def scenario_polyglot(verbose: bool) -> None:
    name = "polyglot-project"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, f"{home}/data"))
    root = f"{home}/poly"
    polyglot(root)
    payload = run(name, "cve_libraries", {"project": root})
    files = (payload.get("project") or {}).get("files")
    if isinstance(files, dict):
        expect(name, len(files) >= 8, f"only {len(files)} lockfile kinds were read of 11 planted")


def scenario_monorepo(verbose: bool) -> None:
    name = "monorepo"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, f"{home}/data"))
    root = f"{home}/mono"
    monorepo(root)
    payload = run(name, "cve_libraries", {"project": root})
    # `components` is a count in the libraries payload; the list itself is `packages`
    packages = payload.get("packages") or []
    expect(name, not any(p.get("version") == "9.9.9" for p in packages),
           "read the decoy inside node_modules instead of the lockfile")
    expect(name, any(p.get("package") == "left-pad" for p in packages),
           "missed the workspace package's lockfile")


def scenario_hostile(verbose: bool) -> None:
    name = "hostile-project"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, f"{home}/data"))
    root = f"{home}/hostile"
    hostile(root)
    payload = run(name, "cve_libraries", {"project": root})
    expect(name, payload.get("exit_code") in (0, 1, 2), "hostile input produced no verdict")
    for text in walk_strings(payload):
        expect(name, "\x00" not in text, "binary garbage reached the answer")


def scenario_no_network(verbose: bool) -> None:
    name = "no-network"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, f"{home}/data"))
    original = osv.query

    def dead(*args, **kwargs):
        raise urllib.error.URLError("network is unreachable")

    osv.query = dead
    try:
        payload = run(name, "cve_libraries", {})
    finally:
        osv.query = original
    answer = json.dumps(payload).lower()
    expect(name, payload.get("exit_code") == 2,
           "with no network the libraries check still exited 0")
    expect(name, not any(word in answer for word in ("all clean", "0 finding")),
           "with no network the libraries check claimed a clean result")


def scenario_dead_registry(verbose: bool) -> None:
    name = "osv-http-429"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, f"{home}/data"))
    original = osv.query

    def limited(*args, **kwargs):
        return {"ok": False, "why": "OSV answered HTTP 429", "results": [], "queried": 0}

    osv.query = limited
    try:
        payload = run(name, "cve_libraries", {})
    finally:
        osv.query = original
    expect(name, payload.get("exit_code") == 2, "a 429 from the registry still exited 0")


def scenario_readonly_data(verbose: bool) -> None:
    name = "read-only-data"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    data = f"{home}/data"
    os.makedirs(data, exist_ok=True)
    os.chmod(data, stat.S_IRUSR | stat.S_IXUSR)
    tools.configure(settings_for(name, home, data))
    try:
        payload = run(name, "cve_integrity", {"action": "baseline"})
    finally:
        os.chmod(data, stat.S_IRWXU)
    expect(name, payload.get("exit_code") in (0, 2),
           "a read-only data directory produced no verdict")


def scenario_corrupt_state(verbose: bool) -> None:
    name = "corrupt-state"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    data = f"{home}/data"
    os.makedirs(data, exist_ok=True)
    write(f"{data}/acks.json", "{not json at all")
    write(f"{data}/integrity.json", "\x00\x00trunc")
    write(f"{data}/settings.json", '{"hosts": 42}')
    tools.configure(settings_for(name, home, data))
    run(name, "cve_ack", {"action": "release", "package": "x", "advisory": "GHSA-x"})
    run(name, "cve_integrity", {})


def scenario_clock_skew(verbose: bool) -> None:
    name = "clock-skew"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    data = f"{home}/data"
    os.makedirs(data, exist_ok=True)
    write(f"{data}/integrity.json", json.dumps({
        "this": {"state": "ok", "read_at": time.time() + 86400, "sockets": [], "tamper": {},
                 "preload": {}, "note": ""}}))
    tools.configure(settings_for(name, home, data))
    payload = run(name, "cve_integrity", {})
    text = json.dumps(payload).lower()
    expect(name, "d ago" not in text.replace("-", ""), "a future timestamp was rendered as an age")


def scenario_empty_project(verbose: bool) -> None:
    name = "empty-project"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, f"{home}/data"))
    empty = f"{home}/empty"
    os.makedirs(empty, exist_ok=True)
    write(f"{empty}/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {}}))
    write(f"{empty}/requirements.txt", "")
    payload = run(name, "cve_libraries", {"project": empty})
    expect(name, payload.get("exit_code") == 2,
           "a project that pins nothing exited 0")


def scenario_project_is_a_file(verbose: bool) -> None:
    name = "project-is-a-file"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, f"{home}/data"))
    path = f"{home}/notes.txt"
    write(path, "hello")
    payload = run(name, "cve_libraries", {"project": path})
    expect(name, payload.get("exit_code") == 2, "a file passed as a project was scanned")


def scenario_apply_gate(verbose: bool) -> None:
    name = "apply-gate"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, f"{home}/data"))
    wrong = run(name, "cve_apply", {"host": "this", "confirm": "not-the-host", "dry_run": True})
    expect(name, wrong.get("exit_code") == 2 and not wrong.get("applied")
           and "gate" in json.dumps(wrong).lower(),
           "a wrong typed confirmation was not refused")
    unknown = run(name, "cve_apply", {"host": "no-such-host", "confirm": "no-such-host"})
    expect(name, unknown.get("exit_code") == 2, "apply answered for a host not in the inventory")


def scenario_host_entry_injection(verbose: bool) -> None:
    """A host entry is user text that reaches a shell. It must never become a command."""
    name = "host-entry-injection"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    marker = f"{home}/injected"
    evil = f"127.0.0.1;touch {marker}"
    tools.configure({"hosts": f"this=local,evil={evil}", "data_dir": f"{home}/data", "timeout": 30})
    run(name, "cve_coverage", {})
    payload = run(name, "cve_libraries", {"host": "evil"})
    expect(name, not os.path.exists(marker),
           "a semicolon in a host entry was executed as a command")
    expect(name, payload.get("exit_code") in (0, 1, 2), "an injection-shaped host produced no verdict")


def scenario_duplicate_labels(verbose: bool) -> None:
    name = "duplicate-labels"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure({"hosts": "this=local,this=127.0.0.1,twin=local", "data_dir": f"{home}/data",
                     "timeout": 30})
    payload = run(name, "cve_coverage", {})
    labels = [h.get("label") for h in (payload.get("hosts") or [])]
    expect(name, len(labels) == len(set(labels)), f"a duplicate label survived: {labels}")


def scenario_awkward_project_path(verbose: bool) -> None:
    name = "path-with-spaces-and-a-loop"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, f"{home}/data"))
    root = f"{home}/my project (copy)"
    write(f"{root}/requirements.txt", "urllib3==1.24.1\n")
    os.symlink(root, f"{root}/loop")                      # a directory that contains itself
    payload = run(name, "cve_libraries", {"project": root})
    expect(name, payload.get("exit_code") in (0, 1),
           "a path with spaces and a symlink loop was not scanned")


def scenario_data_dir_is_a_file(verbose: bool) -> None:
    name = "data-dir-is-a-file"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    path = f"{home}/not-a-directory"
    write(path, "I am a file")
    tools.configure(settings_for(name, home, path))
    payload = run(name, "cve_integrity", {"action": "baseline"})
    expect(name, payload.get("exit_code") == 2,
           "a data directory that is actually a file did not refuse")


def scenario_bad_inputs(verbose: bool) -> None:
    name = "bad-arguments"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    tools.configure(settings_for(name, home, f"{home}/data"))
    explain = run(name, "cve_explain", {"id": "not-an-advisory"})
    expect(name, explain.get("exit_code") == 2, "a garbage advisory id was not refused")
    ack = run(name, "cve_ack", {"action": "ack", "package": "x", "advisory": "GHSA-x"})
    expect(name, ack.get("exit_code") == 2, "an acknowledgement with no reason was accepted")


def scenario_rescan_bundle(verbose: bool) -> None:
    """"scan all" is per device now: one press must read every surface of that one device, keep the
    other devices' blocks intact, and never report a stage as clean when it could not look."""
    name = "scan-all-one-device"
    home = tempfile.mkdtemp(prefix="s-home-")
    os.environ["HOME"] = home
    data = f"{home}/data"
    tools.configure(settings_for(name, home, data))
    payload = run(name, "cve_rescan", {})
    bundle = payload.get("bundle") or {}
    stages = [stage.get("name") for stage in bundle.get("stages") or []]
    expect(name, stages == ["scan", "integrity", "libraries", "plans"],
           f"the stages did not run in the pane's order (packages, integrity, libs): {stages}")
    expect(name, (bundle.get("stages") or [{}])[-1].get("name") == "plans",
           "the plan did not run last — it is built from the measurement that just ran")
    expect(name, os.path.exists(f"{data}/rescan.json"), "the bundle was not written to the data dir")
    devices = bundle.get("devices") or {}
    expect(name, len(devices) == 1, f"one press measured {len(devices)} device(s), expected 1")
    for label, device in devices.items():
        for surface in ("scan", "libraries", "integrity", "plan"):
            expect(name, device.get(surface), f"{label} carries no {surface} reading")
        expect(name, device.get("measured_at"), f"{label} has no measurement time")
    codes = [stage.get("exit_code") for stage in bundle.get("stages") or []]
    expect(name, payload.get("exit_code") == max(codes),
           f"the run reports {payload.get('exit_code')} while its worst stage is {max(codes)}")
    expect(name, bundle.get("stage") == "done", "the bundle does not say it finished")
    # a second run must replace the stages, and keep the device block it already had
    again = run(name, "cve_rescan", {})
    expect(name, len((again.get("bundle") or {}).get("stages") or []) == 4,
           "a second run appended stages instead of starting a new one")
    expect(name, bool((again.get("bundle") or {}).get("devices")),
           "a second run dropped the device block")


SCENARIOS = [
    ("new user, empty home", scenario_new_user),
    ("returning user, second run", scenario_returning_user),
    ("polyglot project, 11 lockfile kinds", scenario_polyglot),
    ("monorepo with nested lockfiles", scenario_monorepo),
    ("hostile input", scenario_hostile),
    ("no network at all", scenario_no_network),
    ("registry answers 429", scenario_dead_registry),
    ("read-only data directory", scenario_readonly_data),
    ("corrupt state files", scenario_corrupt_state),
    ("clock skew (future timestamp)", scenario_clock_skew),
    ("project that pins nothing", scenario_empty_project),
    ("project path is a file", scenario_project_is_a_file),
    ("apply gate", scenario_apply_gate),
    ("host entry shaped like a command", scenario_host_entry_injection),
    ("duplicate host labels", scenario_duplicate_labels),
    ("path with spaces and a symlink loop", scenario_awkward_project_path),
    ("data directory is a file", scenario_data_dir_is_a_file),
    ("bad arguments", scenario_bad_inputs),
    ("scan all: one device, every surface", scenario_rescan_bundle),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-k", "--only", default="")
    args = parser.parse_args()

    before = len(findings)
    for label, function in SCENARIOS:
        if args.only and args.only.lower() not in label.lower():
            continue
        started = time.time()
        mark = len(findings)
        try:
            function(args.verbose)
        except Exception:                                  # noqa: BLE001 - reported as a finding
            fail(label, "scenario crashed:\n" + traceback.format_exc(limit=3))
        status = "ok" if len(findings) == mark else f"{len(findings) - mark} finding(s)"
        print(f"{status:>12}  {label}  ({time.time() - started:.0f}s)")

    print(f"\n{checks} assertions, {len(findings) - before} finding(s)")
    for line in findings[before:]:
        print(f"  ! {line}")
    return 1 if len(findings) > before else 0


if __name__ == "__main__":
    sys.exit(main())
