"""The pure decision core: no I/O, no network, no clock of its own.

Ported from ``~/hermes-admin/scripts/cve-watch.py``, which stays the daily routine on the
beelink — this module is the same logic with the same behaviour, because the behaviour *is*
the product (see ``docs/design.md``, rules 1–8). Every function here takes its inputs as
arguments and returns a value; ``tests/test_verdict.py`` asserts the same 23 statements the
routine's ``--selftest`` asserts, unchanged, plus the release-codename lever added for hosts
that do not run 26.04.

Vocabulary the callers must respect:

* a kernel is ``kernel-update-available`` / ``kernel-reboot-needed`` / ``kernel-current`` —
  three states, because "installed" is not "running";
* an image is ``current`` / ``rebuilt`` / ``not-comparable`` / ``unknown`` — and only
  ``unknown`` is a blind spot: a registry that refused to answer must never read as clean;
* ``explain`` returns an advisory id or ``None``; ``None`` means "no advisory names this
  exact version", never "patched".
"""
from __future__ import annotations

import datetime as dt
import re

# An advisory older than this is not accepted as the explanation for a fix we can see today.
USN_DAYS = 21

# The Ubuntu release this deployment tracks, in the form the USN feed uses.
DEFAULT_RELEASE = "resolute"


def abi(release: str) -> tuple:
    """'7.0.0-43-generic' -> ((7,0,0), 43): comparable, blind to flavour suffixes."""
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)-(\d+)", release.strip())
    return (tuple(int(x) for x in m.groups()[:3]), int(m.group(4))) if m else ((), 0)


INST_RE = re.compile(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+) (.+?) \[(\w+)\]\)")


def parse_inst(sim_text: str) -> list[dict]:
    """The `Inst` lines of an apt simulation: package, version now, version offered, origin."""
    out = []
    for line in sim_text.splitlines():
        m = INST_RE.match(line.strip())
        if m:
            out.append({"package": m.group(1), "from": m.group(2), "to": m.group(3),
                        "origin": m.group(4), "arch": m.group(5)})
    return out


def usn_index(notices: list, days: int = USN_DAYS, now: dt.datetime | None = None,
              release: str = DEFAULT_RELEASE) -> dict:
    """{(package, fixed version): advisory id} for notices still recent enough to explain a fix."""
    now = now or dt.datetime.now(dt.timezone.utc)
    idx = {}
    for n in notices:
        try:
            published = dt.datetime.fromisoformat(n["published"])
            if published.tzinfo is None:
                published = published.replace(tzinfo=dt.timezone.utc)
        except Exception:                                     # noqa: BLE001 - undated notice
            continue
        if (now - published).days > days:
            continue
        for p in (n.get("release_packages") or {}).get(release, []):
            name, version = p.get("name"), p.get("version")
            if name and version:
                idx.setdefault((name, version), n.get("id"))
    return idx


def explain(pkg: str, to: str, idx: dict) -> str | None:
    """Which advisory, if any, names this exact package version."""
    if (pkg, to) in idx:
        return idx[(pkg, to)]
    for candidate_name in (re.sub(r"-?(64k|edge)$", "", pkg),
                           "linux" if re.match(r"^linux-(image|modules|headers|tools)", pkg) else ""):
        if candidate_name and (candidate_name, to) in idx:
            return idx[(candidate_name, to)]
    return None


def kernel_verdict(running: str, newest_installed: str | None, candidate: str | None) -> str:
    """Three states, never two: a patch counts only when it is the kernel that is running."""
    run = abi(running)
    newest = abi(newest_installed) if newest_installed else ((), 0)
    cand = abi(candidate) if candidate else ((), 0)
    if cand > newest:
        return "kernel-update-available"          # a newer kernel exists to install
    if newest > run:
        return "kernel-reboot-needed"             # installed, not running: boot it
    return "kernel-current"


def image_state(local_digest: str | None, registry_digest: str | None,
                ref: str) -> str:
    """current / rebuilt / not-comparable (no registry ref) / unknown (the registry refused).

    'unknown' is deliberately not 'not-comparable': a rate-limited registry (HTTP 429) answering
    nothing is a blind spot, and reading it as "nothing to do" is the false all-clear this class
    exists to prevent — measured here, the same probe returned 4 rebuilt images and then 0.
    """
    if registry_digest and registry_digest.startswith("err:"):
        # "no-such-image" is the expected answer for an image built here, not a blind spot; a rate
        # limit (or any other refusal) is. Only the second class is reported as unverified.
        if registry_digest == "err:no-such-image":
            return "not-comparable"
        return "unknown"
    if not local_digest or not registry_digest:
        return "not-comparable"                   # local build or untagged image id
    return "current" if local_digest.split("@")[-1] == registry_digest else "rebuilt"


def proposal(host: str, pending: list[dict], kern: str, images: list[dict]) -> str:
    """The exact commands to close what was found — the whole point of the routine.

    `full-upgrade`, never `upgrade`: a new kernel arrives as a new *package*, which plain
    `upgrade` keeps back (rule 4).
    """
    lines = []
    if pending or kern == "kernel-update-available":
        lines.append("sudo apt update && sudo apt full-upgrade -y")
    if kern in ("kernel-update-available", "kernel-reboot-needed"):
        lines.append("sudo reboot" + ("   # then confirm: uname -r" if pending else ""))
    if any(i["state"] == "rebuilt" for i in images):
        lines.append("# container images rebuilt upstream: in each compose project, "
                     "docker compose pull && docker compose up -d")
    return "\n".join(lines) or "(nothing)"
