"""One round trip per host: what is running, what is installed, what apt would install, what
the registry says about each running image, and which Ubuntu release this is.

One round trip on purpose. The routine this was ported from learned it: five separate ssh
sessions per host is five connect timeouts, five chances to hang, and a scan that takes long
enough for nobody to run it. The composite command is delimited with sentinels; if a sentinel
is missing the answer is a refusal ("unexpected output shape"), never a partial reading
reported as complete.

Everything below ``parse()`` is a fact read from the host. No verdict is formed here; verdicts
come from :mod:`patch_sentinel.verdict`, which is pure and unit-tested.
"""
from __future__ import annotations

import datetime as dt

from .. import verdict
from . import registry, shell

MARK_K = "@@K@@"
MARK_A = "@@A@@"
MARK_I = "@@I@@"
MARK_R = "@@R@@"

# `local`/`remote` are deliberately not used as variable names here: bash reads `local=$(...)`
# as an assignment to a variable called local, which works but reads like the builtin.
PROBE_CMD = (
    "uname -r; "
    "dpkg-query -W -f='${Package} ${Version}\\n' 'linux-image-[0-9]*' 2>/dev/null | sort -V | tail -3; "
    "echo " + MARK_K + "; "
    "flav=$(uname -r | sed -n 's/^[0-9]*\\.[0-9]*\\.[0-9]*-[0-9]*-//p'); "
    "apt-cache pkgnames linux-image- 2>/dev/null "
    "| grep -E \"^linux-image-[0-9].*-${flav:-generic}$\" | sort -V | tail -3 "
    "| while read -r p; do c=$(apt-cache policy \"$p\" 2>/dev/null "
    "| sed -n 's/^  Candidate: //p'); if [ -n \"$c\" ] && [ \"$c\" != \"(none)\" ]; "
    "then echo \"${p#linux-image-}\"; fi; done; "
    "echo " + MARK_A + "; "
    "apt-get -s dist-upgrade 2>/dev/null | grep '^Inst ' || true; "
    "echo " + MARK_I + "; "
    "if ! command -v docker >/dev/null 2>&1; then echo 'img|no-docker||'; "
    "elif ! docker ps >/dev/null 2>&1; then echo 'img|docker-unreadable||'; "
    "else for i in $(docker ps --format '{{.Image}}' | sort -u); do "
    "locald=$(docker image inspect \"$i\" --format '{{index .RepoDigests 0}}' 2>/dev/null); "
    "remoted=$(docker buildx imagetools inspect \"$i\" --format '{{.Manifest.Digest}}' 2>&1 "
    "| tr '\\n' ' '); "
    "echo \"img|$i|$locald|$remoted\"; sleep 1; done; fi; "
    "echo " + MARK_R + "; "
    "(. /etc/os-release 2>/dev/null; echo \"${ID:-unknown} ${VERSION_CODENAME:-unknown}\")"
)


def parse(out: str) -> dict:
    """Split the probe's output into facts. Raises ValueError on an unexpected shape.

    Returns ``{running, newest_installed, candidate, kernel, pending, images,
    images_outcome, os:{id, codename}, registry_answers}``. ``images_outcome`` is
    ``measured`` / ``unreadable`` (docker present, refused) / ``not-applicable`` (no docker,
    so there are no images on this host to be wrong about).
    """
    for mark in (MARK_K, MARK_A, MARK_I, MARK_R):
        if mark not in out:
            raise ValueError(f"probe output missing {mark}")
    head, rest = out.split(MARK_K, 1)
    kblock, rest = rest.split(MARK_A, 1)
    ablock, rest = rest.split(MARK_I, 1)
    iblock, rblock = rest.split(MARK_R, 1)

    head_lines = [line for line in head.strip().splitlines() if line]
    if not head_lines:
        raise ValueError("no kernel release reported")
    running = head_lines[0].strip()
    installed = []
    installed_packages: dict[str, str] = {}
    for line in head_lines[1:]:
        bits = line.split()
        if len(bits) == 2 and bits[0].startswith("linux-image-"):
            release_name = bits[0].replace("linux-image-", "", 1)
            installed.append(release_name)
            installed_packages[release_name] = bits[1]
    newest = max(installed, key=verdict.abi) if installed else None
    candidates = [line.strip() for line in kblock.splitlines() if line.strip()]
    candidate = max(candidates, key=verdict.abi) if candidates else None

    images: list[dict] = []
    registry_answers: dict[str, str] = {}
    images_outcome = "measured"
    for line in iblock.splitlines():
        if not line.startswith("img|"):
            continue
        ref, local_d, remote_raw = (line.split("|", 3) + ["", "", ""])[1:4]
        if ref in ("no-docker", "docker-unreadable"):
            images_outcome = "not-applicable" if ref == "no-docker" else "unreadable"
            images = []
            registry_answers = {}
            break
        classified = registry.classify(remote_raw)
        registry_answers[ref] = registry.detail(remote_raw)
        images.append({"ref": ref, "local": local_d.strip(),
                       "registry": classified, "answer": registry.detail(remote_raw),
                       "state": verdict.image_state(local_d.strip(), classified, ref)})

    os_bits = rblock.strip().split()
    os_info = {"id": os_bits[0] if os_bits else "unknown",
               "codename": os_bits[1] if len(os_bits) > 1 else "unknown"}

    return {
        "running": running,
        "newest_installed": newest,
        "installed_packages": installed_packages,
        "candidate": candidate,
        "kernel": verdict.kernel_verdict(running, newest, candidate),
        "pending": verdict.parse_inst(ablock),
        "images": images,
        "images_outcome": images_outcome,
        "os": os_info,
        "registry_answers": registry_answers,
    }


def probe(label: str, target: str | None = None, timeout: int = shell.DEFAULT_TIMEOUT) -> dict:
    """Measure one host. Returns ``{"ok": True, ...facts, "label", "target", "measured_at"}``
    or ``{"ok": False, "label", "why", "detail"}`` — never raises."""
    measured_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    code, out = shell.run(PROBE_CMD, target, timeout=timeout)
    if code != 0 or not out:
        return {"ok": False, "label": label, "target": target, "measured_at": measured_at,
                "why": f"could not read the host (rc={code})", "detail": out[:300]}
    try:
        facts = parse(out)
    except ValueError as exc:
        return {"ok": False, "label": label, "target": target, "measured_at": measured_at,
                "why": f"unexpected output shape: {exc}", "detail": out[:300]}
    return {"ok": True, "label": label, "target": target, "measured_at": measured_at, **facts}
