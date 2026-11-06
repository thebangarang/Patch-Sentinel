"""Alpine Linux — `apk`. **Written, not registered: no lab host yet.**

Alpine's cloud images (both the plain `alpine-*` and the `nocloud_*` variant) booted to a login
prompt without processing the cloud-init seed, so this parser has never been exercised against a
real Alpine host. `adapters/__init__.py` deliberately leaves it out of the registry: an unproven
adapter would make an Alpine box look measured when it is not. Everything below is the design for
the day a host exists — the update list, the kernel-package names, and the version-namespace
problem all come from apk's documented behaviour, not from a measurement.

Original notes, kept because the design is sound:

Alpine Linux — `apk`, the package manager inside most container images.

No package called `kernel`: Alpine's kernel packages are `linux-lts`, `linux-virt`, `linux-edge` and
`linux-vanilla` — the same trap Fedora's kernel-core-only image set.

Version comparison is the part with no shortcut. The kernel *release* says `6.12.9-0-lts` (ABI
number) while the *package* says `6.12.9-r0` (release): two namespaces that only agree on the
upstream triple. Running-vs-installed is therefore compared on X.Y.Z, and the payload says so rather
than pretending the numbers are interchangeable. Candidate-vs-installed is compared the same way,
which is enough to answer "is there something newer to install".
"""
from __future__ import annotations

import re

from .. import hostprobe, registry
from . import common

FAMILY = "apk"
OS_IDS = ("alpine",)
KERNELS = ("linux-lts", "linux-virt", "linux-edge", "linux-vanilla", "linux-rpi")

_UPGRADE_RE = re.compile(r"^Upgrading\s+(\S+)\s+\(([^)]+)\s*->\s*([^)]+)\)")
_TRIPLE_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")

BLOCK = (
    "uname -r; "
    "apk info -v 2>/dev/null | grep -E '^(linux-(lts|virt|edge|vanilla|rpi))-[0-9]'; "
    "echo " + hostprobe.MARK_K + "; "
    "apk upgrade --simulate --available 2>&1; "
    "echo " + hostprobe.MARK_A + "; "
    "echo " + hostprobe.MARK_I + "; "
    "if ! command -v docker >/dev/null 2>&1; then echo 'img|no-docker||'; "
    "elif ! docker ps >/dev/null 2>&1; then echo 'img|docker-unreadable||'; "
    "else for i in $(docker ps --format '{{.Image}}' | sort -u); do "
    "locald=$(docker image inspect $i --format '{{index .RepoDigests 0}}' 2>/dev/null); "
    "remoted=$(docker buildx imagetools inspect $i --format '{{.Manifest.Digest}}' 2>&1 | head -1); "
    "echo img'|'$i'|'$locald'|'$remoted; sleep 1; done; fi; "
    "echo " + hostprobe.MARK_R + "; "
    "(. /etc/os-release 2>/dev/null; echo ${ID:-unknown} ${VERSION_ID:-unknown})"
)


def _split(name_version: str) -> tuple[str, str]:
    """``linux-lts-6.12.9-r0`` → (``linux-lts``, ``6.12.9-r0``): the version begins at the first dash
    followed by a digit, the only rule that survives names containing dashes."""
    match = re.match(r"^(.+?)-(\d.*)$", name_version)
    return (match.group(1), match.group(2)) if match else (name_version, "")


def _triple(version: str) -> tuple:
    match = _TRIPLE_RE.match((version or "").strip())
    return tuple(int(x) for x in match.groups()) if match else ()


def parse(body: str) -> dict:
    for mark in (hostprobe.MARK_K, hostprobe.MARK_A, hostprobe.MARK_I, hostprobe.MARK_R):
        if mark not in body:
            raise ValueError(f"probe output missing {mark}")
    head, rest = body.split(hostprobe.MARK_K, 1)
    simulate, rest = rest.split(hostprobe.MARK_A, 1)
    images_block, os_block = rest.split(hostprobe.MARK_I, 1)[1].split(hostprobe.MARK_R, 1)

    lines = [line.strip() for line in head.strip().splitlines() if line.strip()]
    if not lines:
        raise ValueError("no kernel release reported")
    running = lines[0]
    installed = []
    for line in lines[1:]:
        name, version = _split(line.split()[0])
        if version and name in KERNELS:
            installed.append(version)

    pending, candidate = [], None
    for line in simulate.splitlines():
        match = _UPGRADE_RE.match(line.strip())
        if not match:
            continue
        name, old, new = match.group(1), match.group(2), match.group(3)
        pending.append({"package": name, "from": old, "to": new, "origin": "alpine", "arch": ""})
        if name in KERNELS:
            candidate = new

    newest = max(installed, key=_triple) if installed else None
    if not installed:
        kernel, kernel_reason = common.kernel_reading([], running, candidate)
    else:
        verb = ("the running kernel and the installed package are compared on their upstream "
                "X.Y.Z: Alpine's -rN (package release) and the kernel's -N (ABI) are different "
                "namespaces")
        if candidate and _triple(candidate) > _triple(newest):
            kernel, kernel_reason = "kernel-update-available", ""
        elif _triple(newest) > _triple(running):
            kernel, kernel_reason = "kernel-reboot-needed", ""
        else:
            kernel, kernel_reason = "kernel-current", verb

    images, answers, outcome = common.parse_images(images_block)
    return {"running": running, "newest_installed": newest,
            "installed_packages": {v: v for v in installed}, "candidate": candidate,
            "kernel": kernel, "kernel_reason": kernel_reason, "pending": pending,
            "images": images, "images_outcome": outcome,
            "os": common.parse_os(os_block), "registry_answers": answers}
