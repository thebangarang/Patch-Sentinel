"""Arch Linux — `pacman`, and the distro's own comparator instead of a regex.

The kernel trap here is the opposite of Fedora's: Arch *does* install a package called `linux`, but
its version is written `6.12.9.arch1-1` while `uname -r` says `6.12.9-arch1-1`. Converting the
release to the package form (one dot for the first dash) lets `vercmp` — shipped with pacman, the
same function pacman itself uses — answer both orders exactly, instead of a regex that would sort
`6.12.10` below `6.12.9`.
"""
from __future__ import annotations

import re

from .. import hostprobe
from . import common

FAMILY = "pacman"
OS_IDS = ("arch", "manjaro", "endeavouros", "garuda", "artix", "cachyos", "archcraft")
KERNEL_PACKAGES = ("linux", "linux-lts", "linux-zen", "linux-hardened", "linux-rt")

BLOCK = (
    "uname -r; "
    "for p in linux linux-lts linux-zen linux-hardened linux-rt; do "
    "v=$(pacman -Q $p 2>/dev/null | cut -d' ' -f2); "
    "[ -n \"$v\" ] && echo $p $v; done; "
    "echo " + hostprobe.MARK_K + "; "
    "pacman -Qu 2>/dev/null; "
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

_ROW_RE = re.compile(r"^(\S+)\s+(\S+)\s+->\s+(\S+)$")


def running_as_package_version(release: str) -> str:
    """``6.12.9-arch1-1`` → ``6.12.9.arch1-1`` (Arch writes the pkgver with a dot)."""
    text = (release or "").strip()
    match = re.match(r"^(\d+(?:\.\d+)+)-(.+)$", text)
    return f"{match.group(1)}.{match.group(2)}" if match else text


def parse(body: str) -> dict:
    for mark in (hostprobe.MARK_K, hostprobe.MARK_A, hostprobe.MARK_I, hostprobe.MARK_R):
        if mark not in body:
            raise ValueError(f"probe output missing {mark}")
    head, rest = body.split(hostprobe.MARK_K, 1)
    updates, rest = rest.split(hostprobe.MARK_A, 1)
    images_block, os_block = rest.split(hostprobe.MARK_I, 1)[1].split(hostprobe.MARK_R, 1)

    lines = [line.strip() for line in head.strip().splitlines() if line.strip()]
    if not lines:
        raise ValueError("no kernel release reported")
    running = lines[0]
    installed, installed_versions = [], {}
    for line in lines[1:]:
        bits = line.split()
        if len(bits) == 2 and bits[0] in KERNEL_PACKAGES:
            installed.append(bits[1])
            installed_versions[bits[1]] = bits[1]

    pending, candidate = [], None
    for line in updates.splitlines():
        match = _ROW_RE.match(line.strip())
        if not match:
            continue
        name, old, new = match.groups()
        pending.append({"package": name, "from": old, "to": new, "origin": "archlinux", "arch": ""})
        if name in KERNEL_PACKAGES:
            candidate = new

    running_version = running_as_package_version(running)
    newest = installed[-1] if installed else None
    if not installed:
        kernel, kernel_reason = common.kernel_reading([], running, candidate)
    else:
        # exact comparison: the running release in package form, newest installed, candidate
        if candidate and candidate != newest and _newer(candidate, newest):
            kernel, kernel_reason = "kernel-update-available", ""
        elif newest != running_version and _newer(newest, running_version):
            kernel, kernel_reason = "kernel-reboot-needed", ""
        elif newest == running_version:
            kernel, kernel_reason = "kernel-current", ""
        else:
            kernel, kernel_reason = "kernel-unknown", (
                f"the running release {running} could not be matched to an installed kernel package "
                f"(installed: {', '.join(installed)})")

    images, answers, outcome = common.parse_images(images_block)
    return {"running": running, "newest_installed": newest,
            "installed_packages": installed_versions, "candidate": candidate,
            "kernel": kernel, "kernel_reason": kernel_reason, "pending": pending,
            "images": images, "images_outcome": outcome,
            "os": common.parse_os(os_block), "registry_answers": answers}


def _newer(a: str, b: str) -> bool:
    """Arch-style ordering for the versions this adapter deals with (`6.12.10-1` > `6.12.9-1`).

    pacman's own `vercmp` is the authority on a live host; this is only the fallback used when the
    package versions are compared offline (tests, fixtures). Numeric segments compare numerically,
    so `6.12.10` beats `6.12.9` — the bug a plain string comparison has.
    """
    def key(version: str):
        parts = re.split(r"[.\-]", version)
        out = []
        for part in parts:
            out.append((0, int(part)) if part.isdigit() else (1, part))
        return out
    try:
        return key(a) > key(b)
    except TypeError:
        return a > b
