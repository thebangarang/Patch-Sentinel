"""SUSE / openSUSE — `zypper`, and the kernel that is not called `kernel-default`.

Measured on Leap 15.6: `rpm -q kernel-default` answers *"package kernel-default is not installed"*
while the box plainly runs one — the running kernel belongs to **kernel-default-base**, whose
version-release (`6.4.0-150600.23.100.1.150600.12.46.2`) does not look like the release string
(`6.4.0-150600.23.100-default`) at all.

So the adapter does not guess at names or strip suffixes: it asks RPM which package owns the
running kernel image (`rpm -qf /boot/vmlinuz-$(uname -r)`), and compares that package's version
with the installed kernel packages and the candidate. That is the distro's own answer to "which
kernel is this", and it survives flavour renames.

The update list is `zypper -q lu` (list-updates, quiet): a `|`-separated table whose last two
columns are the current and the available version.
"""
from __future__ import annotations

import re

from .. import hostprobe
from . import common

FAMILY = "zypper"
OS_IDS = ("opensuse-leap", "opensuse-tumbleweed", "opensuse", "sles", "sled", "suse")
KERNEL_PACKAGES = ("kernel-default", "kernel-default-base", "kernel-rt", "kernel-azure", "kernel-kvmsmall")

BLOCK = (
    "uname -r; "
    # the package that OWNS the running kernel: the only trustworthy answer to "which kernel is this"
    "rpm -qf /boot/vmlinuz-$(uname -r) --qf 'RUN|%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null; "
    "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null "
    "| grep -E '^kernel-(default|default-base|rt|rt-base|azure|kvmsmall|vanilla|xen) '; "
    "echo " + hostprobe.MARK_K + "; "
    "zypper -q lu 2>/dev/null; "
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

_FLAVOUR_RE = re.compile(r"^(.*?)-(default|default-base|rt|azure|kvmsmall)$")
KERNEL_NAME_RE = re.compile(r"^kernel-(default|default-base|rt|rt-base|azure|kvmsmall|vanilla|xen)$")


def running_as_version(release: str) -> str:
    """``6.4.0-150600.23.30-default`` → ``6.4.0-150600.23.30`` (fallback only).

    The adapter prefers the package RPM reports as owning the running kernel; this string form is
    used when that query fails, and it is the reason the fallback exists rather than being trusted.
    """
    match = _FLAVOUR_RE.match((release or "").strip())
    return match.group(1) if match else (release or "").strip()


def _newer(a: str, b: str) -> bool:
    """Numeric-segment ordering (`6.4.0-…23.30` > `6.4.0-…23.25`), which is what SUSE's versions
    need for the comparison this adapter makes."""
    def key(version: str):
        out = []
        for part in re.split(r"[.\-]", version):
            out.append((0, int(part)) if part.isdigit() else (1, part))
        return out
    try:
        return key(a) > key(b)
    except TypeError:
        return a > b


def parse_updates(text: str) -> list[dict]:
    """The `zypper -q lu` table → pending entries. Headers and the separator row are skipped."""
    pending = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or "|" not in line or set(line) <= set("-| "):
            continue
        cells = [cell.strip() for cell in line.split("|")]
        if cells[0].lower().startswith(("repository", "s ")):
            continue
        if len(cells) >= 4:
            name, current, available = cells[-3], cells[-2], cells[-1]
        elif len(cells) == 3:
            name, current, available = cells
        else:
            continue
        if not name or not available:
            continue
        pending.append({"package": name, "from": current or None, "to": available,
                        "origin": "zypper", "arch": ""})
    return pending


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
    running_package_version = None
    installed, installed_versions = [], {}
    for line in lines[1:]:
        if line.startswith("RUN|"):
            # the package RPM reports as owning the running kernel image: first-class evidence
            bits = line[4:].split()
            if len(bits) == 2 and KERNEL_NAME_RE.match(bits[0]):
                running_package_version = bits[1]
            continue
        bits = line.split()
        if len(bits) != 2 or not KERNEL_NAME_RE.match(bits[0]):
            continue
        installed.append(bits[1])
        installed_versions[bits[1]] = bits[1]

    pending = parse_updates(updates)
    candidate = next((p["to"] for p in pending if p["package"] in installed_versions
                      or KERNEL_NAME_RE.match(p["package"])), None)

    running_version = running_package_version or running_as_version(running)
    newest = max(installed, key=lambda v: v) if installed else None
    if installed:
        newest = installed[0]
        for version in installed[1:]:
            if _newer(version, newest):
                newest = version

    if not installed:
        kernel, kernel_reason = common.kernel_reading([], running, candidate)
    elif candidate and _newer(candidate, newest):
        kernel, kernel_reason = "kernel-update-available", ""
    elif _newer(newest, running_version):
        kernel, kernel_reason = "kernel-reboot-needed", ""
    elif newest == running_version:
        kernel, kernel_reason = "kernel-current", ""
    else:
        kernel, kernel_reason = "kernel-unknown", (
            f"the running release {running} does not match an installed kernel package "
            f"(installed: {', '.join(installed)})")

    images, answers, outcome = common.parse_images(images_block)
    return {"running": running, "newest_installed": newest,
            "installed_packages": installed_versions, "candidate": candidate,
            "kernel": kernel, "kernel_reason": kernel_reason, "pending": pending,
            "images": images, "images_outcome": outcome,
            "os": common.parse_os(os_block), "registry_answers": answers}
