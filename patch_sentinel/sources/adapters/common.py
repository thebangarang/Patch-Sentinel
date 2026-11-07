"""Shared parsing for the adapter blocks.

Every adapter emits the same sections; only the tool output inside them differs. These helpers keep
the image and os-release handling in one place, so a new distro is one block and one parser — not a
copy of the image logic with its own bugs.
"""
from __future__ import annotations

from ... import verdict
from .. import registry

#: A package manager can fail while exiting 0 and printing no update rows: zypper as a normal user on
#: Leap 15.6 says "No permission to write repository cache", and `pacman -Qu` prints nothing when its
#: sync database is stale. Reading that as "0 pending" is a false clean, so an empty list plus one of
#: these markers is reported as unmeasured.
SILENT_FAILURES = (
    "No permission", "Permission denied", "Error building the cache", "not loaded because of error",
    "Problem loading data", "Could not open lock file", "Failed to synchronize",
    "Cannot download", "error: failed to", "ERROR: ", "unable to lock database",
)


def silent_failure(text: str) -> str | None:
    """Why an empty update list cannot be trusted, or None when the output looks like a real answer."""
    for marker in SILENT_FAILURES:
        if marker in (text or ""):
            return (f"the package manager could not build its data ({marker.strip()}) — the update "
                    f"list is unmeasured, not empty")
    return None


def parse_images(block: str) -> tuple[list[dict], dict[str, str], str]:
    """``img|ref|local|registry-answer`` lines → (images, raw answers, outcome).

    ``outcome`` is ``measured`` / ``unreadable`` (docker present, refused) / ``not-applicable``
    (no docker, so no images to be wrong about).
    """
    images: list[dict] = []
    answers: dict[str, str] = {}
    outcome = "measured"
    for line in block.splitlines():
        if not line.startswith("img|"):
            continue
        ref, local_d, remote_raw = (line.split("|", 3) + ["", "", ""])[1:4]
        if ref in ("no-docker", "docker-unreadable"):
            return [], {}, ("not-applicable" if ref == "no-docker" else "unreadable")
        classified = registry.classify(remote_raw)
        answers[ref] = registry.detail(remote_raw)
        images.append({"ref": ref, "local": local_d.strip(), "registry": classified,
                       "answer": registry.detail(remote_raw),
                       "state": verdict.image_state(local_d.strip(), classified, ref)})
    return images, answers, outcome


def parse_os(block: str) -> dict:
    """``ubuntu resolute`` / ``fedora 45`` → ``{"id": ..., "codename": ...}``."""
    bits = block.strip().split()
    return {"id": bits[0] if bits else "unknown",
            "codename": bits[1] if len(bits) > 1 else "unknown"}


def kernel_reading(installed: list[str], running: str | None, candidate: str | None,
                   container_reason: str = "") -> tuple[str, str]:
    """The four kernel readings, from the installed list — never "current" with nothing installed."""
    if not installed:
        return "kernel-unknown", (container_reason or
                                  "no kernel package is installed on this host, so running vs "
                                  "installed cannot be compared (a container shares its host's kernel)")
    newest = max(installed, key=verdict.abi)
    return verdict.kernel_verdict(running or "", newest, candidate), ""
