"""One probe per host, whichever package manager that host runs.

A Hermes plugin runs on the user's machine, not on ours. So "what is pending here?" is answered by
*that* distro's own tool, and the adapter is chosen on the host itself — from `/etc/os-release`, in
one round trip — never assumed from what we happen to run.

Shape of an adapter (``apt`` and ``dnf`` are grown; the rest announce themselves as unsupported):

* a shell block that emits the sections below, and
* a parser that turns them into the same ``facts`` dict ``cve_scan`` consumes.

Sections, shared by every adapter so one downstream shape survives::

    @@FAMILY@@<name>      which adapter answered (the host's own id decided it)
    <head>                uname -r, then the installed kernel packages, one per line
    @@K@@                 the available kernel (raw tool output, parsed in Python)
    @@A@@                 pending updates (raw tool output, parsed in Python)
    @@I@@                 container images: img|ref|local digest|registry answer
    @@R@@                 os-release: id and version id

Two rules this file exists to enforce:

1. **An unimplemented family is a refusal, not a clean.** The ``none`` branch carries the distro id
   and the scan reports ``unsupported`` with its reason — red in GAPS, never green.
2. **A kernel that cannot be measured says so.** A container has no kernel package; that is
   ``kernel-unknown`` with its reason, never ``kernel-current``. The container this adapter was
   developed on proved how easy that mistake is.

Shell-writing rule for this file: the blocks use single quotes only, and no awk. Facts are emitted
raw and parsed here, because a quoting layer between us and the host has already cost a debugging
session once — the parser is testable, a shell one-liner is not.
"""
from __future__ import annotations

import datetime as dt

from .. import verdict
from . import hostprobe, registry, shell
from .adapters import BY_FAMILY as EXTRA_ADAPTERS

FAMILY_MARK = "@@FAMILY@@"

# Which os-release `ID` each adapter claims. Anything else is `unsupported`, by name.
FAMILY_BY_OS: dict[str, tuple[str, ...]] = {
    "apt": ("ubuntu", "debian", "linuxmint", "pop", "raspbian", "kali", "elementary",
            "zorin", "mx", "proxmox", "devuan"),
    "dnf": ("fedora", "rhel", "rocky", "almalinux", "centos", "ol", "nobara", "amzn"),
}
# The families that live in their own module (adapters/), each with its own quirks.
for _family, _module in EXTRA_ADAPTERS.items():
    FAMILY_BY_OS[_family] = tuple(_module.OS_IDS)

# The image half is shared by every family: a rebuilt tag is a rebuilt tag whatever the package
# manager. `head -1` because a multi-line registry error would otherwise break the one-line record;
# the classification only needs the first line's token.
_IMAGES_BLOCK = (
    "if ! command -v docker >/dev/null 2>&1; then echo 'img|no-docker||'; "
    "elif ! docker ps >/dev/null 2>&1; then echo 'img|docker-unreadable||'; "
    "else for i in $(docker ps --format '{{.Image}}' | sort -u); do "
    "locald=$(docker image inspect $i --format '{{index .RepoDigests 0}}' 2>/dev/null); "
    "remoted=$(docker buildx imagetools inspect $i --format '{{.Manifest.Digest}}' 2>&1 | head -1); "
    "echo img'|'$i'|'$locald'|'$remoted; sleep 1; done; fi"
)

_DNF_BLOCK = (
    "uname -r; "
    # every installed version, so the update list can say what each package is *now* (I| prefix)
    "rpm -qa --qf 'I|%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null; "
    "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'kernel*' 2>/dev/null; "
    "echo " + hostprobe.MARK_K + "; "
    "dnf -q list --available kernel 2>/dev/null; "
    "echo " + hostprobe.MARK_A + "; "
    "dnf -q check-update 2>/dev/null; "
    "echo " + hostprobe.MARK_I + "; " + _IMAGES_BLOCK + "; "
    "echo " + hostprobe.MARK_R + "; "
    "(. /etc/os-release 2>/dev/null; echo ${ID:-unknown} ${VERSION_ID:-unknown})"
)

# The apt block is the probe this plugin was born with — unchanged, because it is the one proven
# live on a real host (beelink, 26.04) and its parser carries the ported assertions.
_APT_BLOCK = hostprobe.PROBE_CMD

_UBUNTU_LIKE = "|".join(FAMILY_BY_OS["apt"])
_RPM_LIKE = "|".join(FAMILY_BY_OS["dnf"])

def _case_branches() -> str:
    """One ``case`` branch per family, each announced with its own mark."""
    branches = [
        _UBUNTU_LIKE + ") echo " + FAMILY_MARK + "apt; " + _APT_BLOCK + " ;; ",
        _RPM_LIKE + ") echo " + FAMILY_MARK + "dnf; " + _DNF_BLOCK + " ;; ",
    ]
    for family, module in EXTRA_ADAPTERS.items():
        pattern = "|".join(module.OS_IDS)
        branches.append(pattern + ") echo " + FAMILY_MARK + family + "; " + module.BLOCK + " ;; ")
    return "".join(branches)


PROBE_SCRIPT = (
    ". /etc/os-release 2>/dev/null; "
    "case ${ID:-unknown} in "
    + _case_branches()
    + "*) echo " + FAMILY_MARK + "none; echo 'unsupported|'${ID:-unknown} ;; "
    "esac"
)


def family_for(os_id: str | None) -> str:
    """``ubuntu`` → ``apt``; an unknown id → ``none`` (a refusal, never a guess)."""
    name = (os_id or "").strip().lower()
    for family, ids in FAMILY_BY_OS.items():
        if name in ids:
            return family
    return "none"


# The packages that ARE the kernel. Fedora's cloud image installs `kernel-core` and does not
# install the `kernel` metapackage at all — asking for `kernel` alone reports "not installed" on a
# machine that is plainly running one. Measured on fedora:latest and on a booted Fedora 45 VM.
KERNEL_PACKAGES = frozenset({
    "kernel", "kernel-core", "kernel-default", "kernel-rt", "kernel-rt-core",
    "kernel-uki-virt", "kernel-generic", "kernel-lts",
})


def _rpm_kernel_version(line: str) -> str | None:
    """``kernel-core 7.2.11-300.fc45`` → ``7.2.11-300.fc45``.

    Accepts the two shapes rpm prints: ``name version`` from the qf query, and the
    ``kernel-7.2.15-300.fc45.x86_64`` name-only form, stripping the arch either way.
    """
    text = line.strip()
    bits = text.split()
    if len(bits) == 2 and bits[0] in KERNEL_PACKAGES:
        version = bits[1]
    else:
        # name-only form: `kernel-7.2.15-300.fc45.x86_64`. The digit after the dash is what makes it
        # a kernel package and not `kernel-modules-core`, which is not one (measured: the bare
        # `kernel-` prefix once turned that package into a bogus "modules-core" version here).
        version = ""
        for package in sorted(KERNEL_PACKAGES, key=len, reverse=True):
            prefix = package + "-"
            if text.startswith(prefix) and text[len(prefix):len(prefix) + 1].isdigit():
                version = text[len(prefix):]
                break
        if not version:
            return None
    for suffix in (".x86_64", ".aarch64", ".noarch", ".i686", ".ppc64le", ".s390x"):
        if version.endswith(suffix):
            return version[: -len(suffix)]
    return version


def _dnf_rows(text: str) -> list[tuple[str, str, str]]:
    """Pull ``name.arch  version  repo`` rows out of a dnf table, skipping its headers.

    dnf prints 'Last metadata expiration check…', then a blank line, then a section heading
    ('Upgrades', 'Security: …', 'Obsoleting Packages'), then the rows. A row is exactly three
    whitespace-separated fields; anything else is a heading or history.
    """
    rows = []
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Last metadata") or line.startswith("Available Packages"):
            continue
        if line.lower().startswith("obsoleting packages"):
            section = "obsoleting"
            continue
        if line.lower().startswith("security:"):
            section = "updates"
            continue
        fields = line.split()
        if len(fields) == 3:
            rows.append((fields[0], fields[1], fields[2]))
    return rows


def parse_dnf(out: str) -> dict:
    """The rpm-family sections, into the same ``facts`` dict ``hostprobe.parse`` returns."""
    for mark in (hostprobe.MARK_K, hostprobe.MARK_A, hostprobe.MARK_I, hostprobe.MARK_R):
        if mark not in out:
            raise ValueError(f"probe output missing {mark}")
    head, rest = out.split(hostprobe.MARK_K, 1)
    cblock, rest = rest.split(hostprobe.MARK_A, 1)
    ablock, rest = rest.split(hostprobe.MARK_I, 1)
    iblock, rblock = rest.split(hostprobe.MARK_R, 1)

    head_lines = [line.strip() for line in head.strip().splitlines() if line.strip()]
    if not head_lines:
        raise ValueError("no kernel release reported")
    running = head_lines[0]
    installed = []
    installed_map: dict[str, str] = {}
    for line in head_lines[1:]:
        if line.startswith("I|"):
            bits = line[2:].split()
            if len(bits) == 2:
                installed_map[bits[0]] = bits[1]
            continue
        version = _rpm_kernel_version(line)
        if version:
            installed.append(version)
    installed_packages = {version: version for version in installed}
    newest = max(installed, key=verdict.abi) if installed else None

    candidates = [row[1] for row in _dnf_rows(cblock)]
    candidate = max(candidates, key=verdict.abi) if candidates else None

    pending = []
    for name, version, origin in _dnf_rows(ablock):
        package = name.rpartition(".")[0] if "." in name else name
        pending.append({"package": package, "from": installed_map.get(package), "to": version,
                        "origin": origin, "arch": name.rpartition(".")[2] if "." in name else ""})

    images, answers, outcome = [], {}, "measured"
    for line in iblock.splitlines():
        if not line.startswith("img|"):
            continue
        ref, local_d, remote_raw = (line.split("|", 3) + ["", "", ""])[1:4]
        if ref in ("no-docker", "docker-unreadable"):
            outcome = "not-applicable" if ref == "no-docker" else "unreadable"
            images, answers = [], {}
            break
        classified = registry.classify(remote_raw)
        answers[ref] = registry.detail(remote_raw)
        images.append({"ref": ref, "local": local_d.strip(), "registry": classified,
                       "answer": registry.detail(remote_raw),
                       "state": verdict.image_state(local_d.strip(), classified, ref)})

    os_bits = rblock.strip().split()
    os_info = {"id": os_bits[0] if os_bits else "unknown",
               "codename": os_bits[1] if len(os_bits) > 1 else "unknown"}

    if not installed:
        # A container (or a host with no kernel package): the running release is the HOST's, and
        # there is nothing installed to compare it with. Could not look — not "current".
        kernel = "kernel-unknown"
        kernel_reason = ("no kernel package is installed on this host, so running vs installed "
                         "cannot be compared (a container shares its host's kernel)")
    else:
        kernel, kernel_reason = verdict.kernel_verdict(running, newest, candidate), ""

    return {
        "running": running,
        "newest_installed": newest,
        "installed_packages": installed_packages,
        "candidate": candidate,
        "kernel": kernel,
        "kernel_reason": kernel_reason,
        "pending": pending,
        "images": images,
        "images_outcome": outcome,
        "os": os_info,
        "registry_answers": answers,
    }


PARSERS = {"apt": hostprobe.parse, "dnf": parse_dnf}
PARSERS.update({family: module.parse for family, module in EXTRA_ADAPTERS.items()})


def probe(label: str, target: str | None = None,
          timeout: int = shell.DEFAULT_TIMEOUT) -> dict:
    """Measure one host with whichever adapter its own os-release selects.

    Returns ``{"ok": True, "family": ..., ...facts, "label", "target", "measured_at"}``, or
    ``{"ok": False, "family": ..., "why", "detail"}``. Never raises.
    """
    measured_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    code, out = shell.run(PROBE_SCRIPT, target, timeout=timeout)
    if code != 0 or not out:
        return {"ok": False, "family": "none", "label": label, "target": target,
                "measured_at": measured_at, "why": f"could not read the host (rc={code})",
                "detail": out[:300]}
    if FAMILY_MARK not in out:
        return {"ok": False, "family": "none", "label": label, "target": target,
                "measured_at": measured_at, "why": "host answered without a family mark",
                "detail": out[:300]}
    _, rest = out.split(FAMILY_MARK, 1)
    first_line, _, body = rest.partition("\n")
    family = first_line.strip()
    if family == "none":
        os_id = body.strip().split("|")[-1].strip() if body.strip() else "unknown"
        return {"ok": False, "family": "none", "label": label, "target": target,
                "measured_at": measured_at, "os_id": os_id or "unknown", "unsupported": True,
                "why": f"no adapter for this operating system ({os_id or 'unknown'})",
                "detail": "the host answered; its package manager is not implemented yet, so its "
                          "updates are unmeasured — not clean"}
    parser = PARSERS.get(family)
    if parser is None:
        return {"ok": False, "family": family, "label": label, "target": target,
                "measured_at": measured_at, "unsupported": True,
                "why": f"adapter {family!r} is announced but not implemented",
                "detail": body[:300]}
    try:
        facts = parser(body)
    except ValueError as exc:
        return {"ok": False, "family": family, "label": label, "target": target,
                "measured_at": measured_at, "why": f"unexpected output shape: {exc}",
                "detail": body[:300]}
    return {"ok": True, "family": family, "label": label, "target": target,
            "measured_at": measured_at, **facts}
