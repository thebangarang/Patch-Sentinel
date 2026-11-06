"""Vendor lag: an advisory that names a fixed version the archive does not offer yet.

This is the state the plugin was missing. A host can be *correctly* reported as "0 pending" while a
known CVE is still open, because the distro has not shipped the fix: the advisory says "fixed in
1.2.3-1ubuntu0.4", apt's best candidate is 1.2.3-1ubuntu0.3, and nothing on the machine can be
installed to close it. Folding that into "nothing to do" is the exact false comfort this project
exists to avoid.

The answer is built from two sources that already exist in the scan:

* the Ubuntu notice feed, which names the fixed version per release (``usn.fixed_versions``);
* the host itself, asked one question per affected package — what is installed, and what is the
  archive's best candidate (``dpkg-query`` and ``apt-cache policy``).

Three outcomes per package:

``fixed``      installed >= the advisory's fix — the machine is ahead of the advisory.
``available``  the archive offers the fix and it is in the pending list.
``vendor-lag`` the advisory names a fix, the archive's candidate is older (or there is none): the
               patch exists upstream and has not reached this archive. Nothing here can close it,
               which is why saying so is the useful thing to do.

Version comparison is Debian's own ordering (epoch, upstream, revision; ``~`` sorts lowest, digits
compare numerically). A wrong comparison here would manufacture a lag that is not real, so the
comparator is unit-tested against the cases that bite: ``1.0~rc1 < 1.0``, ``1.2.3-1ubuntu0.4 >
1.2.3-1ubuntu0.3``, ``2:1.0 > 1:9.9``.
"""
from __future__ import annotations

import re

# One round trip, not one per package: dpkg answers for every name (cheap), `apt-cache policy` runs
# only for the ones actually installed. 472 names from a recent-notice window is a normal size.
MAX_PACKAGES = 400


def _epoch(version: str) -> tuple[int, str]:
    epoch, sep, rest = (version or "").partition(":")
    if not sep:
        return 0, version or ""
    try:
        return int(epoch), rest
    except ValueError:
        return 0, version or ""


def _parts(upstream: str) -> tuple[str, str]:
    """Split ``1.2.3-1ubuntu0.4`` into (upstream, revision) the way dpkg does."""
    if "-" not in upstream:
        return upstream, ""
    head, _, tail = upstream.rpartition("-")
    return head, tail


def _order(char: str) -> int:
    """dpkg's character order: ``~`` lowest, then end-of-string, then letters, then everything else.

    This is the whole reason a hand-rolled "split on dots and compare numbers" comparator is wrong:
    in Debian, ``1.0a`` sorts *below* ``1.0.0`` (a letter is below a dot), and ``1.0~rc1`` below
    ``1.0``. Getting either backwards turns a pre-release into a vendor lag that does not exist.
    """
    if char == "~":
        return -1
    if char == "":
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _cmp_chunk(left: str, right: str) -> int:
    """A port of dpkg's ``verrevcmp``: non-digit runs compare by :func:`_order`, digit runs
    numerically (leading zeros ignored)."""
    i = j = 0
    while i < len(left) or j < len(right):
        while ((i < len(left) and not left[i].isdigit())
               or (j < len(right) and not right[j].isdigit())):
            a = _order(left[i] if i < len(left) else "")
            b = _order(right[j] if j < len(right) else "")
            if a != b:
                return -1 if a < b else 1
            i += 1
            j += 1
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        first_diff = 0
        while i < len(left) and left[i].isdigit() and j < len(right) and right[j].isdigit():
            if not first_diff:
                first_diff = ord(left[i]) - ord(right[j])
            i += 1
            j += 1
        if i < len(left) and left[i].isdigit():
            return 1
        if j < len(right) and right[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def compare(left: str, right: str) -> int:
    """-1 / 0 / 1 for two Debian versions. Mirrors ``dpkg --compare-versions`` closely enough for
    this comparison, and the cases that matter are pinned in the tests."""
    epoch_a, rest_a = _epoch(left)
    epoch_b, rest_b = _epoch(right)
    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1
    up_a, rev_a = _parts(rest_a)
    up_b, rev_b = _parts(rest_b)
    result = _cmp_chunk(up_a, up_b)
    if result:
        return result
    return _cmp_chunk(rev_a, rev_b)


def probe_command(packages: list[str]) -> str:
    """One round trip that asks the host for each package's installed and candidate version."""
    names = " ".join(_quote(name) for name in packages[:MAX_PACKAGES])
    # apt-cache policy is the expensive call (one per package), so it only runs for what is installed
    return ("for p in " + names + "; do "
            "i=$(dpkg-query -W -f='${Version}' \"$p\" 2>/dev/null); "
            "if [ -n \"$i\" ]; then "
            "c=$(apt-cache policy \"$p\" 2>/dev/null | sed -n 's/^  Candidate: //p'); "
            "echo \"$p|$i|$c\"; fi; done")


def _quote(name: str) -> str:
    """Package names are [a-z0-9.+-] in practice; anything else is dropped rather than escaped."""
    return name if re.fullmatch(r"[A-Za-z0-9.+_-]+", name or "") else "''"


def parse(out: str) -> dict[str, dict]:
    """``name|installed|candidate`` lines → ``{name: {installed, candidate}}``."""
    rows: dict[str, dict] = {}
    for line in (out or "").splitlines():
        bits = line.strip().split("|")
        if len(bits) != 3 or not bits[0]:
            continue
        name, installed, candidate = bits
        if candidate == "(none)":
            candidate = ""
        rows[name] = {"installed": installed or "", "candidate": candidate or ""}
    return rows


def classify(rows: dict[str, dict], advisories: dict[str, dict]) -> dict:
    """Sort every advisory-named package into fixed / available / vendor-lag.

    *advisories* maps a package name to ``{version, notice, cves}`` — the fix the vendor named.
    """
    lag, available, fixed, unknown = [], [], [], []
    for name, advisory in advisories.items():
        wanted = advisory.get("version") or ""
        row = rows.get(name)
        if not row or not row.get("installed"):
            unknown.append({"package": name, "fixed_version": wanted,
                            "notice": advisory.get("notice"),
                            "why": "not installed on this host"})
            continue
        installed, candidate = row["installed"], row.get("candidate") or ""
        entry = {"package": name, "installed": installed, "candidate": candidate or None,
                 "fixed_version": wanted, "notice": advisory.get("notice"),
                 "cves": advisory.get("cves") or []}
        if wanted and compare(installed, wanted) >= 0:
            fixed.append(entry)
        elif wanted and candidate and compare(candidate, wanted) >= 0:
            available.append(entry)
        elif wanted and candidate:
            lag.append({**entry, "why": f"the archive's best candidate is {candidate}, "
                                        f"the advisory names {wanted}"})
        else:
            lag.append({**entry, "why": "the archive offers no candidate for this package at all"})
    return {"vendor_lag": lag, "fix_available": available, "already_fixed": fixed,
            "not_installed": unknown,
            "counts": {"vendor_lag": len(lag), "fix_available": len(available),
                       "already_fixed": len(fixed), "not_installed": len(unknown)}}
