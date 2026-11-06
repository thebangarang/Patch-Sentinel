"""The four agent-facing handlers. Each takes ``args: dict``, returns a JSON string, never raises.

Two contracts this file exists to keep:

* **A refusal is a payload.** When something could not be measured the answer carries
  ``match: "none"`` / an ``unknown`` outcome with its reason, because a model handed prose will
  substitute a plausible sentence for it (authoring rule + design rule 5).
* **Three outcomes per check.** ``outcomes`` names, per host and per source, whether it
  answered; ``exit_code`` is 2 when anything could not look — the run never reports a clean it
  did not measure (rule 7).
"""
from __future__ import annotations

import datetime as dt
import difflib
import functools
import json
import os
import re

from . import apply as apply_mod
from . import plan, schemas, store, verdict
from .sources import cve_tracker, dispatch, languages, osv, usn
from .sources import hosts as inventory_module

MAX_PENDING = 400             # the update list is a surface the operator reads, not a sample of one
PLAN_MAX_AGE = 600            # seconds a stored measurement may be reused by cve_plan
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_settings: dict = {
    "hosts": "",
    "release": verdict.DEFAULT_RELEASE,
    "usn_limit": usn.MAX_LIMIT,
    "data_dir": "",
    "timeout": 180,
}


def configure(settings: dict) -> None:
    """Called from ``register()`` with the resolved plugin config (or defaults in a probe)."""
    for key, value in (settings or {}).items():
        if value not in (None, ""):
            _settings[key] = value
    store.configure(_settings)


def _json(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


def _not_in_inventory(requested: str) -> dict:
    """Refuse an unknown host by naming the ones that exist — "not in the inventory" alone leaves
    the operator guessing which string the gate wants them to type."""
    labels = _labels()
    close = difflib.get_close_matches(requested, labels, n=1, cutoff=0.6) if labels else []
    hint = f" — did you mean {close[0]!r}?" if close else ""
    listed = ", ".join(labels) if labels else "none (the inventory is empty)"
    return _refusal(f"there is no host called {requested!r} in this inventory{hint} "
                    f"the hosts are: {listed}", nearest=labels,
                    expected=close[0] if close else (labels[0] if labels else None))


def _gap_advice(klass: str, label: str, reason: str) -> str:
    """What to actually do about a failed check — said in terms of its cause.

    "make the host answer (ssh key, host entry, or the missing tool)" was the same sentence for every
    kind of failure, and on a *local* machine it is nonsense: nothing is unreachable, docker simply
    would not talk. Advice that does not fit the cause reads as the product being confused.
    """
    reason = reason or ""
    if klass == "host":
        return (f"{label} did not answer. Check the inventory entry ({label}=user@host:port), the ssh "
                "key it needs, and that the machine is up — then press rescan.")
    if klass == "images" and "refused to list" in reason:
        return ("docker is installed but this user cannot read its socket: for a root install, "
                "`sudo usermod -aG docker $USER` (then log out and back in — a running process keeps "
                "the groups it started with, which is often why the agent's pane and your shell "
                "disagree); for rootless docker, point `DOCKER_HOST` at its socket. If this machine "
                "runs no containers, nothing is wrong — this row is the scan admitting it could not "
                "look.")
    if klass == "images":
        return ("the registry would not answer for one of these images (rate limit, private tag, or "
                "no network). Nothing changed on the host; the digest simply could not be compared. "
                "Make the tag pullable anonymously, then rescan.")
    if klass == "kernel":
        return ("no kernel package was found on this host — normal inside a container, where the "
                "kernel belongs to the host. There is nothing to fix; the row stays unknown by design.")
    if klass == "advisories":
        return ("Ubuntu's notice feed did not answer, so the pending list is measured but no CVE id is "
                "named. This usually clears on the next rescan.")
    return (f"the {klass} check could not run on {label}. The reason is above; if it is a missing "
            "tool, install it or ignore this row.")


def _refusal(reason: str, nearest: list | None = None, answer=None, **extra) -> dict:
    """The refusal shape: ``{"match": "none", "answer": null, "reason": ..., "nearest": [...]}``."""
    return {"match": "none", "answer": answer, "reason": reason,
            "nearest": list(nearest or []), **extra}


def _never_raises(handler):
    @functools.wraps(handler)
    def wrapper(args=None, **kwargs) -> str:
        try:
            return handler(args or {}, **kwargs)
        except Exception as exc:                      # noqa: BLE001 - a raise costs the whole call
            return _json({"error": f"{type(exc).__name__}: {exc}",
                          **_refusal("the tool failed internally; nothing was measured")})
    return wrapper


def _inventory() -> list[dict]:
    return inventory_module.inventory(_settings.get("hosts"),
                                      os.environ.get("PATCH_SENTINEL_HOSTS"))


def _labels() -> list[str]:
    return [h["label"] for h in _inventory()]


def _local_label() -> str:
    hosts = _inventory()
    local = next((h for h in hosts if h["target"] is None), hosts[0])
    return local["label"]


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


# ─── measurement ────────────────────────────────────────────────────────────────


def _summarise(host: dict) -> str:
    """One sentence a model can quote without inventing a number."""
    pending = host.get("pending") or []
    advisories = sorted({p["advisory"] for p in pending if p.get("advisory")})
    images = host.get("images") or []
    rebuilt = [i for i in images if i.get("state") == "rebuilt"]
    unknown = [i for i in images if i.get("state") == "unknown"]
    total = host.get("pending_count")
    total = len(pending) if total is None else total
    advisory_source = host.get("advisory_source")
    if advisory_source:
        advisory_note = (f", {len(advisories)} named by a recent advisory "
                         f"({', '.join(advisories[:4])})" if advisories
                         else ", none named by a recent advisory")
    else:
        advisory_note = (", advisory ids not attributed on this distro (only Ubuntu's feed is "
                         "wired) — the pending list is measured either way")
    parts = [f"{host['label']}: {total} package update(s) installable" + advisory_note]
    kernel = host.get("kernel") or {}
    kernel_line = f"kernel {kernel.get('running')} → {kernel.get('verdict')}"
    if kernel.get("verdict") == "kernel-unknown":
        kernel_line = f"kernel unmeasured on {host['label']} (no kernel package to compare with)"
    elif kernel.get("verdict") == "kernel-update-available" and kernel.get("installable"):
        kernel_line += f" (installable {kernel['installable']})"
    elif kernel.get("verdict") == "kernel-reboot-needed":
        kernel_line += f" (installed {kernel.get('installed')}, not running)"
    parts.append(kernel_line)
    if host.get("images_outcome") == "not-applicable":
        parts.append("no container images on this host")
    elif host.get("images_outcome") == "unreadable":
        parts.append("container images could not be read (docker refused)")
    else:
        parts.append(f"{len(rebuilt)}/{len(images)} image(s) rebuilt upstream"
                     + (f", {len(unknown)} unverified" if unknown else ""))
    return "; ".join(parts)


def _scan_payload(labels: list[str] | None = None, save: bool = True) -> dict:
    """Measure the requested hosts (default: the inventory), then annotate against the feed."""
    inventory = _inventory()
    if labels:
        wanted = {label.lower() for label in labels}
        selected = [h for h in inventory if h["label"].lower() in wanted]
    else:
        selected = inventory

    measured: list[dict] = []
    blind: list[dict] = []
    for host in selected:
        result = dispatch.probe(host["label"], host["target"],
                                timeout=int(_settings.get("timeout") or 180))
        measured.append(result)
        if not result.get("ok"):
            entry = {"host": host["label"], "class": "host", "reason": result.get("why"),
                     "detail": result.get("detail", "")}
            if result.get("unsupported"):
                entry["unsupported"] = True
                entry["os_id"] = result.get("os_id")
            blind.append(entry)

    release = str(_settings.get("release") or verdict.DEFAULT_RELEASE)
    for result in measured:
        os_info = result.get("os") or {}
        if result.get("ok") and os_info.get("id") == "ubuntu" and os_info.get("codename"):
            release = str(os_info["codename"])
            break

    feed = usn.fetch(release, int(_settings.get("usn_limit") or usn.MAX_LIMIT))
    index = verdict.usn_index(feed.get("notices") or [], release=release) if feed.get("ok") else {}
    if not feed.get("ok"):
        blind.append({"host": "-", "class": "advisories", "reason": feed.get("why"),
                      "detail": feed.get("url", "")})

    hosts_payload: dict[str, dict] = {}
    findings = 0
    for result in measured:
        if not result.get("ok"):
            continue
        label = result["label"]
        # Attribution is Ubuntu's feed only. On any other distro the pending list is still
        # measured; what is missing is the advisory id, and the summary says exactly that rather
        # than "none named by a recent advisory" — which would be a false statement about Fedora.
        os_id = (result.get("os") or {}).get("id")
        advisory_source = f"USN ({release})" if os_id == "ubuntu" and feed.get("ok") else None
        pending = []
        for item in result.get("pending") or []:
            entry = dict(item)
            entry["advisory"] = (verdict.explain(item.get("package", ""), item.get("to", ""), index)
                                 if advisory_source else None)
            pending.append(entry)
        named = [p for p in pending if p.get("advisory")]
        images = result.get("images") or []
        unknown = [i for i in images if i.get("state") == "unknown"]
        rebuilt = [i for i in images if i.get("state") == "rebuilt"]
        outcomes = {
            "kernel": "unmeasured" if result.get("kernel") == "kernel-unknown" else "ok",
            "apt": "ok",
            "advisories": ("ok" if advisory_source
                           else "not-applicable" if os_id != "ubuntu" else "refused"),
            "images": ("unreadable" if result.get("images_outcome") == "unreadable"
                       else "unknown" if unknown
                       else "not-applicable" if result.get("images_outcome") == "not-applicable"
                       else "ok"),
        }
        if outcomes["kernel"] == "unmeasured":
            blind.append({"host": label, "class": "kernel",
                          "reason": result.get("kernel_reason") or "kernel state not measurable",
                          "detail": "the kernel is unmeasured here, not current"})
        if outcomes["images"] == "unreadable":
            blind.append({"host": label, "class": "images",
                          "reason": "docker is installed but refused to list containers",
                          "detail": "the images are unmeasured, not current"})
        elif outcomes["images"] == "unknown":
            blind.append({"host": label, "class": "images",
                          "reason": f"{len(unknown)} image(s) could not be checked at the registry "
                                    f"({unknown[0].get('answer', 'no reason given')[:80]})",
                          "detail": "a refused registry is not a clean image"})

        if pending or rebuilt or result.get("kernel") in ("kernel-update-available",
                                                          "kernel-reboot-needed"):
            findings += 1
        host_payload = {
            "label": label,
            "target": result.get("target") or "local",
            "adapter": result.get("family"),
            "measured_at": result.get("measured_at"),
            "os": result.get("os"),
            "kernel": {"running": result.get("running"),
                       "installed": result.get("newest_installed"),
                       "installable": result.get("candidate"),
                       "installed_packages": result.get("installed_packages"),
                       "verdict": result.get("kernel"),
                       "reason": result.get("kernel_reason")},
            "pending": pending[:MAX_PENDING],
            "pending_count": len(pending),
            "pending_truncated": len(pending) > MAX_PENDING,
            "advised_count": len(named),
            "advisory_source": advisory_source,
            "images": images,
            "images_outcome": result.get("images_outcome"),
            "outcomes": outcomes,
        }
        host_payload["summary"] = _summarise(host_payload)
        hosts_payload[label] = host_payload

    exit_code = 2 if blind else (1 if findings else 0)
    answer = " | ".join(h["summary"] for h in hosts_payload.values())
    if blind:
        answer += " | COULD NOT LOOK: " + "; ".join(
            f"{b['host']}/{b['class']}: {b.get('reason')}" for b in blind)
    payload = {
        "tool": "cve_scan",
        "scan": {"at": _now(), "release": release, "hosts": [h["label"] for h in selected],
                 "usn_url": feed.get("url"), "usn_ok": bool(feed.get("ok")),
                 "usn_fetched_at": feed.get("fetched_at")},
        "answer": answer,
        "hosts": hosts_payload,
        "blind": blind,
        "findings": findings,
        "exit_code": exit_code,
        "limits": {"pending_listed_at_most": MAX_PENDING,
                   "in_image_cves": "not measured (needs an image scanner)",
                   "language_dependencies": "not measured (needs an SBOM + dependency scanner)"},
    }
    if save and selected:
        try:
            store.save_scan({k: payload[k] for k in
                             ("tool", "scan", "answer", "hosts", "blind", "findings", "exit_code")})
        except OSError:
            payload["stored"] = False
    return payload


# ─── tools ─────────────────────────────────────────────────────────────────────


@_never_raises
def cve_scan(args: dict, **kwargs) -> str:
    requested = str(args.get("host") or "").strip()
    if requested:
        known = {label.lower() for label in _labels()}
        if requested.lower() not in known:
            return _json({"tool": "cve_scan", "measured_hosts": [],
                          **_not_in_inventory(requested)})
        return _json(_scan_payload([requested]))
    return _json(_scan_payload())


@_never_raises
def cve_plan(args: dict, **kwargs) -> str:
    requested = str(args.get("host") or "").strip() or _local_label()
    if requested.lower() not in {label.lower() for label in _labels()}:
        return _json({"tool": "cve_plan",
                      **_not_in_inventory(requested)})

    stored = store.load_scan()
    age = store.scan_age_seconds(stored)
    hosts = (stored or {}).get("hosts") or {}
    host = next((v for k, v in hosts.items() if k.lower() == requested.lower()), None)
    fresh = age is not None and age <= PLAN_MAX_AGE
    re_measured = False
    if host is None or not fresh:
        payload = _scan_payload()
        hosts = payload.get("hosts") or {}
        host = next((v for k, v in hosts.items() if k.lower() == requested.lower()), None)
        re_measured = True
        if host is None:
            return _json({"tool": "cve_plan",
                          **_refusal(f"{requested!r} could not be read, so there is no plan for it",
                                     detail="see cve_scan's blind list")})

    planned = plan.plan_for(host)
    return _json({
        "tool": "cve_plan",
        "executes": False,
        "host": host.get("label"),
        "measured_at": host.get("measured_at"),
        "measurement_reused": not re_measured,
        "kernel": host.get("kernel"),
        "pending_count": host.get("pending_count"),
        "steps": planned["steps"],
        "refusals": planned["refusals"],
        "proposal_text": planned["proposal_text"],
        "not_in_this_version": "nothing else: the plan is what this tool returns. Acting on it is "
                               "cve_apply, which needs the host name typed and dry_run=false",
    })


@_never_raises
def cve_apply(args: dict, **kwargs) -> str:
    """The gated apply. Refuses by default; needs the host name typed and dry_run=false."""
    requested = str(args.get("host") or "").strip() or _local_label()
    host = next((h for h in _inventory() if h["label"].lower() == requested.lower()), None)
    if host is None:
        return _json({"tool": "cve_apply", "applied": False,
                      **_not_in_inventory(requested)})

    confirm = str(args.get("confirm") or "")
    dry_run = args.get("dry_run")
    dry_run = True if dry_run is None else bool(dry_run)
    timeout = max(120, min(int(args.get("timeout") or apply_mod.APPLY_TIMEOUT), 1800))

    # The apply must run against a measurement, not against a hope: reuse a fresh scan, else scan.
    stored = store.load_scan()
    age = store.scan_age_seconds(stored)
    entry = None
    if stored and age is not None and age <= PLAN_MAX_AGE:
        entry = next((v for k, v in (stored.get("hosts") or {}).items()
                      if k.lower() == requested.lower()), None)
    if entry is None:
        payload = _scan_payload([requested])
        entry = (payload.get("hosts") or {}).get(requested)
        if entry is None:
            return _json({"tool": "cve_apply", "applied": False,
                          **_refusal(f"{requested!r} could not be measured, so there is nothing "
                                     "to apply against")})

    result = apply_mod.apply(entry, host["target"], confirm, dry_run=dry_run, timeout=timeout)
    return _json({"tool": "cve_apply", **result})


@_never_raises
def cve_explain(args: dict, **kwargs) -> str:
    cve = str(args.get("cve_id") or args.get("cve") or "").strip().upper()
    if not cve:
        return _json({"tool": "cve_explain", **_refusal("no cve_id given")})
    if not CVE_RE.match(cve):
        return _json({"tool": "cve_explain",
                      **_refusal(f"{cve!r} is not a CVE identifier (expected CVE-YYYY-NNNN)")})

    stored = store.load_scan()
    release = str(((stored or {}).get("scan") or {}).get("release")
                  or _settings.get("release") or verdict.DEFAULT_RELEASE)
    feed = usn.fetch(release, int(_settings.get("usn_limit") or usn.MAX_LIMIT))
    tracker = cve_tracker.fetch(cve)
    parsed = (cve_tracker.parse(tracker["record"], release)
              if tracker.get("ok") else None)
    notices = feed.get("notices") or []
    hits = usn.for_cve(notices, cve) if feed.get("ok") else []

    if not hits and parsed is None:
        reasons = []
        if not feed.get("ok"):
            reasons.append(f"advisory feed: {feed.get('why')}")
        if not tracker.get("ok"):
            reasons.append(f"CVE tracker: {tracker.get('why')}")
        if hits == [] and feed.get("ok"):
            reasons.append(f"no fetched notice names {cve}")
        return _json({"tool": "cve_explain", "cve_id": cve,
                      **_refusal("; ".join(reasons) or "nothing was found for this CVE",
                                 nearest=usn.nearest(notices, cve, release),
                                 release=release, feed_url=feed.get("url"),
                                 tracker_url=tracker.get("url"))})

    fixed = []
    seen = set()
    for hit in hits:
        notice = next((n for n in notices if n.get("id") == hit["id"]), {})
        for entry in usn.fixed_versions(notice, release):
            key = (entry["package"], entry["version"])
            if key in seen:
                continue
            seen.add(key)
            fixed.append({**entry, "notice": hit["id"], "via": "Ubuntu security notice"})
    for slot in (parsed or {}).get("statuses", []):
        if not slot.get("version"):
            continue
        key = (slot["package"], slot["version"])
        if key in seen:
            continue
        seen.add(key)
        fixed.append({"package": slot["package"], "version": slot["version"],
                      "via": f"CVE tracker ({slot.get('status')}) — context, not a measurement",
                      "pocket": slot.get("pocket")})

    # our state, from the last measurement only — never inferred
    our_state = {"measured_at": None, "hosts": {}, "basis": "no scan yet: run cve_scan first"}
    disagreements = []
    not_compared: list = []
    if stored:
        our_state["measured_at"] = (stored.get("scan") or {}).get("at")
        our_state["basis"] = "the last cve_scan on this machine"
        advisory_ids = {h["id"] for h in hits}
        for label, host in (stored.get("hosts") or {}).items():
            installable = [p for p in (host.get("pending") or [])
                           if p.get("advisory") in advisory_ids]
            our_state["hosts"][label] = {
                "kernel_running": (host.get("kernel") or {}).get("running"),
                "kernel_installed": (host.get("kernel") or {}).get("installed"),
                "installable_from_this_advisory": [
                    {"package": p.get("package"), "to": p.get("to")} for p in installable],
                "count": len(installable),
                "reading": ("installable now" if installable else
                            "not offered by apt on this host as measured — either already "
                            "installed or not applicable here"),
            }
            if parsed:
                comparison = cve_tracker.compare_to_measurement(parsed, host)
                for item in comparison["disagreements"]:
                    disagreements.append({"host": label, **item})
                not_compared = comparison["not_compared"]

    return _json({
        "tool": "cve_explain",
        "match": "advisory" if hits else "context-only",
        "id": cve,
        "source": {"name": "Ubuntu Security Notices", "url": feed.get("url"),
                   "fetched_at": feed.get("fetched_at")},
        "published": (hits[0].get("published") if hits else (parsed or {}).get("published")),
        "tracker": ({"context_only": True,
                     "url": tracker.get("url"), "fetched_at": tracker.get("fetched_at"),
                     "status": parsed.get("status"), "priority": parsed.get("priority"),
                     "cvss3": parsed.get("cvss3"), "updated_at": parsed.get("updated_at"),
                     "notices_ids": parsed.get("notices_ids"),
                     "statuses": parsed.get("statuses"),
                     "reading": cve_tracker.narrative(parsed)}
                    if parsed else {"context_only": True, "error": tracker.get("why")}),
        "notices": hits,
        "fixed_versions": fixed,
        "our_state": our_state,
        "disagreements": disagreements,
        "not_compared": not_compared,
        "release": release,
        "caveat": "the tracker's status word is context, never the verdict: measured here, it "
                  "read 'pending' for the exact kernel version already installed and running "
                  "(rule 2 — the archive wins). 'No advisory' means no fetched Ubuntu notice "
                  "names this CVE yet; it does not mean unaffected.",
    })


@_never_raises
def cve_coverage(args: dict, **kwargs) -> str:
    stored = store.load_scan()
    age = store.scan_age_seconds(stored)
    if stored is None or age is None or age > PLAN_MAX_AGE:
        stored = _scan_payload()
        age = 0.0

    hosts = stored.get("hosts") or {}
    scan = stored.get("scan") or {}
    covered = []
    for label, host in hosts.items():
        covered.append({"source": "apt simulation (installed vs installable)",
                        "host": label, "measured_at": host.get("measured_at"),
                        "outcome": (host.get("outcomes") or {}).get("apt")})
        covered.append({"source": "running kernel vs newest installed",
                        "host": label, "measured_at": host.get("measured_at"),
                        "outcome": (host.get("outcomes") or {}).get("kernel"),
                        "running": (host.get("kernel") or {}).get("running")})
        covered.append({"source": "container image digests",
                        "host": label, "measured_at": host.get("measured_at"),
                        "outcome": (host.get("outcomes") or {}).get("images")})
    covered.append({"source": "Ubuntu security notices (advisories that name a version)",
                    "host": "-", "measured_at": scan.get("usn_fetched_at"),
                    "outcome": "ok" if scan.get("usn_ok") else "refused",
                    "url": scan.get("usn_url")})

    implemented = sorted(dispatch.FAMILY_BY_OS)
    # Every gap carries a scope (`hosts`: "every" or the labels it concerns) and a `kind`:
    #   "limit"   — a surface this version cannot see, by design. Nothing to clear; the honest
    #               answer is a statement, not a button.
    #   "blocked" — a check that ran and failed on a host (unreachable, tool missing). Fixable, and
    #               the panel says what to fix.
    gaps: list[dict] = [
        {"gap": "CVEs inside container image layers", "state": "not measured",
         "hosts": "every", "kind": "limit",
         "why": "needs an image scanner (trivy) and a vulnerability database; v0.2",
         "consequence": "a rebuilt image is reported as 'an update exists', never as "
                        "'these CVEs are fixed'",
         "next": "the real fix is outside this pane: rebuild the image on a schedule, because a "
                 "base-image CVE is only fixed by a newer base. Scanning inside layers needs an "
                 "image scanner (trivy), which 0.1.0 deliberately does not ship. Until then the "
                 "digest check still tells you a newer build exists."},
        {"gap": "language packages outside the global trees",
         "state": "partly measured", "hosts": "every", "kind": "limit",
         "why": "cve_libraries reads npm's global tree and the pip environment on PATH; "
                "per-project lockfiles, other virtualenvs and vendor/ directories are not read",
         "consequence": "a vulnerable dependency of one project can be invisible while the "
                        "machine-level list is clean",
         "next": "name the project in chat and I will query OSV for its packages ('which of my "
                 "node/python dependencies have known CVEs in ~/projects/x?'). Reading lockfiles "
                 "automatically is a 0.2 item; today it is one question away."},
        {"gap": "operating systems without an adapter", "state": "not measured",
         "hosts": "every", "kind": "limit",
         "why": f"adapters exist for: {', '.join(implemented)}; every other OS answers "
                "'unsupported' with its own id. Not implemented: Alpine (the apk adapter is written "
                "but has never read a real host), macOS, and Windows (which needs a PowerShell "
                "transport, not a package-manager block)",
         "consequence": "such a host is a red gap in this list, never a green 'patched'",
         "next": "nothing to switch on here: that host answers 'unsupported' on purpose, because "
                 "reporting it as patched would be a guess. Measuring it means adding an adapter — "
                 "a code change, not a setting. Until then use the distro's own updater, and open "
                 "an issue with the distro id from cve_coverage."},
    ]
    # one entry per *fact*, not one per host: a 20-host inventory must not bury the real gaps
    without_advisory = sorted(label for label, host in hosts.items()
                              if (host.get("os") or {}).get("id") not in ("ubuntu", None))
    if scan.get("release") and without_advisory:
        gaps.append({"gap": "advisory attribution on non-Ubuntu hosts", "state": "not attributed",
                     "kind": "limit", "hosts": without_advisory,
                     "next": "the update is still listed with both versions — you can act on it "
                             "without the CVE id. A per-distro security feed is a 0.2 item; on "
                             "Ubuntu hosts the notice feed already names the advisory.",
                     "why": "only Ubuntu's security-notice feed is wired (read for release "
                            f"{scan.get('release')}), so on these hosts the pending list is measured "
                            "but the CVE id behind each update is not named: "
                            + ", ".join(without_advisory),
                     "consequence": "the update is still listed, the CVE behind it is not"})
    unreachable = [b for b in (stored.get("blind") or []) if b.get("class") == "host"]
    for blind in stored.get("blind") or []:
        if blind.get("class") == "host":
            continue
        label = blind.get("host") or "this machine"
        gaps.append({"gap": f"{blind.get('class')} check on {label}", "state": "unmeasured",
                     "kind": "blocked", "hosts": [label],
                     "why": blind.get("reason"),
                     "consequence": "reported as unknown, not clean",
                     "next": _gap_advice(blind.get("class") or "check", label,
                                         blind.get("reason") or "")})

    return _json({
        "tool": "cve_coverage",
        "measured_at": scan.get("at"),
        "reused_measurement": age > 0,
        "covered": covered,
        "gaps": gaps,
        "hosts_unreachable": [{"host": b.get("host"), "reason": b.get("reason")}
                              for b in unreachable],
        "exit_code": stored.get("exit_code", 2),
        "note": "the gap list is never empty and never green: an empty list would be a claim "
                "that nothing is missed",
    })


LIBRARY_LIMITS = {
    "measured": "npm global tree; the pip environment of the first python3 on PATH",
    "not_measured": [
        "per-project lockfiles (package.json, composer.json, Cargo.toml, go.mod, *.csproj)",
        "virtualenvs other than the first python3 on PATH",
        "vendor/ and node_modules/ directories inside projects",
        "anything inside a container image",
    ],
    "advisory_source": "api.osv.dev (batched query, one detail fetch per advisory shown)",
}
MAX_ADVISORY_RECORDS = 40


@_never_raises
def cve_libraries(args: dict, **kwargs) -> str:
    requested = str(args.get("host") or "").strip() or _local_label()
    host = next((h for h in _inventory() if h["label"].lower() == requested.lower()), None)
    if host is None:
        return _json({"tool": "cve_libraries",
                      **_not_in_inventory(requested)})

    collected = languages.collect(host["target"])
    components = collected["components"]
    base = {"tool": "cve_libraries", "host": host["label"], "target": host["target"] or "local",
            "measured_at": collected["measured_at"], "outcomes": collected["outcomes"],
            "details": collected["details"], "by_ecosystem": collected["by_ecosystem"],
            "components": len(components), "truncated": collected["truncated"],
            # the installed list itself, so a pane can show what was checked instead of a count
            "packages": [{"ecosystem": c.get("ecosystem"), "package": c.get("package"),
                          "version": c.get("version")} for c in components[:MAX_PENDING]]}

    if not components:
        return _json({**base, "vulnerable": [], "exit_code": 2,
                      "reason": "no supported language package manager answered on this host — "
                                "nothing was measured, which is not the same as clean",
                      "limits": LIBRARY_LIMITS})

    answer = osv.query(components)
    if not answer.get("ok"):
        return _json({**base, "vulnerable": [], "exit_code": 2,
                      "reason": f"the advisory database could not be queried "
                                f"({answer.get('why')}) — unmeasured, not clean",
                      "limits": LIBRARY_LIMITS})

    pairs = list(zip(components, answer["results"]))
    wanted = sorted({vid for _, found in pairs for vid in found})
    records = {vid: osv.vuln(vid) for vid in wanted[:MAX_ADVISORY_RECORDS]}

    vulnerable = []
    for component, found in pairs:
        for vid in found:
            record = records.get(vid)
            if record:
                item = osv.summarise(record, component["ecosystem"], component["package"])
            else:
                item = {"id": vid, "aliases": [], "summary": None, "severity": None,
                        "fixed": [], "url": f"https://osv.dev/vulnerability/{vid}"}
            vulnerable.append({"ecosystem": component["ecosystem"],
                               "package": component["package"],
                               "version": component["version"], **item})

    unreadable = [eco for eco, state in collected["outcomes"].items() if state == "unreadable"]
    exit_code = 2 if unreadable else (1 if vulnerable else 0)
    answer_line = (f"{host['label']}: {len(vulnerable)} advisory match(es) across "
                   f"{len({(v['ecosystem'], v['package']) for v in vulnerable})} package(s), "
                   f"from {len(components)} installed language package(s) checked"
                   if components else f"{host['label']}: nothing measurable")
    return _json({**base, "answer": answer_line, "vulnerable": vulnerable[:MAX_PENDING],
                  "vulnerable_count": len(vulnerable),
                  "advisories_examined": len(records),
                  "advisories_truncated": len(wanted) > MAX_ADVISORY_RECORDS,
                  "exit_code": exit_code,
                  "limits": LIBRARY_LIMITS})


HANDLERS = {
    "cve_scan": cve_scan,
    "cve_plan": cve_plan,
    "cve_explain": cve_explain,
    "cve_coverage": cve_coverage,
    "cve_libraries": cve_libraries,
    "cve_apply": cve_apply,
}

__all__ = ["HANDLERS", "SCHEMAS", "configure", "cve_scan", "cve_plan", "cve_explain",
           "cve_coverage", "cve_libraries", "cve_apply"]

SCHEMAS = schemas.SCHEMAS
