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
import functools
import json
import os
import re

from . import plan, schemas, store, verdict
from .sources import cve_tracker, dispatch, usn
from .sources import hosts as inventory_module

MAX_PENDING = 60              # a payload the model can read; the count is always the true one
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
    parts = [f"{host['label']}: {len(pending)} package update(s) installable"
             + (f", {len(advisories)} named by a recent advisory ({', '.join(advisories[:4])})"
                if advisories else ", none named by a recent advisory")]
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
        pending = []
        for item in result.get("pending") or []:
            entry = dict(item)
            entry["advisory"] = verdict.explain(item.get("package", ""), item.get("to", ""), index)
            pending.append(entry)
        named = [p for p in pending if p.get("advisory")]
        images = result.get("images") or []
        unknown = [i for i in images if i.get("state") == "unknown"]
        rebuilt = [i for i in images if i.get("state") == "rebuilt"]

        outcomes = {
            "kernel": "unmeasured" if result.get("kernel") == "kernel-unknown" else "ok",
            "apt": "ok",
            "advisories": "ok" if feed.get("ok") else "refused",
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
            return _json({"tool": "cve_scan",
                          **_refusal(f"host {requested!r} is not in the inventory — nothing was "
                                     "measured for it",
                                     nearest=_labels(),
                                     measured_hosts=[])})
        return _json(_scan_payload([requested]))
    return _json(_scan_payload())


@_never_raises
def cve_plan(args: dict, **kwargs) -> str:
    requested = str(args.get("host") or "").strip() or _local_label()
    if requested.lower() not in {label.lower() for label in _labels()}:
        return _json({"tool": "cve_plan",
                      **_refusal(f"host {requested!r} is not in the inventory", nearest=_labels())})

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
        "not_in_this_version": "applying — the plan is the deliverable; an apply step needs the "
                               "operator to type the host name and is not enabled in 0.1.0",
    })


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

    gaps = [
        {"gap": "CVEs inside container image layers", "state": "not measured",
         "why": "needs an image scanner (trivy) and a vulnerability database; v0.2",
         "consequence": "a rebuilt image is reported as 'an update exists', never as "
                        "'these CVEs are fixed'"},
        {"gap": "language and package-manager dependencies (npm, pip, go, cargo)",
         "state": "not measured",
         "why": "needs an SBOM and a dependency scanner (osv-scanner); v0.2",
         "consequence": "a vulnerable library inside your own code is invisible to this scan"},
        {"gap": "hosts that do not run Ubuntu", "state": "not measured",
         "why": "the advisory feed read here is Ubuntu's ('release' = " + str(scan.get("release")) + ")",
         "consequence": "deb-based facts still read, advisory attribution does not"},
    ]
    unreachable = [b for b in (stored.get("blind") or []) if b.get("class") == "host"]
    for blind in stored.get("blind") or []:
        if blind.get("class") == "host":
            continue
        gaps.append({"gap": f"{blind.get('class')} on {blind.get('host')}", "state": "unmeasured",
                     "why": blind.get("reason"), "consequence": "reported as unknown, not clean"})
    for label, host in hosts.items():
        if (host.get("os") or {}).get("id") not in ("ubuntu", None):
            gaps.append({"gap": f"advisory coverage for {label}",
                         "state": "partial",
                         "why": f"os id is {(host.get('os') or {}).get('id')}, not ubuntu",
                         "consequence": "package facts are read, advisory ids are not"})

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


HANDLERS = {
    "cve_scan": cve_scan,
    "cve_plan": cve_plan,
    "cve_explain": cve_explain,
    "cve_coverage": cve_coverage,
}

__all__ = ["HANDLERS", "SCHEMAS", "configure", "cve_scan", "cve_plan", "cve_explain",
           "cve_coverage"]

SCHEMAS = schemas.SCHEMAS
