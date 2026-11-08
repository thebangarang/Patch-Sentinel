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
import time
from pathlib import Path

from . import apply as apply_mod
from . import plan, rescan, schemas, store, verdict
from .sources import (acks, cve_tracker, dispatch, distro_lag, environments, image_db, integrity,
                      jars, languages, osv, projects, repos, sbom, services, shell, support, threat,
                      usn)
from .sources import vendor as vendor_lag
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
    # exit_code 2 is the refusal code everywhere else in the plugin, and `answer` is a sentence
    # rather than null: a pane that renders the answer must never have to render nothing.
    return {"match": "none", "answer": reason if answer is None else answer, "reason": reason,
            "nearest": list(nearest or []), "exit_code": 2, **extra}


def _never_raises(handler):
    @functools.wraps(handler)
    def wrapper(args=None, **kwargs) -> str:
        try:
            return handler(args or {}, **kwargs)
        except Exception as exc:                      # noqa: BLE001 - a raise costs the whole call
            why = (f"{handler.__name__} could not finish: {type(exc).__name__}: {exc} — nothing was "
                   f"measured, and this is a limit of the run, not a result")
            return _json({"tool": handler.__name__, "error": f"{type(exc).__name__}: {exc}",
                          **_refusal(why)})
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


def _commands_for(family) -> dict:
    """The pasteable sequence for an adapter family — empty when there is none, never a guess."""
    from .plan import COMMANDS
    entry = COMMANDS.get(str(family or "")) or {}
    return {key: entry.get(key) or ""
            for key in ("refresh", "stage", "apply", "verify", "reversal")}


def _where_for(target, label) -> dict:
    from .apply import _where
    return _where(target if target and target != "local" else None, label)


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
        advisory_note = (", no advisory id is attributed here (this host's feed names none of "
                         "these packages) — the pending list is measured either way")
    if (host.get("outcomes") or {}).get("updates") == "unmeasured":
        # never "0 installable" when the list could not be built
        parts = [f"{host['label']}: the update list could not be read — "
                 f"{(host.get('pending_reason') or 'the package manager refused')}"]
    else:
        parts = [f"{host['label']}: {total} package update(s) installable" + advisory_note]
    lag = host.get("vendor_lag") or []
    if lag:
        sample = ", ".join(f"{row['package']} (fixed {row['fixed_version']}, archive "
                           f"{row.get('candidate') or 'nothing'})" for row in lag[:3])
        more = f" (+{len(lag) - 3} more)" if len(lag) > 3 else ""
        if host.get("vendor_index_fresh") is False:
            # the comparison ran, but this host has not refreshed its package index: the archive
            # answers "nothing" because it was never asked, and saying "the fix is missing" would be
            # a claim nobody measured
            parts.append(f"{len(lag)} package(s) look older than the vendor's fix, but this host's "
                         f"package index is older than 48 h — refresh it and rescan before believing "
                         f"that — {sample}{more}")
        else:
            parts.append(f"{len(lag)} package(s) have a fix the archive does not carry yet — "
                         f"{sample}{more}")
    kernel = host.get("kernel") or {}
    kernel_line = f"kernel {kernel.get('running')} → {kernel.get('verdict')}"
    if kernel.get("verdict") == "kernel-unknown":
        kernel_line = f"kernel unmeasured on {host['label']} (no kernel package to compare with)"
    elif kernel.get("verdict") == "kernel-update-available" and kernel.get("installable"):
        kernel_line += f" (installable {kernel['installable']})"
    elif kernel.get("verdict") == "kernel-reboot-needed":
        kernel_line += f" (installed {kernel.get('installed')}, not running)"
    parts.append(kernel_line)
    support_state = host.get("support") or {}
    if support_state.get("state") == "end-of-life":
        pro = support_state.get("pro") or {}
        attached = (" — Ubuntu Pro is attached and enabled: " + ", ".join(pro.get("enabled") or [])
                    if pro.get("outcome") == "ok" and pro.get("enabled") else "")
        parts.append(f"this release is past standard support ({support_state.get('ends')})"
                     + attached + ": no new fixes are published for it")
    elif support_state.get("state") == "unknown":
        parts.append("release support state unknown (no lifecycle recorded) — not assumed supported")
    pockets = host.get("pockets") or {}
    if pockets.get("outcome") == "ok" and not (pockets.get("pockets") or {}).get("security"):
        parts.append("no security pocket is enabled on this host — a published fix may not be "
                     "delivered here at all")
    exploited_pending = sum(1 for row in (host.get("pending") or []) if row.get("kev"))
    if exploited_pending:
        parts.append(f"{exploited_pending} of these update(s) close a CVE in CISA's known-exploited "
                     f"list — those are the ones to install first")
    effect = host.get("services") or {}
    if effect.get("reboot_required"):
        owed = effect.get("reboot_packages") or []
        parts.append("a reboot is owed"
                     + (f" ({', '.join(owed[:4])})" if owed else "")
                     + " — installed is not in effect until the machine restarts")
    if effect.get("services"):
        parts.append(f"{len(effect['services'])} service(s) still map a replaced library — restart: "
                     + ", ".join(effect["services"][:3]))
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
            # an adapter that could not build its update list says so here, and the host stops
            # reading as "0 pending" (measured on Leap 15.6: zypper exits 0 with a cache error)
            "updates": "unmeasured" if result.get("pending_unmeasured") else "ok",
            "advisories": ("ok" if advisory_source
                           else "not-applicable" if os_id != "ubuntu" else "refused"),
            "images": ("unreadable" if result.get("images_outcome") == "unreadable"
                       else "unknown" if unknown
                       else "not-applicable" if result.get("images_outcome") == "not-applicable"
                       else "ok"),
        }
        # ---- vendor lag: an advisory names a fix the archive does not carry yet -------------
        # Only Ubuntu's feed names per-release fixed versions, so this runs where the feed applies:
        # the host's own codename must match the release the notices were read for.
        vendor_state = None
        host_release = (result.get("os") or {}).get("codename")
        # one place for the state directory: integrity's baseline and its last reading live there
        state_data_dir = str(_settings.get("data_dir") or store.data_dir())
        if os_id == "ubuntu" and feed.get("ok") and host_release == release:
            advisories: dict[str, dict] = {}
            for notice in feed.get("notices") or []:
                for item in usn.fixed_versions(notice, release):
                    if item["is_source"]:
                        continue        # apt knows binary package names, not source names
                    current = advisories.get(item["package"])
                    if current and vendor_lag.compare(item["version"], current["version"]) <= 0:
                        continue
                    advisories[item["package"]] = {
                        "version": item["version"], "notice": notice.get("id"),
                        "cves": (notice.get("cves_ids") or [])[:4]}
            if advisories:
                code, out = shell.run(vendor_lag.probe_command(sorted(advisories)),
                                      result.get("target"),
                                      timeout=int(_settings.get("timeout") or 180),
                                      path_prefix=shell.SYSTEM_PATH_PREFIX)
                if out.strip():
                    vendor_state = vendor_lag.classify(vendor_lag.parse(out), advisories)
                    vendor_state["advisories_read"] = len(advisories)
                    code, fresh = shell.run(distro_lag.FRESHNESS["apt"], result.get("target"),
                                            timeout=int(_settings.get("timeout") or 180),
                                            path_prefix=shell.SYSTEM_PATH_PREFIX)
                    vendor_state["index_fresh"] = bool((fresh or "").strip())
                    vendor_state["state"] = "measured"
                    if not vendor_state["index_fresh"]:
                        vendor_state["index_note"] = (
                            "the archive index on this host is older than 48 h, so a version that "
                            "fixes this may already be published — refresh it before acting")
                else:
                    blind.append({"host": label, "class": "vendor-lag",
                                  "reason": f"dpkg/apt-cache answered nothing (rc={code})",
                                  "detail": "the vendor-lag state is unmeasured, not empty"})
        elif os_id != "ubuntu":
            # Debian, Alpine, the RHEL family and Arch publish a feed with a fixed version per
            # release; Fedora and openSUSE do not (yet), and say so instead of implying "no lag".
            assessed = distro_lag.assess(
                result.get("target"), str(result.get("family") or ""), str(os_id or ""),
                str(host_release or "unknown"),
                timeout=int(_settings.get("timeout") or 180),
                cache_dir=str(_settings.get("data_dir") or "") or None)
            vendor_state = {"vendor_lag": assessed.get("vendor_lag") or [],
                            "counts": assessed.get("counts") or {},
                            "advisories_read": assessed.get("advisories_read"),
                            "feed": assessed.get("feed"),
                            "state": assessed.get("state"), "reason": assessed.get("reason"),
                            "index_fresh": assessed.get("index_fresh"),
                            "index_note": assessed.get("index_note") or ""}

        if vendor_state and vendor_state.get("vendor_lag"):
            # "fixed upstream, not here yet" is bad; "…and it is being exploited" is the reason to act
            vendor_state["threat"] = threat.annotate_rows(vendor_state["vendor_lag"])

        # Fedora and openSUSE: the feed that proves vendor lag also names the advisory behind a
        # pending update, so those rows stop being anonymous too — the index is already in hand.
        advisory_index = (vendor_state or {}).get("advisory_index") or {}
        if advisory_index and os_id != "ubuntu":
            attached = 0
            for entry in pending:
                if entry.get("advisory"):
                    continue
                hit = advisory_index.get(entry.get("package") or "")
                if not hit or not hit.get("notice"):
                    continue
                entry["advisory"] = hit["notice"]
                entry["advisory_cves"] = hit.get("cves") or []
                attached += 1
            if attached:
                advisory_source = ("Bodhi" if (os_id or "").lower() == "fedora"
                                   else "SUSE's OVAL")
                outcomes["advisories"] = "ok"

        # An exploited CVE outranks everything else: the plan is *ordered* by it, not merely
        # annotated with it, because the first line of a plan is the one an operator runs.
        if pending and any(entry.get("advisory_cves") for entry in pending):
            threat.annotate_rows(pending, field="advisory_cves")
        pending.sort(key=lambda row: (0 if row.get("kev") else 1, -(row.get("epss") or 0)))
        named = [p for p in pending if p.get("advisory")]

        if result.get("pending_unmeasured"):
            blind.append({"host": label, "class": "updates",
                          "reason": str(result.get("pending_unmeasured")),
                          "detail": "the pending list is unmeasured here, not empty"})
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

        # Is the patch in effect? The kernel comparison answers that for the kernel; this answers it
        # for userland — a reboot the packaging system recorded, or a service still mapping a library
        # that has been replaced on disk.
        effect = services.collect(result.get("target"), timeout=int(_settings.get("timeout") or 180))
        if effect.get("reboot_required") or effect.get("services"):
            findings += 1

        # Integrity is a 40-second reading on a full package database, so a scan does not run it: it
        # carries the last reading and its timestamp, and `cve_integrity` takes a fresh one on demand.
        integrity_cached = integrity.read_result(state_data_dir, label)
        if integrity_cached and (integrity_cached.get("state") or {}).get("state") == "finding":
            findings += 1

        # Is this release still receiving fixes at all? An end-of-life host with nothing pending is
        # not a patched host, it is a host nobody will publish a fix for again.
        # the adapter reports a *codename* on Ubuntu; the lifecycle table is keyed by version
        release_for_support = str(host_release or "")
        if not release_for_support[:1].isdigit():
            release_for_support = distro_lag._version_id(result.get("target"),
                                                         int(_settings.get("timeout") or 180))
        support_state = support.state(str(os_id or ""), release_for_support)
        if support_state.get("state") == "end-of-life":
            findings += 1
            if str(os_id or "").lower() == "ubuntu":
                support_state["pro"] = support.pro_status(result.get("target"))
        # And is this host even subscribed to the pocket that carries a fix? Two different causes of
        # "there is an update but I do not get it" used to read the same.
        pockets = repos.collect(result.get("target"), str(result.get("family") or ""),
                                timeout=int(_settings.get("timeout") or 180))

        lag_rows = (vendor_state or {}).get("vendor_lag") or []
        if pending or rebuilt or lag_rows or result.get("kernel") in ("kernel-update-available",
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
            # what the vendor says is fixed but the archive does not offer yet — its own state,
            # because "0 pending" and "no known vulnerability" are different sentences
            "vendor_lag": (vendor_state or {}).get("vendor_lag", [])[:20],
            "vendor_counts": (vendor_state or {}).get("counts"),
            "vendor_advisories_read": (vendor_state or {}).get("advisories_read"),
            "pending_reason": result.get("pending_unmeasured") or "",
            "vendor_state": (vendor_state or {}).get("state") or "not-run",
            "vendor_reason": (vendor_state or {}).get("reason") or "",
            "vendor_index_fresh": (vendor_state or {}).get("index_fresh"),
            "vendor_index_note": (vendor_state or {}).get("index_note") or "",
            "vendor_threat": (vendor_state or {}).get("threat"),
            # whose feed answered, and how old it is: a stale feed is not a vendor delay
            "vendor_feed": (vendor_state or {}).get("feed"),
            "services": effect,
            "integrity": (integrity_cached or {}).get("state"),
            "integrity_at": (integrity_cached or {}).get("at"),
            "integrity_answer": integrity_cached
            and integrity.summarise((integrity_cached or {}).get("state") or {}) or "",
            "support": support_state,
            "pockets": pockets,
            # the commands that would fix this host, and where they belong — the pane must never
            # offer a list of packages as if a package named "1.2.3" were something you can paste
            "commands": _commands_for(result.get("family")),
            "where": _where_for(result.get("target"), label),
        }
        host_payload["summary"] = _summarise(host_payload)
        hosts_payload[label] = host_payload

    exit_code = 2 if blind else (1 if findings else 0)
    answer = " | ".join(h["summary"] for h in hosts_payload.values())
    # one line the model will actually relay: exploited beats severe
    exploited = sorted({cve for h in hosts_payload.values()
                        for cve in ((h.get("vendor_threat") or {}).get("exploited") or [])})
    if exploited:
        answer += (f" | EXPLOITED IN THE WILD (CISA KEV): {len(exploited)} — "
                   + ", ".join(exploited[:4]))
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
        "threat": {"exploited": exploited,
                   "kev_state": ("measured" if any((h.get("vendor_threat") or {}).get("kev_state")
                                                   == "measured" for h in hosts_payload.values())
                                 else "unmeasured")},
        "exit_code": exit_code,
        "limits": {"pending_listed_at_most": MAX_PENDING,
                   "in_image_cves": "not measured (needs an image scanner)",
                   "language_dependencies": "not measured (needs an SBOM + dependency scanner)"},
    }
    if save and selected:
        try:
            store.save_scan({k: payload[k] for k in
                             ("tool", "scan", "answer", "hosts", "blind", "findings", "exit_code",
                              "threat")})
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
def cve_image(args: dict, **kwargs) -> str:
    """Read one container image's package database and check it against OSV.

    The image is unpacked with ``docker save`` — never started. An image the reader cannot understand
    (an rpm-based one, a foreign layout, a size past the cap) says so and exits 2, because "0 findings"
    on an image nobody read is the false comfort this plugin exists to remove.
    """
    image = str(args.get("image") or args.get("name") or "").strip()
    if not image:
        return _json({"tool": "cve_image", **_refusal("no image given — name one, e.g. 'nginx:1.27'")})
    host_label = str(args.get("host") or "").strip() or _local_label()
    entry = next((h for h in _inventory() if h["label"] == host_label), None)
    if entry is None:
        return _json({"tool": "cve_image", "host": host_label,
                      **_refusal(f"there is no host called {host_label!r} in this inventory")})
    target = entry.get("target") or None

    timeout = int(_settings.get("timeout") or 180)
    saved = image_db.save_and_read([image], target, timeout=max(timeout, 300))
    state = image_db.report(saved["images"].get(image) or {})
    base = {"tool": "cve_image", "host": host_label, "image": image,
            "os": state.get("os_label"), "features_read": len(state.get("packages") or []),
            "layers": state.get("layers"), "ecosystem": state.get("ecosystem"),
            "summary": state.get("summary")}
    if not state.get("packages"):
        why = str(state.get("outcome") or "")
        # the common case on a fresh machine is not "unreadable image" but "no container runtime at
        # all" — saying that plainly beats a sentence about rpm databases and osv-scanner
        if "not found" in why or "rc=127" in why:
            return _json({**base, "exit_code": 2,
                          "reason": "no container runtime on this host — docker (or podman) is not "
                                    "installed, so an image cannot be unpacked. The image surface is "
                                    "unmeasured here, not clean.",
                          "detail": why[:200]})
        # The reader could not understand this image (an rpm database, a foreign layout). If the
        # operator installed osv-scanner, use it; if not, say the image is unmeasured and why.
        fallback = image_db.osv_scanner_fallback(image, target, timeout=300)
        if fallback.get("outcome") == "ok":
            findings = fallback["findings"]
            threat_summary = threat.annotate(findings)
            answer_line = (f"{image} on {host_label}: {len(findings)} advisory match(es), read by "
                           f"osv-scanner ({state.get('os_label')}) — this plugin's own reader could "
                           f"not open the image ({state.get('outcome')})")
            return _json({**base, "answer": answer_line, "engine": "osv-scanner",
                          "vulnerable": findings[:MAX_PENDING], "vulnerable_count": len(findings),
                          "threat": threat_summary, "exit_code": 1 if findings else 0})
        return _json({**base, "outcome": state.get("outcome"), "fallback": fallback, "exit_code": 2,
                      **_refusal((state.get("outcome") or "nothing was read from the image")
                                 + f" — and {fallback.get('why')}")})
    if not state.get("ecosystem"):
        return _json({**base, "outcome": "unsupported",
                      "reason": (f"the image runs {state.get('os_label')}, and this plugin has no "
                                 f"advisory feed for that distribution — the package list is read, "
                                 f"the CVEs are unmeasured"),
                      "exit_code": 2})

    components = [{"package": row["package"], "version": row["version"],
                   "ecosystem": state["ecosystem"], "source": f"image:{image}"}
                  for row in state["packages"]]
    answer = osv.query(components[:800])
    if not answer.get("ok"):
        return _json({**base, "outcome": "unmeasured", "exit_code": 2,
                      **_refusal(f"the advisory database could not be queried ({answer.get('why')})")})

    pairs = list(zip(components, answer["results"]))
    wanted = sorted({vid for _, found in pairs for vid in found})
    records = {vid: osv.vuln(vid) for vid in wanted[:MAX_ADVISORY_RECORDS]}
    vulnerable, seen = [], set()
    for component, found in pairs:
        for vid in found:
            record = records.get(vid)
            item = (osv.summarise(record, component["ecosystem"], component["package"])
                    if record else {"id": vid, "aliases": [], "summary": None, "severity": None,
                                    "fixed": [], "url": f"https://osv.dev/vulnerability/{vid}"})
            key = (component["package"], component["version"], item.get("id"))
            if key in seen:
                continue
            seen.add(key)
            vulnerable.append({"package": component["package"], "version": component["version"],
                               "source": component["source"], **item})
    threat_summary = threat.annotate(vulnerable)
    exploited = sum(1 for row in vulnerable if row.get("kev"))
    answer_line = (f"{image} on {host_label}: {len(vulnerable)} advisory match(es) across "
                   f"{len({(v['package'], v['version']) for v in vulnerable})} package(s), from "
                   f"{len(components)} package(s) read out of the image ({state.get('os_label')})")
    if exploited:
        answer_line += f" — {exploited} in CISA's known-exploited list"
    return _json({**base, "answer": answer_line, "vulnerable": vulnerable[:MAX_PENDING],
                  "vulnerable_count": len(vulnerable), "threat": threat_summary,
                  "exit_code": 1 if vulnerable else 0})


def cve_sbom(args: dict, **kwargs) -> str:
    """Export what this scan holds as a CycloneDX 1.5 document, and say what it does not hold."""
    host_label = str(args.get("host") or "").strip() or _local_label()
    entry = next((h for h in _inventory() if h["label"] == host_label), None)
    if entry is None:
        return _json({"tool": "cve_sbom", "host": host_label,
                      **_refusal(f"there is no host called {host_label!r} in this inventory")})
    timeout = int(_settings.get("timeout") or 180)
    target = entry.get("target") or None
    collected = languages.collect(host_label if False else target)
    components = list(collected.get("components") or [])
    for extra in (environments.collect(target, timeout=timeout),
                  jars.collect(target, timeout=timeout)):
        components.extend(extra.get("components") or [])
    stored = store.load_scan() or {}
    host_entry = ((stored.get("hosts") or {}).get(host_label)) or {}
    document = sbom.build(components, host_label,
                          os_label=" ".join(filter(None, [(host_entry.get("os") or {}).get("id"),
                                                          (host_entry.get("os") or {}).get("version_id")])) or None,
                          pending=host_entry.get("pending") or [],
                          extra_properties={"release_support": (host_entry.get("support") or {}).get("state")})
    directory = Path(store.data_dir())
    directory.mkdir(parents=True, exist_ok=True)
    stamp = _now().replace(":", "").replace("-", "")
    path = directory / f"sbom-{host_label}-{stamp}.json"
    path.write_text(json.dumps(document, indent=2))
    return _json({"tool": "cve_sbom", "host": host_label, "path": str(path),
                  "format": "CycloneDX 1.5", "components": len(document["components"]),
                  "complete": False,
                  "not_included": ["the full installed OS package set (this plugin reads the update "
                                   "list, not the whole package database)",
                                   "node_modules and vendor/ directories"],
                  "exit_code": 0})


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

    # The gate is a string comparison; it is checked before the measurement, not after. Typing the
    # wrong name used to cost a full scan of the inventory before being refused — measured, the pane
    # sat for over 20 s on a refusal that could not have run anything.
    if confirm.strip() != str(host["label"]).strip():
        return _json({"tool": "cve_apply", "applied": False, "dry_run": dry_run, "exit_code": 2,
                      "host": host["label"], "steps": [],
                      "reason": f"the gate is armed by typing {host['label']!r} exactly — got "
                                f"{confirm.strip()!r}. Nothing was run, and nothing was measured."})

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
        {"gap": "dependencies pinned in manifests with no lockfile",
         "state": "partly measured", "hosts": "every", "kind": "limit",
         "why": "a project is covered when it has a lockfile: package-lock.json, yarn.lock, "
                "pnpm-lock.yaml, requirements.txt, constraints.txt, poetry.lock, Pipfile.lock, "
                "go.sum, Cargo.lock, composer.lock, Gemfile.lock or pubspec.lock are all parsed "
                "(pass a directory to cve_libraries, or use the field in the pane). What is left "
                "out is the project with only a manifest — composer.json, Cargo.toml, go.mod, "
                "*.csproj, setup.py — where the version is a range rather than a pin. Installed "
                "Python environments are not the hole: every virtualenv on the machine is read by "
                "package name and version from its dist-info directories.",
         "consequence": "a project without a lockfile can carry a vulnerable dependency that no "
                        "scan here names; a lockfile makes the same project fully covered",
         "next": "commit the lockfile — that is the fix, and this plugin reads it the moment it "
                 "exists. Guessing from a range would be a claim, not a measurement."},
        {"gap": "vendor lag on a release the vendor has stopped updating", "state": "partly measured",
         "hosts": "suse (ancient releases), and any distro past its end of life", "kind": "limit",
         "why": "vendor lag is measured on all six families this plugin ships: Ubuntu (USN), Debian, "
                "Alpine and the RHEL family (OSV per release), Arch (its AVG tracker), Fedora "
                "(Bodhi's stable security updates) and openSUSE/SUSE (their OVAL document). What no "
                "feed can answer is a release its vendor has stopped publishing for: openSUSE 15.6's "
                "OVAL last moved in June 2026, so the comparison runs against a snapshot. The feed's "
                "own date is quoted on the host row and a feed older than 30 days is flagged.",
         "consequence": "on an out-of-support release the lag list is as current as the vendor's last "
                        "publication — which is a fact about the release, not about this scan",
         "next": "upgrade off an end-of-life release; that is the only thing that produces new "
                 "advisories for it."},
        {"gap": "container images are not scanned by a host scan", "state": "partly measured",
         "hosts": "every", "kind": "limit",
         "why": "a host scan compares image digests against the registry (a rebuilt upstream image is "
                "reported), but unpacking every image on every scan would cost minutes and gigabytes. "
                "`cve_image` reads one image on demand — `docker save`, then the layer's dpkg or apk "
                "database, checked against OSV — and names its distro. Images built on rpm (Fedora, "
                "RHEL) answer 'unmeasured': their package database is sqlite, which this plugin does "
                "not parse.",
         "consequence": "an image built on a vulnerable base is only caught when someone asks about "
                        "that image, not by the periodic scan",
         "next": "ask per image (`cve_image`, 'is our nginx:1.27 patched?'); an rpmdb reader is the "
                 "remaining piece."},
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
    "measured": ("npm's global tree, the first pip on PATH, composer's global vendor, local gems, "
                 "cargo's installed binaries, dotnet's global tools, Maven's local repository and "
                 "the modules behind Go's installed binaries — plus every virtualenv on the "
                 "machine (project .venv/venv, pipx and poetry environments), read from its "
                 "dist-info names without executing anything"),
    "missing_toolchains": ("a toolchain that is not installed here is reported as 'missing', never "
                           "as zero findings"),
    "not_measured": [
        "project manifests with no lockfile (package.json, composer.json, Cargo.toml, go.mod)",
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

    # Project mode: the lockfiles of a repository, read on this machine. A machine-wide scan cannot
    # see what a project pins, and a project is exactly what ships.
    project_arg = str(args.get("project") or args.get("path") or "").strip()
    project = None
    if project_arg:
        if host.get("target") not in (None, "", "local"):
            return _json({"tool": "cve_libraries", "scope": "project",
                          "reason": f"a project path is read on the machine this plugin runs on — "
                                    f"{host['label']!r} is remote, so its files are not reachable "
                                    f"from here. Point the path at a local checkout, or run the "
                                    f"project scan on that host.",
                          "exit_code": 2})
        if not os.path.isdir(project_arg):
            # a wrong path used to fall through to "no package manager answered on this host", which
            # sent the operator looking at their toolchains instead of at the path they typed
            return _json({"tool": "cve_libraries", "scope": "project", "exit_code": 2,
                          "reason": f"there is no directory at {project_arg!r} on this machine — a "
                                    f"project scan reads the lockfiles of a checkout, so the path has "
                                    f"to exist here (and be readable by this account)"})
        project = projects.read(project_arg)
        if not project.get("components"):
            # files were found but pinned nothing exact — say which files, and that a range is not a
            # version, rather than reporting "nothing measured"
            files = project.get("files") or {}
            if files:
                return _json({"tool": "cve_libraries", "scope": "project",
                              "project": {"root": project.get("root"), "files": files},
                              "packages": [], "vulnerable": [], "vulnerable_count": 0,
                              "answer": "this project pins no exact versions — a range such as "
                                        "`>=2.0` cannot be compared with a published advisory, so "
                                        "nothing here is claimed clean",
                              "limit": "lockfile ranges are unverifiable by construction",
                              "exit_code": 2})
            return _json({"tool": "cve_libraries", "scope": "project", "exit_code": 2,
                          "reason": f"no supported lockfile was found under {project_arg!r} — looked "
                                    f"for package-lock.json, yarn.lock, pnpm-lock.yaml, "
                                    f"requirements.txt, constraints.txt, poetry.lock, Pipfile.lock, "
                                    f"go.sum, Cargo.lock, composer.lock, Gemfile.lock, pubspec.lock"})
        collected = {"components": project["components"], "outcomes": {}, "details": {},
                     "by_ecosystem": {}, "installers": {}, "truncated": project["truncated"],
                     "measured_at": _now()}
    else:
        collected = languages.collect(host["target"])
        # …and every project environment the machine can name. A developer's ten virtualenvs are the
        # largest surface a global-tree reader cannot see, and they cost one `find`.
        environments_state = environments.collect(host.get("target") or None,
                                                  timeout=int(_settings.get("timeout") or 180))
        # jars on disk: the Java deployments that never pass through the local Maven repository
        jars_state = jars.collect(host.get("target") or None,
                                  timeout=int(_settings.get("timeout") or 180))
        # dedupe including the owner: the same name@version in Hermes's own environment and in a
        # project venv is two facts, not a duplicate. Dropping the project copy is how "235 packages"
        # became 171 in the pane while the environment reader had found every one of them.
        known = {(c["ecosystem"], c["package"], c["version"], c.get("owner") or "machine")
                 for c in collected["components"]}
        extra = [c for c in environments_state["components"] + jars_state["components"]
                 if (c["ecosystem"], c["package"], c["version"], c.get("owner") or "machine")
                 not in known]
        collected = {**collected,
                     "components": collected["components"] + extra,
                     "outcomes": {**collected.get("outcomes", {}),
                                  **environments_state["outcomes"], **jars_state["outcomes"]},
                     "truncated": (collected.get("truncated") or environments_state["truncated"]
                                   or jars_state["truncated"])}
    components = collected["components"]
    base = {"tool": "cve_libraries", "host": host["label"], "target": host["target"] or "local",
            "scope": "project" if project else "machine",
            "project": ({"root": project["root"], "files": project["files"]} if project else None),
            "measured_at": collected["measured_at"], "outcomes": collected["outcomes"],
            "details": collected["details"], "by_ecosystem": collected["by_ecosystem"],
            "components": len(components), "truncated": collected["truncated"],
            # how each store is upgraded on this host, with the absolute path of the binary the scan
            # used: an advisory the user cannot act on is half an answer
            "installers": collected.get("installers") or {},
            # the installed list itself, so a pane can show what was checked instead of a count
            "packages": [{"ecosystem": c.get("ecosystem"), "package": c.get("package"),
                          "version": c.get("version"), "source": c.get("source"),
                          "owner": c.get("owner") or "machine",
                          # the component's own manager first: a package read out of a project
                          # virtualenv knows its venv's pip, which no ecosystem-level table can name
                          "manager": c.get("manager") or collected.get("installers", {})
                          .get(c.get("ecosystem"), {}).get(c.get("source"))}
                         for c in components[:MAX_PENDING]],
            # How many of those packages belong to the agent's own environment. They are real
            # advisories, but they are not the user's to upgrade one by one: the agent ships them.
            "hermes_env": {
                "packages": sum(1 for c in components if c.get("owner") == "hermes"),
                "note": "read from the interpreter Hermes runs on — upgraded with `hermes update`, "
                        "not package by package"}}

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

    # `0.0.0` is what an editable or in-tree install reports. Comparing it against advisory ranges
    # produced 20 CVEs on `hermes-agent 0.0.0` — the package itself, at a version that does not
    # exist. Named as skipped; a version nobody published cannot be said to be vulnerable.
    unversioned = [c for c in components if str(c.get("version")) in ("0.0.0", "0.0.0.0")]
    pairs = [(c, r) for c, r in zip(components, answer["results"])
             if str(c.get("version")) not in ("0.0.0", "0.0.0.0")]
    wanted = sorted({vid for _, found in pairs for vid in found})
    records = {vid: osv.vuln(vid) for vid in wanted[:MAX_ADVISORY_RECORDS]}

    # The same package@version can sit in several project environments. A finding belongs to the
    # package, not to the copy: one row, with every environment that carries it.
    vulnerable: list[dict] = []
    seen_findings: dict[tuple, dict] = {}
    for component, found in pairs:
        for vid in found:
            record = records.get(vid)
            if record:
                item = osv.summarise(record, component["ecosystem"], component["package"])
            else:
                item = {"id": vid, "aliases": [], "summary": None, "severity": None,
                        "fixed": [], "url": f"https://osv.dev/vulnerability/{vid}"}
            key = (component["ecosystem"], component["package"], component["version"],
                   item.get("id"))
            source = component.get("source") or ""
            known_row = seen_findings.get(key)
            if known_row is not None:
                if source and source not in known_row["sources"]:
                    known_row["sources"].append(source)
                continue
            row = {"ecosystem": component["ecosystem"],
                   "package": component["package"],
                   "version": component["version"],
                   # whose package it is travels with the finding, so a count can be
                   # split by who can act on it
                   "owner": component.get("owner") or "machine",
                   "source": source,
                   "sources": [source] if source else [],
                   **item}
            seen_findings[key] = row
            vulnerable.append(row)

    # An acknowledgement is a record, not a filter: the row leaves the count, keeps its reason and its
    # end date, and comes back by itself. A new advisory against the same version is never covered.
    state_dir = str(_settings.get("data_dir") or store.data_dir())
    vulnerable, acked = acks.split(state_dir, host["label"], vulnerable)

    # Is any of this being exploited right now? KEV and EPSS are the two public feeds that answer it,
    # and they are what turns a list of CVEs into a decision.
    threat_summary = threat.annotate(vulnerable)

    unreadable = [eco for eco, state in collected["outcomes"].items() if state == "unreadable"]
    exit_code = 2 if unreadable else (1 if vulnerable else 0)
    where = (f"pinned in {project['root']}" if project
             else "across the machine's installed language packages")
    # Packages that ship inside Hermes's own environment are measured, but they are not the
    # operator's to upgrade: the only lever is `hermes update`. Counting them with everything else
    # is what made "128 packages, 40 advisories" read as a broken alert list after an update.
    agent = [v for v in vulnerable if v.get("owner") == "hermes"]
    # packages the distribution owns are patched by the distribution: counting their PyPI advisories
    # as the operator's findings is how a fresh Debian showed 118 of them, none actionable
    distro = [v for v in vulnerable if v.get("owner") == "distro"]
    mine = [v for v in vulnerable if v.get("owner") not in ("hermes", "distro")]
    # the population is the operator's packages, the same set the pane counts in its header —
    # "2 findings from 302 packages" next to "174 packages" was two different denominators
    readable = [c for c in components if c.get("owner") != "hermes"]
    answer_line = (f"{host['label']}: {len(mine)} advisory match(es) across "
                   f"{len({(v['ecosystem'], v['package'], v['version']) for v in mine})} package(s), "
                   f"from {len(readable)} package(s) of yours {where}"
                   if components else f"{host['label']}: nothing measurable")
    if agent:
        answer_line += (f" · {len(agent)} more on {len({v['package'] for v in agent})} package(s) "
                        f"that ship with Hermes itself (lever: `hermes update`)")
    if distro:
        answer_line += (f" · {len(distro)} more on {len({v['package'] for v in distro})} package(s) "
                        f"installed by the distribution — they are fixed by the distro, not by pip")
    if acked:
        answer_line += (f" · {len(acked)} acknowledged with a reason "
                        f"({', '.join(sorted({a['package'] for a in acked})[:3])})")
    if unversioned:
        answer_line += (f" · {len(unversioned)} package(s) at version 0.0.0 were not compared "
                        f"(an in-tree install has no published version to match): "
                        f"{', '.join(sorted(c['package'] for c in unversioned)[:4])}")
    # An exploited CVE outranks a critical one that nobody is using. Say it in the answer, not only in
    # a field a pane might forget to render.
    if threat_summary["kev_count"]:
        answer_line += (f" — {threat_summary['kev_count']} of them are in CISA's known-exploited "
                        f"list: {', '.join(threat_summary['exploited'][:3])}")
    return _json({**base, "answer": answer_line, "vulnerable": vulnerable[:MAX_PENDING],
                  "vulnerable_count": len(vulnerable),
                  "threat": threat_summary,
                  "acknowledged": acked[:MAX_PENDING],
                  "acknowledged_count": len(acked),
                  # an in-tree 0.0.0 install cannot be compared with a published version; the pane
                  # says so on its own line instead of inside a sentence
                  "unversioned": [{"package": c.get("package"), "source": c.get("source")}
                                  for c in unversioned][:20],
                  "distro_managed": {"advisories": len(distro),
                                     "packages": len({v["package"] for v in distro}),
                                     "names": sorted({v["package"] for v in distro})[:8]},
                  "advisories_examined": len(records),
                  "advisories_truncated": len(wanted) > MAX_ADVISORY_RECORDS,
                  "exit_code": exit_code,
                  "limits": LIBRARY_LIMITS})


def cve_integrity(args: dict, **kwargs) -> str:
    """Is what is installed still what was installed? Checksums, the preload hook, the sockets.

    Deliberately not part of ``cve_scan``: verifying a full package database takes tens of seconds, and
    a scan has to stay interactive. The scan carries the last reading and its timestamp; this takes a
    fresh one. It answers clean / finding / could-not-look, and never "not compromised".
    """
    requested = str(args.get("host") or "").strip() or _local_label()
    host = next((h for h in _inventory() if h["label"].lower() == requested.lower()), None)
    if host is None:
        return _json({"tool": "cve_integrity", **_not_in_inventory(requested)})
    data_dir = str(_settings.get("data_dir") or store.data_dir())
    action = str(args.get("action") or "").strip().lower()

    # A reading the operator ran as root, pasted back. The plugin cannot elevate, so this is the only
    # way the files it could not read get covered — and the paste is labelled as theirs, not ours.
    if action in ("import", "paste"):
        saved = integrity.read_result(data_dir, host["label"])
        if not saved:
            return _json({"tool": "cve_integrity", "exit_code": 2,
                          "reason": "there is no reading to attach this to — take an integrity reading "
                                    "first, then paste the root run of the command it names"})
        state = saved["state"]
        merged = integrity.merge_pasted(state, str(args.get("output") or ""),
                                        data_dir=data_dir, host=host["label"])
        if not merged.get("ok"):
            return _json({"tool": "cve_integrity", "exit_code": 2, "reason": merged.get("reason")})
        integrity.save_result(data_dir, host["label"], state)
        return _json({"tool": "cve_integrity",
                      "host": {"label": host["label"], "target": host.get("target") or "local"},
                      "integrity": state, "answers": integrity.answers(state),
                      "answer": merged.get("answer"), "read_at": time.time(), "exit_code": 0})

    def keep(current: dict) -> tuple[bool, str]:
        """Store the reading; a read-only data directory costs the *storage*, not the measurement."""
        try:
            integrity.save_result(data_dir, host["label"], current)
            return True, ""
        except integrity.CannotStore as exc:
            return False, str(exc)

    state = integrity.collect(host.get("target"), data_dir, host["label"],
                              timeout=int(_settings.get("timeout") or 180))
    if (action in ("baseline", "rebase")
            and (state.get("listeners") or {}).get("set") is not None):
        # re-baselining is an explicit act: it accepts today's sockets as the known set, and the
        # previous set is not lost — it is replaced, so the pane says the baseline was renewed now
        try:
            record = integrity.write_baseline(data_dir, host["label"],
                                             state["listeners"].get("records")
                                             or state["listeners"]["set"])
        except integrity.CannotStore as exc:
            return _json({"tool": "cve_integrity", "exit_code": 2,
                          "reason": f"a baseline was requested but cannot be stored: {exc} — "
                                    f"nothing was re-baselined, so the sockets are still compared "
                                    f"with the old set"})
        state["listeners"].update(state="baseline", new=[], baseline_at=record.get("at"),
                                  baseline_count=record.get("count"),
                                  reason=f"baseline renewed now with {record.get('count')} socket(s)")
    kept, why = keep(state)
    return _json({"tool": "cve_integrity",
                  "host": {"label": host["label"], "target": host.get("target") or "local"},
                  "integrity": state,
                  "answers": integrity.answers(state),
                  "kept": kept,
                  "answer": integrity.summarise(state) + ("" if kept else
                             f" · this reading could not be kept: {why}"),
                  "read_at": time.time(),
                  "exit_code": 0 if state.get("state") in ("ok", "baseline") else (1 if state.get("state") == "finding" else 2)})


def cve_ack(args: dict, **kwargs) -> str:
    """Record "I know, and I accept it" against one advisory, with a reason and an end date."""
    action = str(args.get("action") or "ack").strip().lower()
    host = str(args.get("host") or _local_label()).strip()
    package = str(args.get("package") or "").strip()
    advisory = str(args.get("advisory") or args.get("id") or "").strip()
    if not package or not advisory:
        return _json({"tool": "cve_ack", "exit_code": 2,
                      "reason": "an acknowledgement needs `package` and `advisory` — it names one "
                                "advisory, never a whole package"})
    state_dir = str(_settings.get("data_dir") or store.data_dir())
    common = dict(host=host, ecosystem=str(args.get("ecosystem") or ""), package=package,
                  version=str(args.get("version") or ""), advisory=advisory)
    if action in ("release", "reopen", "undo"):
        result = acks.release(state_dir, **common)
    else:
        result = acks.acknowledge(state_dir, reason=str(args.get("reason") or ""),
                                  days=int(args.get("days") or acks.DEFAULT_DAYS), **common)
    return _json({"tool": "cve_ack", **result, "exit_code": 0 if result.get("ok") else 2})


def _plans_for_every_host() -> tuple[dict, int]:
    """One plan per host in the inventory — the commands half of "rescan all"."""
    plans, worst = {}, 0
    for host in _inventory():
        try:
            payload = json.loads(cve_plan({"host": host["label"]}))
        except Exception as exc:                      # noqa: BLE001 - a stage that dies is reported
            payload = {"tool": "cve_plan", "exit_code": 2,
                       "answer": f"the plan for {host['label']} could not be built: {exc}"}
        plans[host["label"]] = payload
        worst = max(worst, int(payload.get("exit_code") or 0))
    return plans, worst


def cve_rescan(args: dict, **kwargs) -> str:
    """One control instead of four: walk every surface in the order the pane shows them.

    The bundle is written after each stage, so the pane renders what has landed while the integrity
    reading (the slow one) is still running. Nothing is decided here: each stage calls the same handler
    the single-purpose tool calls, and its payload is stored verbatim.
    """
    data_dir = str(_settings.get("data_dir") or store.data_dir())
    bundle = rescan.start(data_dir)
    handlers = {"scan": cve_scan, "libraries": cve_libraries, "integrity": cve_integrity}
    worst = 0
    for stage in rescan.STAGES:
        started = time.time()
        if stage == "plans":
            payload = {"tool": "cve_plan", "plans": None}
            payload["plans"], code = _plans_for_every_host()
            payload["exit_code"] = code
        else:
            try:
                payload = json.loads(handlers[stage]({}))
            except Exception as exc:                  # noqa: BLE001 - one stage cannot end the run
                payload = {"tool": f"cve_{stage}", "exit_code": 2,
                           "answer": f"this stage could not finish: {exc}"}
        code = int(payload.get("exit_code") or 0)
        worst = max(worst, code)
        bundle[stage] = payload
        bundle["stage"] = stage
        bundle["stages"].append({"name": stage, "exit_code": code,
                                 "seconds": round(time.time() - started, 1),
                                 "at": time.time()})
        rescan.write(data_dir, bundle)
    bundle["stage"] = "done"
    bundle["finished_at"] = time.time()
    rescan.write(data_dir, bundle)

    # The answer is the verdict, not a stopwatch. It carries the three counts the sections above are
    # built from, so a caller that only reads `answer` still gets the state of the fleet.
    scan = bundle.get("scan") or {}
    hosts = scan.get("hosts") or {}
    pending = sum(int((entry or {}).get("pending_count") or 0) for entry in hosts.values())
    libraries = bundle.get("libraries") or {}
    findings = len([row for row in (libraries.get("vulnerable") or []) if row.get("owner") != "hermes"])
    plans = ((bundle.get("plans") or {}).get("plans") or {})
    commands = sum(len((plan or {}).get("steps") or []) for plan in plans.values())
    timings = " · ".join(
        f"{ {'scan': 'packages', 'libraries': 'language stack', 'integrity': 'integrity',
             'plans': 'commands'}[stage['name']] } {round(stage['seconds'])}s"
        + (" (could not look)" if stage["exit_code"] == 2 else "")
        for stage in bundle["stages"])
    return _json({"tool": "cve_rescan", "exit_code": worst, "bundle": bundle,
                  "pending": pending, "library_findings": findings, "commands": commands,
                  "hosts": len(hosts),
                  "answer": (f"{len(hosts)} device(s) · {pending} package update(s) pending · "
                             f"{findings} library finding(s) · {commands} command(s) to run — "
                             "measured once, in order: " + timings),
                  "seconds": round(time.time() - bundle["started_at"], 1)})


HANDLERS = {
    "cve_scan": cve_scan,
    "cve_plan": cve_plan,
    "cve_explain": cve_explain,
    "cve_coverage": cve_coverage,
    "cve_libraries": cve_libraries,
    "cve_apply": cve_apply,
    "cve_image": cve_image,
    "cve_sbom": cve_sbom,
    "cve_ack": cve_ack,
    "cve_integrity": cve_integrity,
    "cve_rescan": cve_rescan,
}

__all__ = ["HANDLERS", "SCHEMAS", "configure", "cve_scan", "cve_plan", "cve_explain",
           "cve_coverage", "cve_libraries", "cve_image", "cve_sbom", "cve_apply"]

SCHEMAS = schemas.SCHEMAS
