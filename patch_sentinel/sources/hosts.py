"""Host inventory: which labels we scan, and what each one is reached through.

Config-driven, and honest about the default: with nothing configured the inventory is this
machine, because that is the only host the plugin can prove anything about. A remote host is
``label=ssh-target`` and is reached with the operator's own agent key — the plugin never holds
a credential for it.

Format (config ``hosts`` or ``PATCH_SENTINEL_HOSTS``):
    ``this-box=local,vps=webasix``      → two hosts; ``local`` means "the machine we run on"
An empty target means local too, so ``beelink=`` works.
"""
from __future__ import annotations

import re
import socket


def parse_inventory(text: str | list | None) -> list[dict]:
    """``"a=local,b=vps"`` → ``[{"label":"a","target":None}, {"label":"b","target":"vps"}]``."""
    if isinstance(text, (list, tuple)):
        items = [str(x) for x in text]
    else:
        items = [chunk for chunk in str(text or "").replace(";", ",").split(",")]
    hosts = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        label, _, target = item.partition("=")
        label = (label or item).strip() or item
        target = target.strip()
        if target.lower() in ("", "local", "localhost", "this", "this-box", "self"):
            target = None
        hosts.append({"label": label, "target": target})
    return hosts


LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
# An ssh target ends up in an ssh argv. Only what can legitimately appear there is accepted, so a
# crafted target cannot become a second command.
TARGET_RE = re.compile(r"^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9._\[\]:-]{1,120}$")


def validate(label: str, target: str) -> tuple[bool, str]:
    """Is this host entry safe and unambiguous? Returns (ok, reason)."""
    label = (label or "").strip()
    target = (target or "").strip()
    if not LABEL_RE.match(label):
        return False, ("a label is 1–32 characters: letters, digits, dot, dash or underscore, "
                       "starting with a letter or digit")
    if is_local(target):
        return True, ""
    if " " in target or "=" in target or "," in target:
        return False, "a target cannot contain spaces, '=' or ','"
    if not TARGET_RE.match(target):
        return False, ("a target is user@host, host, or user@host:port — nothing else fits in "
                       "an ssh command line")
    return True, ""


LOCAL_TARGETS = ("", "local", "localhost", "self", "this-box")


def is_local(target) -> bool:
    """Is this entry the machine the plugin runs on? ``local`` arrives as a string from the
    inventory and as ``None`` from a config that never set a target — both mean the same thing."""
    return target is None or str(target).strip().lower() in LOCAL_TARGETS


def serialize(entries: list[dict]) -> str:
    """``[{"label": "a", "target": None}, {"label": "b", "target": "vps"}]`` → ``a=local,b=vps``."""
    parts = []
    for entry in entries or []:
        label = (entry.get("label") or "").strip()
        if not label:
            continue
        parts.append(f"{label}={entry.get('target') or 'local'}")
    return ",".join(parts)


def local_label() -> str:
    """The machine's own name, so a payload never says "host 1"."""
    try:
        return socket.gethostname().split(".")[0] or "local"
    except Exception:                                    # noqa: BLE001 - never fail a scan on this
        return "local"


def inventory(configured: str | list | None = None, env_value: str | None = None) -> list[dict]:
    """The configured inventory, or this machine when nothing is configured."""
    hosts = parse_inventory(configured) or parse_inventory(env_value)
    if not hosts:
        hosts = [{"label": local_label(), "target": None}]
    if not any(h["target"] is None for h in hosts):
        # The machine we run on is always included: a scan that cannot answer for itself is
        # not a patch posture, it is a fleet tool with no fleet.
        hosts.insert(0, {"label": local_label(), "target": None})
    seen, unique = set(), []
    for host in hosts:
        if host["label"] not in seen:
            seen.add(host["label"])
            unique.append(host)
    return unique
