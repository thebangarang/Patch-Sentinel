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
