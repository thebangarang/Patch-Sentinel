"""Patch Sentinel — plugin entry point.

``register()`` is the only thing Hermes calls: it imports the tool module *inside* the function
(``hermes plugins doctor --ci`` blocks sockets during registration, and a module-level import is
also what breaks when this directory is loaded bare by tooling), hands the tool layer the resolved
config, and registers exactly the four tools declared in ``plugin.yaml``.

Nothing here touches the network or the system. The first measurement happens when the model
calls ``cve_scan``, and not a moment before.

One hook is registered: ``pre_tool_call`` escalates every real ``cve_apply`` to Hermes' own human
approval gate. The typed host label inside the tool is a second guard, not the first — a model can
fill in both the label and ``dry_run=false`` on its own, and nothing else stops that in cron.
"""
from __future__ import annotations

# Our own defaults, mirrored in plugin.yaml: the manifest is what a user sees, this is what runs
# if a value is missing.
DEFAULTS = {
    "hosts": "",
    "release": "resolute",
    "usn_limit": 20,
    "data_dir": "",
    "timeout": 180,
}


def _is_real_apply(value) -> bool:
    """``dry_run`` omitted or true means nothing runs. Anything that reads as false is a real apply.

    The schema types it as a boolean, but a model may send ``"false"`` or ``0``; treating those as
    "not false" would let the one dangerous call through the gate that exists for it.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value is False
    if isinstance(value, (int, float)):
        return value == 0
    return str(value).strip().lower() in {"false", "0", "no", "off"}


def pre_tool_call(tool_name: str = "", args=None, **_) -> dict | None:
    """Escalate a real ``cve_apply`` to Hermes' approval prompt. Never raises, never blocks.

    Hermes treats ``{"action": "approve"}`` as "ask the human": it renders the message and fails
    closed where nobody can answer (cron, the messaging gateway). ``rule_key`` is the grain of the
    "[a]lways" answer, so allowing one host does not silently allow every host.
    """
    try:
        if tool_name != "cve_apply":
            return None
        params = args if isinstance(args, dict) else {}
        if not _is_real_apply(params.get("dry_run")):
            return None
        host = str(params.get("host") or "").strip() or "this machine"
        return {
            "action": "approve",
            "message": (f"cve_apply will run a full system upgrade with sudo on {host} "
                        f"(package manager upgrade, then a re-measure). Nothing has run yet."),
            "rule_key": f"patch-sentinel:cve_apply:{host}",
        }
    except Exception:                       # noqa: BLE001 - a raising hook is a broken agent
        return None


def register(ctx) -> None:
    """Register the four tools. Called by the plugin loader with a real ``PluginContext``."""
    from .patch_sentinel import schemas, store, tools

    settings = {key: ctx.get_config(key, default) for key, default in DEFAULTS.items()}
    # A host list edited in the pane wins over config.yaml: the pane writes settings.json and marks
    # it, and a config value that predates that edit must not quietly undo it on the next restart.
    saved = {}
    try:
        saved = store.load_settings() or {}
    except OSError:
        saved = {}
    if saved.get("hosts_source") == "pane" and saved.get("hosts"):
        settings["hosts"] = saved["hosts"]
    tools.configure(settings)
    # The dashboard half has no ctx: it reads these back so the pane and the agent cannot disagree
    # about which hosts exist. Only a *non-default* configuration is persisted — the validate/doctor
    # probes call register() with a stub ctx that answers every key with its default, and writing
    # those would silently wipe a real host list from disk.
    if any(settings.get(key) != default for key, default in DEFAULTS.items()):
        try:
            for key in ("hosts_source",):
                if saved.get(key):
                    settings[key] = saved[key]
            store.save_settings(settings)
        except OSError:
            pass

    # Every real apply goes through Hermes' approval gate. The typed label inside cve_apply stays:
    # a second guard costs one comparison and survives a caller that bypasses the hook.
    ctx.register_hook("pre_tool_call", pre_tool_call)

    for name, schema in schemas.SCHEMAS.items():
        ctx.register_tool(
            name=name,
            toolset="patch-sentinel",
            schema=schema,
            handler=tools.HANDLERS[name],
            description=schema["description"],
        )
