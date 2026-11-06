"""Patch Sentinel — plugin entry point.

``register()`` is the only thing Hermes calls: it imports the tool module *inside* the function
(``hermes plugins doctor --ci`` blocks sockets during registration, and a module-level import is
also what breaks when this directory is loaded bare by tooling), hands the tool layer the resolved
config, and registers exactly the four tools declared in ``plugin.yaml``.

Nothing here touches the network or the system. The first measurement happens when the model
calls ``cve_scan``, and not a moment before.
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


def register(ctx) -> None:
    """Register the four tools. Called by the plugin loader with a real ``PluginContext``."""
    from .patch_sentinel import schemas, store, tools

    settings = {key: ctx.get_config(key, default) for key, default in DEFAULTS.items()}
    tools.configure(settings)
    # The dashboard half has no ctx: it reads these back so the pane and the agent cannot disagree
    # about which hosts exist. Only a *non-default* configuration is persisted — the validate/doctor
    # probes call register() with a stub ctx that answers every key with its default, and writing
    # those would silently wipe a real host list from disk.
    if any(settings.get(key) != default for key, default in DEFAULTS.items()):
        try:
            store.save_settings(settings)
        except OSError:
            pass

    for name, schema in schemas.SCHEMAS.items():
        ctx.register_tool(
            name=name,
            toolset="patch-sentinel",
            schema=schema,
            handler=tools.HANDLERS[name],
            description=schema["description"],
        )
