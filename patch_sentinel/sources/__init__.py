"""Source layer: one module per allowlisted source, each returning a typed result.

Nothing here runs at import time. Every function that could touch the system or the network
is called from a tool handler, at call time — ``hermes plugins doctor --ci`` blocks sockets
during registration and a fetch at import would fail that gate (and would be a lie about
what the plugin does when nobody asked it to).
"""
