"""Patch Sentinel — patch posture for the machine Hermes runs on, and the hosts it manages.

The pure decision core lives in :mod:`patch_sentinel.verdict`; the measurement lives under
``patch_sentinel/sources/``; the agent-facing tools live in :mod:`patch_sentinel.tools`.

This package marker exists so ``patch_sentinel.verdict`` can be imported (and unit-tested)
without loading Hermes: it imports nothing itself and touches nothing outside the process.
The plugin entry point (``__init__.py`` at the repository root) imports the tools module
lazily, inside ``register()``.
"""

__version__ = "0.1.0"
