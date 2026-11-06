"""Adapters for the package-manager families beyond apt and dnf.

Each module exposes ``FAMILY``, ``BLOCK`` (the shell text that emits the shared sections) and
``parse(body)`` — the same contract ``dispatch.PARSE...`` uses for the two original families. They
live in separate files because each one carries the quirks of its own tool, and a single 600-line
module is where those quirks get lost.
"""

from . import pacman, zypper

# `apk` (Alpine) is written but NOT registered: its cloud images would not process the NoCloud seed
# (two variants tried, both booted to a login prompt with no user created), so the adapter has never
# read a real Alpine host. An adapter this project cannot prove must not claim to measure a machine
# — an Alpine box answers `unsupported` with its own id, which is the honest answer until a lab host
# exists. Register it here the day one does.
MODULES = (pacman, zypper)
BY_FAMILY = {module.FAMILY: module for module in MODULES}
