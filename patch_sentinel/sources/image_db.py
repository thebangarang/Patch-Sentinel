"""What is inside a container image — read without running it.

An image id tells you whether the *tag* moved upstream. It says nothing about the 400 packages baked
into it, and that is where the CVEs live. The scanners that answer this (Trivy, Grype) unpack the
layers; so does this module, with nothing but the standard library and `docker save`.

How it works:

1. `docker save <image>` writes the image as a tar of layer tars (older format) or an OCI layout whose
   blobs are layer tars. Both are handled: every regular entry is tried as a tar.
2. The layers are walked in archive order and the files that matter are kept as they appear — later
   layers overwrite earlier ones, which is how an overlay filesystem resolves a path.
3. `etc/os-release` says which distribution the image is, `var/lib/dpkg/status` or `lib/apk/db/installed`
   lists its packages. RPM-based images are **not** parsed: an sqlite rpmdb needs a parser this plugin
   does not ship, and an empty answer would read as "no packages" instead of "not read".

Nothing is executed: `docker save` reads the image, it does not start it. That distinction matters —
running `sh` from an untrusted image to read a text file is the kind of shortcut that turns a scanner
into an attack surface.
"""
from __future__ import annotations

import io
import json
import os
import re
import tarfile
import tempfile

MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024        # 2 GB: past this the disk cost is not worth it
MAX_FILES = 6
MAX_PACKAGES = 1500
WANTED = ("etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status",
          "lib/apk/db/installed", "var/lib/rpm/Packages")

#: Which OSV ecosystem this image's packages are checked against.
ECOSYSTEMS = {"debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine"}


def _parse_os_release(text: str) -> dict:
    fields = {}
    for line in text.splitlines():
        if "=" in line and not line.strip().startswith("#"):
            key, _, value = line.partition("=")
            # os-release keys are upper case (ID, VERSION_ID); the rest of this module reads them
            # lower case, and a case mismatch here silently produced "unknown distribution"
            fields[key.strip().lower()] = value.strip().strip('"').strip("'")
    return fields


def parse_dpkg(text: str) -> list[dict]:
    """dpkg's `status` file → packages. Only fully installed entries count."""
    rows = []
    for block in re.split(r"\n\s*\n", text or ""):
        fields = {}
        for line in block.splitlines():
            if ":" in line and not line.startswith(" "):
                key, _, value = line.partition(":")
                fields[key.strip().lower()] = value.strip()
        if not fields.get("package") or not fields.get("version"):
            continue
        status = fields.get("status", "")
        if "installed" not in status:
            continue
        rows.append({"package": fields["package"], "version": fields["version"]})
    return rows


def parse_apk(text: str) -> list[dict]:
    """apk's `installed` file → packages (`P:` name, `V:` version, blocks separated by a blank line)."""
    rows, name, version = [], None, None
    for line in (text or "").splitlines():
        if not line.strip():
            if name and version:
                rows.append({"package": name, "version": version})
            name = version = None
            continue
        if line.startswith("P:"):
            name = line[2:].strip()
        elif line.startswith("V:"):
            version = line[2:].strip()
    if name and version:
        rows.append({"package": name, "version": version})
    return rows


def read_tar(path: str) -> dict:
    """Walk a `docker save` archive; return what the image is and what it carries."""
    state: dict = {"os": {}, "packages": [], "layers": 0, "read": [], "outcome": "ok"}
    found_packages: list[dict] = []
    with tarfile.open(path, "r:*") as outer:
        for member in outer:
            if not member.isfile() or member.size < 512:
                continue
            try:
                stream = outer.extractfile(member)
                if stream is None:
                    continue
                with tarfile.open(fileobj=stream, mode="r|*") as layer:
                    state["layers"] += 1
                    for entry in layer:
                        name = entry.name.lstrip("./")
                        if name not in WANTED or not entry.isfile() or entry.size > 32 * 1024 * 1024:
                            continue
                        handle = layer.extractfile(entry)
                        if handle is None:
                            continue
                        text = handle.read().decode("utf-8", "replace")
                        if name.endswith("os-release") and state["os"].get("id") is None:
                            state["os"] = _parse_os_release(text)
                        elif name == "var/lib/dpkg/status":
                            found_packages = parse_dpkg(text)           # a later layer wins
                            state["read"] = ["dpkg"]
                        elif name == "lib/apk/db/installed":
                            found_packages = parse_apk(text)
                            state["read"] = ["apk"]
                        elif name == "var/lib/rpm/Packages":
                            state["outcome"] = ("rpm-based image: the package database is sqlite and "
                                                "this plugin does not parse it — unmeasured, not clean")
            except (tarfile.TarError, OSError, EOFError):
                continue                                    # not a layer: skip it, keep going
    state["packages"] = found_packages[:MAX_PACKAGES]
    if state["outcome"] == "ok" and not found_packages:
        state["outcome"] = ("no package database found in the image — unmeasured, not clean")
    return state


def ecosystem_for(os_fields: dict) -> str | None:
    """`{"id": "alpine", "version_id": "3.19.1"}` → `Alpine:v3.19` — the OSV spelling."""
    os_id = (os_fields.get("id") or "").strip().lower()
    version = (os_fields.get("version_id") or "").strip()
    base = ECOSYSTEMS.get(os_id)
    if not base or not version:
        return None
    if base == "Alpine":
        return f"Alpine:v{'.'.join(version.split('.')[:2])}"
    major = version.split(".")[0]
    if base == "Debian":
        return f"Debian:{major}"
    if base == "Ubuntu":
        return f"Ubuntu:{version}"                       # OSV keys Ubuntu on the full release
    return None


def save_and_read(images: list[str], target: str | None, timeout: int = 300) -> dict:
    """`docker save` each image once, then read it. Capped in count and in bytes.

    Returns ``{"images": {tag: state}, "outcome": str}``. A docker that refuses, a missing daemon or an
    image that cannot be written all become outcomes — never an empty "clean".
    """
    from . import shell

    results: dict[str, dict] = {}
    for image in images[:MAX_FILES]:
        with tempfile.TemporaryDirectory(prefix="ps-image-") as work:
            path = os.path.join(work, "image.tar")
            # the archive is written here, not on the host: a remote docker's /tmp is not a path this
            # process can open, and `docker save` on stdout streams it back over the same ssh session
            code, out = save_image(image, target, path, timeout)
            if code != 0 or not os.path.exists(path):
                results[image] = {"outcome": f"docker save failed (rc={code}): {out[:160]}",
                                  "packages": [], "os": {}}
                continue
            size = os.path.getsize(path)
            if size > MAX_IMAGE_BYTES:
                results[image] = {"outcome": f"image archive is {size // (1024 * 1024)} MB — larger "
                                             f"than the reader will unpack", "packages": [], "os": {}}
                continue
            try:
                results[image] = read_tar(path)
            except (tarfile.TarError, OSError, EOFError) as exc:
                results[image] = {"outcome": f"the image archive could not be read "
                                             f"({type(exc).__name__})", "packages": [], "os": {}}
    return {"images": results}


def shell_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def _argv(command: str, target: str | None) -> list[str]:
    from . import shell

    if target:
        host, port = shell.split_target(target)
        argv = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={shell.SSH_CONNECT_TIMEOUT}"]
        if port:
            argv += ["-p", port]
        return argv + [host, command]
    return ["/bin/bash", "-c", command]


def save_image(image: str, target: str | None, path: str, timeout: int) -> tuple[int, str]:
    """`docker save` into a local file, from this machine or through ssh. Returns (rc, stderr tail)."""
    import subprocess

    command = ("docker save " if not target else "docker save ") + shell_quote(image)
    try:
        with open(path, "wb") as handle:
            proc = subprocess.run(_argv(command, target), stdout=handle,
                                  stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "docker save timed out"
    except OSError as exc:
        return 127, f"{type(exc).__name__}: {exc}"
    return proc.returncode, (proc.stderr or b"").decode("utf-8", "replace").strip()


def report(state: dict) -> dict:
    """Add the ecosystem the packages should be checked against, and a sentence for the pane."""
    ecosystem = ecosystem_for(state.get("os") or {})
    os_label = " ".join(filter(None, [(state.get("os") or {}).get("id"),
                                      (state.get("os") or {}).get("version_id")])) or "unknown os"
    return {**state, "ecosystem": ecosystem, "os_label": os_label,
            "summary": (f"{os_label}: {len(state.get('packages') or [])} package(s) read from "
                        f"{state.get('layers')} layer(s)"
                        if state.get("packages") else state.get("outcome") or "nothing read")}
