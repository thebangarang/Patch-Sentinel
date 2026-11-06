#!/usr/bin/env python3
"""Lab VMs — a real machine per distro, because an adapter is proven on a host or not at all.

A container borrows the host's kernel, so it can prove a package-manager parser and nothing about
the kernel. A VM has its own, which is what makes "this Fedora box's kernel is current" a fact
instead of a hope. These VMs are also the plugin's remote-host test bench: each one is reached over
ssh on a loopback port, the exact path ``cve_scan`` uses for any remote host.

    python3 scripts/lab_vm.py fetch fedora      # download the cloud image (~600 MB, once)
    python3 scripts/lab_vm.py up fedora         # overlay disk + cloud-init seed + boot + wait
    python3 scripts/lab_vm.py ssh fedora -- uname -r
    python3 scripts/lab_vm.py status
    python3 scripts/lab_vm.py down fedora

Everything lives under ``tmp/vms/`` (gitignored). The ssh key is ``~/.ssh/id_ed25519_patchlab``,
added to the operator's agent, so the plugin's own ssh (BatchMode, agent) reaches the VMs without
the plugin ever holding a credential.

Images are the distro's own cloud images: Fedora Cloud Base Generic, Debian genericcloud.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "tmp" / "vms"
KEY = Path.home() / ".ssh" / "id_ed25519_patchlab"
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=5"]

DISTROS = {
    "fedora": {
        "url": "https://download.fedoraproject.org/pub/fedora/linux/releases/45/Cloud/"
               "x86_64/images/Fedora-Cloud-Base-Generic-45-1.4.x86_64.qcow2",
        "user": "fedora",
        "port": 2222,
        "label": "fedora-lab",
    },
    "debian": {
        "url": "https://cloud.debian.org/images/cloud/bookworm/latest/"
               "debian-12-genericcloud-amd64.qcow2",
        "user": "debian",
        "port": 2223,
        "label": "debian-lab",
    },
}


def sh(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, **kwargs)


def ensure_key() -> None:
    if KEY.exists():
        return
    LAB.mkdir(parents=True, exist_ok=True)
    result = sh(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "patch-sentinel lab VMs",
                 "-f", str(KEY)])
    if result.returncode != 0:
        sys.exit(f"ssh-keygen failed: {result.stderr.strip()}")
    print(f"created {KEY}")
    sh(["ssh-add", str(KEY)])          # the plugin's ssh uses the agent, never the key file


def paths(name: str) -> dict[str, Path]:
    spec = DISTROS[name]
    base = LAB / f"{name}-base.qcow2"
    return {
        "base": base,
        "disk": LAB / f"{name}.qcow2",
        "seed": LAB / f"{name}-seed.iso",
        "pid": LAB / f"{name}.pid",
        "console": LAB / f"{name}-console.log",
        "userdata": LAB / f"{name}-user-data",
        "meta": LAB / f"{name}-meta-data",
    }


def fetch(name: str) -> None:
    spec = DISTROS[name]
    p = paths(name)
    if p["base"].exists() and p["base"].stat().st_size > 100 * 1024 * 1024:
        print(f"{p['base']} already fetched ({p['base'].stat().st_size // 1048576} MB)")
        return
    LAB.mkdir(parents=True, exist_ok=True)
    url = spec["url"]
    print(f"fetching {url}")
    tmp = p["base"].with_suffix(".part")
    with urllib.request.urlopen(url, timeout=120) as resp, tmp.open("wb") as handle:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        while chunk := resp.read(1 << 20):
            handle.write(chunk)
            done += len(chunk)
            if total:
                pct = done * 100 // total
                if pct % 10 == 0:
                    print(f"  {pct}% ({done // 1048576} MB)", flush=True)
    tmp.replace(p["base"])
    print(f"fetched {p['base']} ({p['base'].stat().st_size // 1048576} MB)")


def write_seed(name: str) -> None:
    spec = DISTROS[name]
    p = paths(name)
    pub = Path(str(KEY) + ".pub").read_text().strip()
    # An optional local fragment lets the operator grant this lab host things the repository must
    # not ship (a NOPASSWD sudoers rule, for one). It lives under tmp/vms/, is gitignored, and its
    # absence simply means the host gets no extra policy — which is the default and the safe case.
    extra = LAB / "seed-extra.yaml"
    extra_text = extra.read_text(encoding="utf-8") if extra.exists() else ""
    p["userdata"].write_text(
        "#cloud-config\n"
        f"hostname: {spec['label']}\n"
        "preserve_hostname: false\n"
        "users:\n"
        f"  - name: {spec['user']}\n"
        "    groups: [wheel]\n"
        "    shell: /bin/bash\n"
        # No passwordless sudo: the scan is read-only, so the test host does not need root, and a
        # plugin that ships an NOPASSWD rule in its own tree is a finding (it was, at admission).
        "    ssh_authorized_keys:\n"
        f"      - {pub}\n"
        "ssh_pwauth: false\n"
        "package_update: false\n" + extra_text,
        encoding="utf-8")
    p["meta"].write_text(f"instance-id: {spec['label']}\nlocal-hostname: {spec['label']}\n",
                         encoding="utf-8")
    result = sh(["cloud-localds", str(p["seed"]), str(p["userdata"]), str(p["meta"])])
    if result.returncode != 0:
        sys.exit(f"cloud-localds failed: {result.stderr.strip()}")


def up(name: str) -> None:
    spec = DISTROS[name]
    p = paths(name)
    ensure_key()
    fetch(name)
    if not p["seed"].exists():
        write_seed(name)
    if not p["disk"].exists():
        # A new disk means a new ssh host key; the old entry would block the plugin's strict
        # checking with "host key has changed". Drop only this lab VM's loopback entry.
        sh(["ssh-keygen", "-f", str(Path.home() / ".ssh" / "known_hosts"),
            "-R", f"[127.0.0.1]:{spec['port']}"])
        result = sh(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                     "-b", str(p["base"]), str(p["disk"]), "20G"])
        if result.returncode != 0:
            sys.exit(f"qemu-img failed: {result.stderr.strip()}")
        print(f"created {p['disk']} (backed by {p['base'].name})")
    if running(name):
        print(f"{name} is already running on port {spec['port']}")
        return
    argv = [
        "qemu-system-x86_64",
        "-enable-kvm", "-cpu", "host", "-smp", "2", "-m", "2048",
        "-drive", f"file={p['disk']},if=virtio,cache=unsafe",
        "-drive", f"file={p['seed']},format=raw,if=virtio",
        "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{spec['port']}-:22",
        "-device", "virtio-net-pci,netdev=n0",
        "-display", "none",
        "-serial", f"file:{p['console']}",
        "-pidfile", str(p["pid"]),
        "-daemonize",
    ]
    result = sh(argv)
    if result.returncode != 0:
        sys.exit(f"qemu failed: {result.stderr.strip()}")
    print(f"booted {name}, waiting for ssh on 127.0.0.1:{spec['port']} ...")
    if not wait_ssh(name, timeout=300):
        tail = p["console"].read_text(errors="replace")[-1500:] if p["console"].exists() else ""
        sys.exit(f"{name} did not answer ssh within 300s. Console tail:\n{tail}")
    print(f"{name} is up: ssh {spec['user']}@127.0.0.1 -p {spec['port']}")
    print(f"plugin host entry: {spec['label']}={spec['user']}@127.0.0.1:{spec['port']}")


def ssh_argv(name: str, command: list[str] | None = None) -> list[str]:
    spec = DISTROS[name]
    return ["ssh", *SSH_OPTS, "-i", str(KEY), "-p", str(spec["port"]),
            f"{spec['user']}@127.0.0.1", *(command or ["true"])]


def wait_ssh(name: str, timeout: int = 300) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if sh(ssh_argv(name, ["true"])).returncode == 0:
            return True
        time.sleep(5)
    return False


def running(name: str) -> bool:
    p = paths(name)
    if not p["pid"].exists():
        return False
    try:
        os.kill(int(p["pid"].read_text().strip()), 0)
        return True
    except (ValueError, OSError):
        return False


def down(name: str) -> None:
    p = paths(name)
    if not p["pid"].exists():
        print(f"{name}: no pid file")
        return
    pid = int(p["pid"].read_text().strip())
    os.kill(pid, 15)
    for _ in range(20):
        time.sleep(0.5)
        try:
            os.kill(pid, 0)
        except OSError:
            print(f"{name}: stopped")
            return
    os.kill(pid, 9)
    print(f"{name}: killed")


def status() -> None:
    for name, spec in DISTROS.items():
        state = "running" if running(name) else "stopped"
        print(f"{name:8} {state:8} port {spec['port']}  {spec['label']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Lab VMs for proving patch-sentinel adapters")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("fetch", "up", "down"):
        cmd = sub.add_parser(action)
        cmd.add_argument("name", choices=sorted(DISTROS))
    ssh_cmd = sub.add_parser("ssh")
    ssh_cmd.add_argument("name", choices=sorted(DISTROS))
    ssh_cmd.add_argument("command", nargs=argparse.REMAINDER)
    sub.add_parser("status")
    args = parser.parse_args()

    if args.action == "status":
        status()
        return 0
    if args.action == "fetch":
        ensure_key()
        fetch(args.name)
        return 0
    if args.action == "up":
        up(args.name)
        return 0
    if args.action == "down":
        down(args.name)
        return 0
    if args.action == "ssh":
        ensure_key()
        command = args.command or []
        if command[:1] == ["--"]:
            command = command[1:]
        result = subprocess.run(ssh_argv(args.name, command or ["true"]))
        return result.returncode
    return 2


if __name__ == "__main__":
    sys.exit(main())
