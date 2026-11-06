# The lab: proving adapters on real machines

A container proves a parser. Only a machine with its own kernel can answer "is this Fedora box
patched", so the lab is a set of QEMU VMs booted from the distro's own cloud image, reached over
ssh on loopback — the same path `cve_scan` uses for any remote host.

```
python3 scripts/lab_vm.py fetch fedora      # once, ~580 MB (Fedora Cloud Base Generic 45)
python3 scripts/lab_vm.py up fedora         # overlay disk + cloud-init seed + boot + wait
python3 scripts/lab_vm.py ssh fedora -- uname -r
python3 scripts/lab_vm.py status | down fedora
```

Also available: `arch` (~580 MB, Arch cloudimg), `opensuse` (~600 MB, Leap 15.6 Minimal-VM) and
`alpine` — the last one is why the table below has a "not proven" row.

Debian is the same with `debian` (~330 MB, Debian 12 genericcloud). Images, disks and the ssh key
live under `tmp/vms/` (gitignored); the key is `~/.ssh/id_ed25519_patchlab` and is added to the
operator's agent, so the plugin reaches the VMs without ever holding a credential.

The repository ships **no** sudo policy for these hosts. If an apply needs prompt-free sudo, the
operator writes it in `~/.config/patch-sentinel-lab/seed-extra.yaml` (or the path in
`PATCH_SENTINEL_LAB_SEED`), which `lab_vm.py` appends to the cloud-init user data: the lab box gets
the policy and the published tree stays clean — the admission scan rates a no-password sudo rule
*dangerous*, correctly, and it scans every file in the directory.

## What was proven here, with the numbers

**1. The adapter reads a distro it has never seen** — first boot of Fedora 45:

```
fedora-lab  dnf  fedora/45  kernel 7.2.11-300.fc45.x86_64 → 7.2.15-300.fc45 installable
            109 package updates pending, exit_code 1
```

**2. The gate applies, and says what is still owed** — `cve_apply` with the host name typed and
`dry_run=false`, on that same VM:

| | |
|---|---|
| before | kernel running 7.2.11-300.fc45, installed 7.2.11-300.fc45, **109 pending** |
| stage | `sudo dnf -y check-upgrade --refresh` → rc 100 (updates exist), 1.4 s |
| apply | `sudo dnf -y upgrade --refresh` → rc 0, 105.2 s, *3 installing / 107 upgrading* |
| after | kernel installed **7.2.15-300.fc45**, running **7.2.11-300.fc45** → `kernel-reboot-needed`, 0 pending |
| verdict | `reboot_required: true` — installing is not running |

Receipt written to `~/.hermes/patch-sentinel/receipts.jsonl` (mode 600) with the before/after
versions and the outcome.

**3. After the reboot the loop is closed** — `uname -r` on the VM:

```
7.2.15-300.fc45.x86_64
kernel-core-7.2.11-300.fc45.x86_64   (kept: the reversal is the bootloader menu)
kernel-core-7.2.15-300.fc45.x86_64
```

and a fresh scan of all three machines:

```
beelink     apt  ubuntu/resolute  0 pending  kernel 7.0.0-43-generic       current
fedora-lab  dnf  fedora/45        0 pending  kernel 7.2.15-300.fc45         current
debian-lab  apt  debian/bookworm  0 pending  kernel 6.1.0-54-cloud-amd64    current
exit_code 0 · findings 0 · blind 0
```

## What the real machines caught that containers and reasoning did not

- **`rpm -q kernel` is not "is there a kernel"**: Fedora ships `kernel-core`, no `kernel`
  metapackage, so the query answered *"package kernel is not installed"* on a box plainly running
  one. The first fix then invented a version called `modules-core` out of `kernel-modules-core`;
  a package name now only counts when the character after it is a digit.
- **`dnf check-upgrade` exits 100 *because* updates exist.** The gate read that as a failed stage
  and refused to continue — right behaviour, wrong reading. Success codes are per family now.
- **A rebuilt VM has a new ssh host key**, which strict checking rejects as "host key changed";
  `lab_vm.py up` clears that one loopback entry when it creates a fresh disk.
- **`apt-get` leaked into a Fedora plan.** Caught by rendering the pane, not by a test: commands
  now come from the host's own adapter, and a test fails if `apt-get` appears in an rpm plan.

## Five machines, four families, one call (2026-11-06, after the new adapters landed)

```
beelink      apt     ubuntu/resolute        0 pending  kernel 7.0.0-43-generic            current
fedora-lab   dnf     fedora/45              0 pending  kernel 7.2.15-300.fc45             current
debian-lab   apt     debian/bookworm        0 pending  kernel 6.1.0-54-cloud-amd64        current
arch-lab     pacman  arch                   0 pending  kernel 7.2.11-arch1-1              current
opensuse-lab zypper  opensuse-leap/15.6     0 pending  kernel 6.4.0-150600.23.100-default current
exit_code 0 · findings 0 · blind 0
```

Three more traps the new machines produced, each now encoded:

- **openSUSE's kernel is not `kernel-default`.** `rpm -q kernel-default` answers *"not installed"*
  on a Leap box that is plainly running one: the running kernel belongs to `kernel-default-base`,
  and its version-release (`6.4.0-150600.23.100.1.150600.12.46.2`) does not resemble the release
  string (`6.4.0-150600.23.100-default`). The adapter now asks RPM which package *owns*
  `/boot/vmlinuz-$(uname -r)` instead of guessing names, and the first version of it reported a
  reboot as owed on a current host — the exact false alarm this project treats as a defect.
- **Arch writes the same kernel two ways**: `uname -r` says `7.2.11-arch1-1`, the package says
  `7.2.11.arch1-1`. The adapter converts between them and compares numerically, so `6.12.10` sorts
  above `6.12.9` (string order gets that wrong, and the mis-sort reads as a boot owed).
- **Alpine did not come up in the lab.** Neither the plain `alpine-*` nor the `nocloud_*` cloud
  image processed the cloud-init seed — both booted to a login prompt with no user created. The
  `apk` adapter exists in the tree, is **not registered**, and Alpine therefore answers
  `unsupported`. A host we could not measure does not get a green row.

## Adding a distro

One entry in `scripts/lab_vm.py` (`url`, `user`, `port`, `label`) plus one adapter in
`patch_sentinel/sources/dispatch.py`. Until the adapter exists the host answers `unsupported`
with its own id — a red gap, never a green.
