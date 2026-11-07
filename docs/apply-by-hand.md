# Patching by hand, when APPLY refuses

APPLY is the only control in this plugin that changes a machine. It runs as the user Hermes runs as,
with `sudo -n` — **non-interactive, because an agent tool call cannot answer a password prompt**. When
that user cannot run its package manager without a password, the gate refuses, and it hands you the
commands instead.

This page is those commands, with the part that usually gets left out: **where to type them**.

---

## When APPLY works on its own

| situation | APPLY works? |
|---|---|
| the entry is `root@host` (or any account that is root over ssh) | **yes** — no sudo involved |
| the account can run the package manager with no password (a scoped rule, or a broad one) | **yes** |
| the entry is `local`, and Hermes runs as the same user you are logged in as, with a no-prompt rule | **yes** |
| the entry is `local`, and Hermes runs as its own service account (`hermes`) | **no** — its sudo is not yours; use the handoff below |
| any host where sudo wants a password | **no** — by design; see "Why there is no password field" |

The refusal message names the account: on a local host it is whatever `whoami` says inside the plugin
(often `hermes`), not your login.

---

## The local machine (the one running Hermes)

Open a terminal **on that machine**, as yourself — not through Hermes, not as `hermes`.

```bash
# 1. refresh the metadata and download everything, changing nothing
sudo apt-get update && sudo apt-get -y --download-only full-upgrade

# 2. install what was downloaded
sudo apt-get -y full-upgrade

# 3. check what is left (empty output = nothing pending)
apt-get -s dist-upgrade | grep '^Inst ' || echo 'nothing pending'

# 4. if the kernel moved, reboot — an installed kernel is not a running one
uname -r
```

On Fedora / RHEL-family the same three steps are:

```bash
sudo dnf -y check-upgrade --refresh         # rc 100 means updates available; that is not an error
sudo dnf -y upgrade --refresh
dnf check-upgrade >/dev/null; echo rc=$?    # 100 = still pending, 0 = none
sudo reboot                                  # only if the kernel changed
```

Arch: `sudo pacman -Syu`, then `pacman -Qu` to confirm. Alpine: `sudo apk update && sudo apk upgrade`,
then `apk version -l '<'`. openSUSE: `sudo zypper refresh && sudo zypper update`, then `zypper lu`.

---

## A remote server

Two ways, both fine.

**From your machine, one command at a time** — the ssh line is in the pane's handoff block
(`connect: ssh -p 2223 debian@10.0.0.9`):

```bash
ssh -p 2223 debian@10.0.0.9 'sudo apt-get update && sudo apt-get -y --download-only full-upgrade'
ssh -p 2223 debian@10.0.0.9 'sudo apt-get -y full-upgrade'
ssh -p 2223 debian@10.0.0.9 "apt-get -s dist-upgrade | grep '^Inst ' || echo 'nothing pending'"
```

**Or open a session there** and run the same commands as if you were on the box:

```bash
ssh -p 2223 debian@10.0.0.9
# then, in that shell:
sudo apt-get update && sudo apt-get -y --download-only full-upgrade
sudo apt-get -y full-upgrade
```

If the account is `root`, drop every `sudo`.

---

## After the reboot

Re-run the scan (`rescan all`, or `hermes chat -q "are we patched?"`). Two things must be true before
you call it done:

1. **the running kernel is the installed one** — `uname -r` equals the version the plan installed;
2. **the pending list is empty** — the scan says `0 pending`, not "nothing to do".

A machine that installed a kernel but did not reboot reports `kernel-reboot-needed`. That is not a
failure of the apply; it is the apply telling the truth about what is actually running.

---

## Why there is no password field

Because the plugin would then be the thing holding your root credential: typed into a webview, carried
across the bridge, kept in the Python process, and piped over ssh. One leak — a log, a crash dump, a
screenshot, a malicious pane — hands over root on every server in the inventory. The plugin's promise is
that **no credential ever touches it**, and a password box would spend that promise to save one paste.

The three alternatives are all better than a password box:

1. **root over ssh** for servers you own — no sudo at all;
2. **a no-prompt rule scoped to the update commands**, if you want unattended patches:
   `/etc/sudoers.d/patch-sentinel`, `chmod 440`, holding one line naming the exact binaries
   (`apt-get`, `dnf`, …) for the exact account — read it, then `visudo -c` to validate. This is a
   decision about your host, so the plugin will not write it for you;
3. **the handoff above** — the same work, one paste, no new privilege anywhere.

---

## If something goes wrong

| symptom | what it means |
|---|---|
| `sudo: a password is required` in the refusal | the account cannot patch unattended; use this page |
| `Could not get lock /var/lib/dpkg/lock` | another upgrade is running, or a previous one died: wait, or `sudo rm` the stale lock only if you are sure |
| the apply reports `rc 100` on `dnf check-upgrade` | not a failure: 100 is dnf's "updates available" |
| the scan still says *N pending* after the apply | the archive moved (new updates landed), or the apply ran on a different host — check the receipt's `before`/`after` |
| the scan says `kernel-reboot-needed` | install worked, reboot owed |
