# How to check it actually works

Trust is not a feature. Every surface below can be re-run in a minute, and each one prints what it
measured. `scripts/selfcheck.py` runs all of them in one go:

```bash
python3 scripts/selfcheck.py                 # this machine
python3 scripts/selfcheck.py --host fedora-lab   # a declared host, plus its plan
python3 scripts/selfcheck.py --json          # machine-readable
```

Exit code **0** when every surface answered (a finding is not a failure), **2** when one could not
look — the same contract the tools use.

Real output, 2026-11-06, five machines declared:

```
[ok] os scan · beelink        apt    ubuntu/resolute    0 pending   kernel 7.0.0-43-generic → kernel-current
[ok] os scan · fedora-lab     dnf    fedora/45        109 pending   kernel 7.2.11-300.fc45 → kernel-update-available
[ok] os scan · debian-lab     apt    debian/bookworm    0 pending   kernel 6.1.0-54-cloud → kernel-current
[ok] os scan · arch-lab       pacman arch               0 pending   kernel 7.2.11-arch1-1 → kernel-current
[ok] os scan · opensuse-lab   zypper opensuse-leap/15.6 0 pending   kernel 6.4.0-150600.23.100 → kernel-current
[ok] language check           4 package(s) via npm global tree, pip3 · 0 vulnerable · no findings
[ok] update proposal · fedora-lab   3 step(s) for 109 pending update(s)
[ok] advisory feed            https://ubuntu.com/security/notices.json?release=resolute&limit=20
```

## 0. The test suite, in the environment that runs all of it

```bash
python3 -m unittest discover -s tests -t .   # 110 tests — the full run
.venv/bin/python -m unittest discover -s tests -t .   # 110 tests, 8 skipped
```

The project's own venv has no FastAPI (the plugin declares no Python dependency), so the six
dashboard-route tests **skip** there. They run under the Hermes interpreter, which is what the pane
actually uses — run the suite with `python3`, not with the venv, or those six never execute.

## 1. The language check, against something known to be vulnerable

A clean machine proves nothing — "0 vulnerable" is also what a broken query returns. So point it at
a throwaway environment that *is* vulnerable. This writes only inside `tmp/`, and needs no root:

```bash
cd ~/projects/patch-sentinel
V=$(mktemp -d)/vulnvenv          # OUTSIDE the repo: see the note below
python3 -m venv "$V"
"$V/bin/pip" install -q 'jinja2==2.10' 'urllib3==1.24.1'
PATH="$V/bin:$PATH" .venv/bin/python -c "
import json,sys; sys.path.insert(0,'.')
from patch_sentinel import tools
print(json.loads(tools.cve_libraries({}))['answer'])
print(json.loads(tools.cve_libraries({}))['vulnerable'][0])"
```

Expected (measured 2026-11-06, 10.5 s):

```
hermes-SER: 38 advisory match(es) across 2 package(s), from 7 installed language package(s) checked
{'ecosystem': 'PyPI', 'package': 'Jinja2', 'version': '2.10', 'id': 'GHSA-462w-v97r-4m45',
 'aliases': ['CVE-2019-10906', ...], 'severity': 'critical (loss of confidentiality or integrity)',
 'fixed': ['2.10.1'], ...}
```

Jinja2 2.10 returns **12** advisories, urllib3 1.24.1 **26**, each with the versions that close it.
If those numbers come back zero with the venv on `PATH`, the query is broken — that is exactly what
this check is for.

> **Keep the throwaway venv out of the repo.** `hermes plugins validate .` runs a security scan over
> the whole working tree; a venv inside it fails the run with `binary_file`, `exec_string` and
> `symlink_escape` (measured — a `.so`, pip's bundled `.exe` launchers and its `python3` symlinks).
> That is the scanner doing its job, not a plugin defect, which is why this recipe uses `mktemp -d`.

**What it reads:** npm's global tree and the pip environment on `PATH` — the venv above *is* the pip
environment, which is why the numbers move. Per-project lockfiles are read only when you ask about a
specific project in chat (see the GAPS panel).

## 2. The update proposal, on a host with something to install

A plan is only meaningful when the host has pending updates. All five lab hosts are patched except
Fedora, which is left deliberately behind:

```bash
PATCH_SENTINEL_HOSTS='fedora-lab=fedora@127.0.0.1:2222' \
  .venv/bin/python -c "
import json,sys; sys.path.insert(0,'.')
from patch_sentinel import tools
tools.configure({'hosts':'fedora-lab=fedora@127.0.0.1:2222'})
p = json.loads(tools.cve_plan({'host':'fedora-lab'}))
print(p['pending_count'], p['kernel']['verdict'])
for s in p['steps']: print('-', s['command'], '| reverse:', s['reversal'])"
```

Expected — three ordered steps, each with its own reversal:

```
109 kernel-update-available
- sudo dnf -y check-upgrade --refresh | reverse: nothing changed to reverse
- sudo dnf -y upgrade --refresh      | reverse: dnf history undo last
- sudo reboot                        | reverse: boot the previous kernel …
```

To get the fresh-host state back (109 pending):

```bash
.venv/bin/python scripts/lab_vm.py down fedora
rm -f tmp/vms/fedora.qcow2 tmp/vms/fedora-seed.iso
.venv/bin/python scripts/lab_vm.py up fedora
```

## 3. The refusal — the check most scanners cannot pass

```bash
PATCH_SENTINEL_HOSTS='beelink=local,vps=nowhere.invalid' \
  .venv/bin/python -c "
import json,sys; sys.path.insert(0,'.')
from patch_sentinel import tools
tools.configure({'hosts':'beelink=local,vps=nowhere.invalid'})
out = json.loads(tools.cve_scan({}))
print('exit', out['exit_code']); print(out['blind'])"
```

Expected: `exit 2` and a `blind` entry carrying `ssh: Could not resolve hostname…` — the host is
reported as *could not look*, never as patched.

## 4. Is the pane the build I just edited?

The desktop app stages a copy of `desktop/plugin.js` and imports it at launch, so an edit can be on
disk and not on screen. The pane prints its own build in the footer:

```
pane build 79ffd2d4 · matches the repo
```

If it disagrees, or no footer is visible, quit the app completely and relaunch — closing the pane
alone does not re-import the module. `GET /api/plugins/patch-sentinel/health` reports the two
fingerprints (`repo` and `served`) directly.

## "Plugin failed to load — missing ) argument list"

The desktop app imports `desktop/plugin.js` as a module and hot-reloads it when the file changes. It
stages a copy under `$HERMES_HOME/desktop-plugins/<name>/` first, so the renderer can import the file
while it is still being written — and V8's report for a file that ends mid-expression is exactly
`missing ) after argument list`.

Check the file rather than the toast:

```bash
node --check desktop/plugin.js                                  # syntax
sha1sum desktop/plugin.js ~/.hermes/desktop-plugins/patch-sentinel/plugin.js   # same build?
```

If both copies match and the file parses, the error is a stale read: touch or save the file again, or
restart the app, and it clears. A real syntax error would fail `node --check` too.

**Editing discipline (for whoever works on this tree):** write `desktop/plugin.js` atomically —
`cp file /tmp/x && mv /tmp/x file` — and run `node --check` after every edit. A plain truncate-and-write
leaves a window in which the app can import half a file, which is how this toast appears.

## The theme

The palette is a skin file, not a marketplace download: `~/.hermes/skins/patch-sentinel.yaml`
(cyan `#35d6d6` on `#0a0a0f`, the pane's own colours). Pick **patch-sentinel** in
Settings → Appearance, or:

```bash
hermes config set display.skin patch-sentinel
```

One file themes the CLI, the TUI and the desktop GUI. `hermes config set display.skin default`
(Reboot the app) puts it back.
