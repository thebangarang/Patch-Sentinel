# RESUME — start here in a fresh session

You are picking up **patch-sentinel**, a Hermes plugin (hackathon entry): patch-posture scanning for the
local machine and remote hosts, with a dashboard pane and a gated apply. Today it is **design + reuse
analysis only — no plugin code exists yet**. Do not assume otherwise.

## The clock — this decides everything else

**Submissions close 11 Nov 2026, 5 PM EST (= 23:00 CET).** An entry is three things:

1. **A pull request adding `plugin-catalog/patch-sentinel.yaml`** to the Hermes catalogue. Needs: the
   public repo (it exists, MIT `LICENSE` added), README, `SECURITY.md` with a disclosure block
   (network calls, subprocesses, credential handling), and the catalogue file pinning a **full 40-char
   commit SHA** from a clean tree.
2. **A demo video ≤ 90 s, posted on X, tagging @NousResearch.**
3. **The Typeform** `form.typeform.com/to/FwJLvOln` with both links — sendable as soon as the PR is open.

Repo: `github.com/thebangarang/Patch-Sentinel`. Judged on **usefulness, reliability, polish,
creativity**, and on doing more than a prompt or a skill could — which is what the honesty layer
(three outcomes, installed ≠ running) is for. Scope cuts are decided in `decisions.md` D9.

## Read, in this order (≈10 minutes)

1. `project-context.md` — the why, the reuse table, the v0.1 boundary, the four questions for the operator
2. `docs/design.md` — the architecture and **the eight rules**; each one cites the measurement that produced it
3. `docs/landscape.md` — what we wrap instead of rebuilding (do not re-run this research)

Then: `decisions.md` (D1–D7, closed decisions — do not reopen them silently).

## Where things stand

| | |
|---|---|
| scaffolded | `~/projects/patch_sentinel/` — git repo, `.venv`, tier High, docs complete |
| built | **nothing** — no `plugin.yaml`, no `__init__.py`, no code |
| proven elsewhere | the logic this plugin ports runs daily already: `~/hermes-admin/scripts/cve-watch.py` |
| blocked by | 4 operator questions (`project-context.md` end) — none are technical |

## First three tasks, in order

**1. Port the pure logic (do this first — it has fixtures already).**
Copy, from `~/hermes-admin/scripts/cve-watch.py` into `patch_sentinel/verdict.py`, these functions *and*
their selftest cases: `abi`, `parse_inst`, `usn_index`, `explain`, `kernel_verdict`, `image_state`,
`proposal`. Rename the module's selftest into `tests/test_verdict.py` (stdlib `unittest`). The
19 assertions there are the plugin's first tests; keep them passing unchanged, they encode the rules.

**2. The plugin shell.**
```
plugin.yaml      name: patch-sentinel, version: 0.1.0, provides_tools: [cve_scan, cve_plan, cve_explain, cve_coverage]
__init__.py      register(ctx) — import the tools module *inside* register (never at module level)
patch_sentinel/tools.py    four handlers: (args, **kwargs) -> str, JSON, try/except per tool, refusal shape
```
Then prove it, in a fresh process (the only evidence that counts):
```bash
cd ~/projects/patch-sentinel
hermes plugins validate .            # manifest + registrations agree
hermes plugins doctor . --ci         # blocks sockets during registration — catches imports that fetch
ln -s ~/projects/patch-sentinel ~/.hermes/plugins/patch-sentinel   # install refuses ./, symlink for iteration
hermes chat -q "are we patched?"     # read the tool-call line: it must name cve_scan
```

**3. The dashboard half + the demo script.**
`dashboard/{manifest.json,plugin_api.py}` (router scoped to `/api/plugins/patch-sentinel`) and
`desktop/plugin.js` (three panels: NOW / PENDING / GAPS, house HUD style). Load the subpackage with
`importlib.util.spec_from_file_location`, never `sys.path`. The GAPS panel is never green and never
empty — that panel is the product's argument.

## What NOT to redo

- **The landscape research** (`docs/landscape.md`): no Hermes catalogue plugin occupies this space; wrap
  `osv-scanner`/`trivy` later, do not write a dependency matcher or an image scanner.
- **The incident analysis**: the eight rules in `docs/design.md` are the product. Do not "simplify" the
  three-outcome model, the installed≠running distinction, or the archive-over-tracker rule — each one
  was a real false all-clear.
- **A `-security` pocket filter.** It would have missed the kernel fix that started all this (D4).
- **`docker manifest inspect -v`.** Measured wrong: its first digest never equals RepoDigest (D5).
- **Declaring a Python dependency.** Stdlib only in v0.1 (D7).

## Answered already (do not re-ask)

- **Deadline / form / video**: 11 Nov 17:00 EST; catalogue PR + ≤90 s X video + Typeform. See the clock above.
- **Repo**: `github.com/thebangarang/Patch-Sentinel`, public, MIT (`LICENSE` in the tree).
- **Name**: Patch Sentinel — `patch-sentinel` id, `patch_sentinel` Python package (D1, closed).

## Still his to decide

1. **Unattended auto-apply in scope?** The typed-confirmation version is built either way (D6).
2. **He posts the video and the form** — his X account and the Typeform. Write the script, the credits
   line and the caption; never post them yourself.

## Definition of done for v0.1 (the demo lines, live)

`docs/design.md` → *v0.1 acceptance*: the two gates pass; a fresh `hermes chat -q "are we patched?"`
calls the tool and its answer matches `apt-get -s dist-upgrade` + `uname -r` quoted with timestamps;
the 2026-11-06 incident is reproduced from the captured fixture (kernel available → `full-upgrade` +
reboot); an unreachable host and a rate-limited registry both answer `unknown` with a non-zero exit;
the pane renders all three panels; one change-notification fires and a repeat does not.

## House rules that bite in this project

- Nothing touches the network at import (`doctor --ci` blocks sockets) — fetch at call time.
- Handlers return JSON strings and never raise; a refusal is a payload (`{"match": "none", ...}`),
  because a model handed prose will substitute a plausible sentence instead.
- `hermes chat` runs the **installed** tree: after each change, remove and re-install (or re-symlink),
  and check `git -C ~/.hermes/plugins/patch-sentinel rev-parse HEAD` when behaviour looks stale.
- Secrets via `agent.secret_scope.get_secret`, declared in `requires_env`; never read `.env`/`auth.json`.
- Server-side routes live behind the plugin's own `/api/plugins/<id>` prefix — no absolute URLs.
