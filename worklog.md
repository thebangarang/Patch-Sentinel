# Worklog

## 2026-11-06 — project opened, design settled, nothing built yet

- **Action:** after nine days of hand-tracking CVE-2026-98432 on two hosts (kernel fix shipped
  2026-11-05/06, both hosts patched today), turned the work into a product idea and scaffolded the
  project from `_templates/init-project.sh` (tier High).
- **Result:** `README.md`, `project-context.md`, `docs/design.md`, `docs/landscape.md`, `AGENTS.md`,
  `SECURITY.md`, `decisions.md` (D1–D7) written. Landscape checked: no Hermes catalogue plugin covers
  this; OSS to wrap is identified (`osv-scanner`, `trivy`) and the parts not to rebuild are named.
  **No plugin code exists yet** — `plugin.yaml`, `__init__.py`, `patch_sentinel/`, `dashboard/`,
  `desktop/` are empty.
- **Reusable material ready to port:** `~/hermes-admin/scripts/cve-watch.py` (pure functions +
  19-assertion selftest), `pull-pending-images.sh` (429 backoff), `probe-cve-2026-98432.py`
  (proof by effect), `notify.py` (alert channel).
- **Next step:** the v0.1 vertical slice — `plugin.yaml` + `__init__.py` + `patch_sentinel/{verdict,
  apt_sim,usn,kernel,registry,plan,tools}.py` + tests, porting the four pure functions first (they
  already have fixtures). Then the dashboard half, then the demo script.
- **Blocked by:** nothing technical.

## 2026-11-06 (later) — renamed, licensed, published

- **Action:** the operator named the public repo `Patch-Sentinel`; the working name is retired. Folder
  `~/projects/patchpilot` → `~/projects/patch-sentinel`, all ten documents rewritten (ids
  `patch-sentinel`, Python package `patch_sentinel`), template leftovers removed (`CLAUDE.md`,
  `deploy_safe.py`), `LICENSE` (MIT) and a project `.gitignore`/`.env.example` written for a public
  plugin, remote wired to `git@github.com:thebangarang/Patch-Sentinel.git` and pushed.
- **Result:** contest rules recorded in `project-context.md` (due 11 Nov 17:00 EST; entry = catalogue PR
  + ≤90 s X video + Typeform), D1 closed, D8 (MIT) and D9 (deadline sets the scope) added.
- **Next step:** unchanged — port the pure logic into `patch_sentinel/verdict.py` (task 1 in
  `RESUME.md`), then the plugin shell so the catalogue PR has something to pin.

## 2026-11-06 (evening) — tasks 1 and 2 of RESUME done: the core and the four tools

- **Action:** ported the seven pure functions from `~/hermes-admin/scripts/cve-watch.py` into
  `patch_sentinel/verdict.py` and its `--selftest` into `tests/test_verdict.py` (the routine stays where
  it is and is untouched). Then built the plugin shell: `plugin.yaml`, `__init__.py`, `schemas.py`,
  `tools.py`, `plan.py`, `store.py`, and `patch_sentinel/sources/` (`shell`, `hostprobe`, `usn`,
  `registry`, `cve_tracker`, `hosts`).
- **Result, measured:**
  - `hermes plugins validate .` → passed, 12 checks; one caution (`sudo_usage` — command *text* in a
    plan, never executed).
  - `hermes plugins doctor . --ci` → OK, `4 tool(s), 0 hook(s)`.
  - Symlinked into `~/.hermes/plugins`, enabled, then `hermes chat -q "are we patched?"` → the
    transcript's tool line reads **`Cve_scan 7.8s`**; the answer quotes the scan timestamp, reports
    `exit_code 0`, both standing gaps, and that the VPS is not in the inventory yet.
  - Unreachable host (`vps=nowhere.invalid`): `exit_code 2`, `blind[]` carries
    `ssh: Could not resolve hostname…`, the answer says `COULD NOT LOOK` — never "clean".
  - 43 tests pass: the 23 ported assertions (differentially checked against the original module across
    770 comparisons — identical) plus the sources/plan/tracker fixtures.
- **Correction to an earlier note:** the routine's `--selftest` prints "17 cases asserted" while
  asserting 23 statements, and the project documents said 19. The port is 23 statements; the count in
  `tests/test_verdict.py` is the number of assertions, which is what the docs should have said.
- **Correction to the product story:** the live tracker for CVE-2026-98432 (2026-11-06) reads
  `pending` / `7.0.0-43.43` while 7.0.0-43.43 is installed and 7.0.0-43-generic is running here. The
  incident is therefore reproducible *today*, not only from an old capture — it is now a pinned
  fixture and a test (D11).
- **Two claims removed from the docs** because the code does not have them: "it applies the plan" (no
  apply path exists — D6's design stands, the code does not) and "an optional registry token" (D10: no
  credential path at all).
- **Next step:** task 3 — `dashboard/{manifest.json,plugin_api.py}` and `desktop/plugin.js` (NOW /
  PENDING / GAPS), then the demo script and the catalogue PR.
