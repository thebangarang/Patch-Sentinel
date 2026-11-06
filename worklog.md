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
