#!/usr/bin/env bash
# Render the real pane to one standalone HTML file, so the interface can be looked at on any machine —
# including one that has no Hermes desktop app. With a Chromium available it also writes a PNG.
#
#   ./scripts/preview_pane.sh          # runs the real tools (~40 s), then renders
#   ./scripts/preview_pane.sh --fast   # skips the scan and shows the "not measured yet" state
#
# It does not fake data: every number comes from the same handlers the pane calls, on this machine.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="${HERMES_DESKTOP_APP:-$HOME/.hermes/hermes-agent/apps/desktop}"
# Outside the repo on purpose: the payloads quote `sudo` commands, and the admission scan reads every
# file in the tree — a scratch payload in tmp/ once rated the whole plugin "dangerous".
preview="${PATCH_SENTINEL_PREVIEW:-${TMPDIR:-/tmp}/patch-sentinel-preview}"
out="$preview/pane-preview.html"
[[ "${1:-}" == "--fast" ]] && out="$preview/pane-preview-fast.html"
rm -rf "$preview" && mkdir -p "$preview"

echo "· collecting the payloads the pane reads"
python3 - "$root" "$preview" "${1:-}" <<'PY'
import json
import sys

root, preview, mode = sys.argv[1], sys.argv[2], (sys.argv[3] if len(sys.argv) > 3 else "")
sys.path.insert(0, root)
from patch_sentinel import store, tools

tools.configure(store.load_settings() or {})

def dump(name, payload):
    with open(f"{preview}/preview-{name}.json", "w") as handle:
        handle.write(payload if isinstance(payload, str) else json.dumps(payload))

coverage = tools.cve_coverage({})
dump("coverage", coverage)
scan = tools.cve_scan({}) if mode != "--fast" else json.dumps({"hosts": {}, "blind": [], "note": ""})
dump("status", scan)
dump("libraries", tools.cve_libraries({}))
# the label comes from the scan, because that is what the pane selects first
label = next(iter((json.loads(scan).get("hosts") or {})), "")
if label:
    dump("integrity", tools.cve_integrity({"host": label}))
    dump("plan", tools.cve_plan({"host": label}))
PY

echo "· rendering"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
ln -s "$app/node_modules" "$work/node_modules"
cp "$root"/tests/pane/sdk-stub.mjs "$work/"
sed "s|from '@hermes/plugin-sdk'|from './sdk-stub.mjs'|g" "$root/desktop/plugin.js" > "$work/pane.mjs"

cd "$work"
cat > render.mjs <<'JS'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { readFileSync, writeFileSync } from 'node:fs'
import { VerdictBar, HostsPanel, NowPanel, UpdatesPanel, IntegrityPanel, LanguagesPanel,
         PendingPanel, GapsPanel } from './pane.mjs'

const read = (name, fallback) => {
  try { return JSON.parse(readFileSync(process.env.PREVIEW + '/preview-' + name + '.json', 'utf8')) }
  catch { return fallback }
}
const status = read('status', { hosts: {}, blind: [], note: '' })
const libraries = read('libraries', null)
const coverage = read('coverage', null)
const integrity = read('integrity', null)
const plan = read('plan', null)
const selected = Object.keys((status && status.hosts) || {})[0] || null
const noop = () => {}

const body = renderToStaticMarkup(createElement('div', {}, [
  createElement(VerdictBar, { key: 'v', status }),
  createElement(HostsPanel, { key: 'h', onChanged: noop, initialTest: null,
                              initialHosts: Object.entries((status && status.hosts) || {}).map(([label, entry]) => ({
                                label, target: (entry && entry.target) || 'local'
                              })) }),
  createElement(NowPanel, { key: 'n', status }),
  createElement(UpdatesPanel, { key: 'u', entry: selected ? status.hosts[selected] : null, hostLabel: selected }),
  createElement(IntegrityPanel, { key: 'i', reading: integrity, busy: false, seconds: 0,
                                  onRead: noop, onRebaseline: noop, onImport: noop }),
  createElement(LanguagesPanel, { key: 'l', libraries, onCheck: noop, busy: false }),
  createElement(PendingPanel, { key: 'p', hostLabel: selected, plan, onPlan: noop, limited: !selected,
                                planning: false, where: null, libraryFindings: 0 }),
  createElement(GapsPanel, { key: 'g', coverage, selected })
]))

writeFileSync(process.env.OUT, `<!doctype html><html><head><meta charset="utf-8">
<title>Patch Sentinel — preview</title><style>
:root{--foreground:#c9d6dd;--muted-foreground:#7f8d97;--accent:#4de3d0;--border:#22303a;--card:#0b1116}
body{margin:0;background:#0a0f13;color:var(--foreground);font-family:Inter,system-ui,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
</style></head><body><div class="wrap">${body}</div></body></html>`)
console.log('wrote', process.env.OUT)
JS
PREVIEW="$preview" OUT="$out" node render.mjs

chrome="$HOME/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome"
if [[ -x "$chrome" && -d "$app/node_modules/@playwright/test" ]]; then
  png="${out%.html}.png"
  cat > shot.cjs <<JS
const { chromium } = require('$app/node_modules/@playwright/test')
;(async () => {
  const browser = await chromium.launch({ executablePath: '$chrome' })
  const page = await browser.newPage({ viewport: { width: 1040, height: 1200 }, deviceScaleFactor: 2 })
  await page.goto('file://$out')
  await page.screenshot({ path: '$png', fullPage: true })
  await browser.close()
  console.log('wrote', '$png')
})()
JS
  node shot.cjs || echo "(png skipped — no chromium)"
fi

echo "· done: $out"
