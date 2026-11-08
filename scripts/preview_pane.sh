#!/usr/bin/env bash
# Render the real pane to one standalone HTML file, so the interface can be looked at on any machine —
# including one that has no Hermes desktop app. With a Chromium available it also writes a PNG.
#
#   ./scripts/preview_pane.sh          # runs the real "rescan all" (~90 s), then renders
#   ./scripts/preview_pane.sh --fast   # renders the bundle already on disk, no measuring
#
# It does not fake data: every number comes from the same handlers the pane reads, on this machine.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="${HERMES_DESKTOP_APP:-$HOME/.hermes/hermes-agent/apps/desktop}"
# Outside the repo on purpose: the payloads quote `sudo` commands, and the admission scan reads every
# file in the tree — a scratch payload in tmp/ once rated the whole plugin "dangerous".
preview="${PATCH_SENTINEL_PREVIEW:-${TMPDIR:-/tmp}/patch-sentinel-preview}"
out="$preview/pane-preview.html"
[[ "${1:-}" == "--fast" ]] && out="$preview/pane-preview-fast.html"
mkdir -p "$preview"

echo "· collecting the bundle the pane reads"
python3 - "$root" "$preview" "${1:-}" <<'PY'
import json
import sys

root, preview, mode = sys.argv[1], sys.argv[2], (sys.argv[3] if len(sys.argv) > 3 else "")
sys.path.insert(0, root)
from patch_sentinel import rescan, store, tools

tools.configure(store.load_settings() or {})
data_dir = str(tools._settings.get("data_dir") or store.data_dir())

if mode == "--fast":
    bundle = rescan.read(data_dir)
else:
    # per device: a preview is for the device named on the command line, or this machine
    host = next((a for a in sys.argv[4:] if not a.startswith("--")), "")
    bundle = json.loads(tools.cve_rescan({"host": host} if host else {})).get("bundle") or {}

with open(f"{preview}/bundle.json", "w") as handle:
    json.dump(bundle, handle)
print("  stages:", ", ".join(f"{s['name']} {s['seconds']}s" for s in bundle.get("stages") or []))
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
import { VerdictBar, HostsPanel, TodoPanel, CommandsPanel, IntegrityPanel, UpdatesPanel,
         LanguagesPanel, GapsPanel, HowItWorks } from './pane.mjs'

const bundle = JSON.parse(readFileSync(process.env.PREVIEW + '/bundle.json', 'utf8'))
const scan = bundle.scan || { hosts: {}, blind: [], note: '' }
const devices = bundle.devices || {}
const labels = Object.keys(devices).length ? Object.keys(devices) : Object.keys(scan.hosts || {})
const selected = process.env.PREVIEW_HOST || labels[0] || null
const entry = ((devices[selected] || {}).scan || {}).hosts || {}
const deviceEntry = entry[selected] || (scan.hosts || {})[selected] || null
const where = deviceEntry ? deviceEntry.where : null
const noop = () => {}

const device = ((bundle.devices || {})[selected]) || {}
const libraries = device.libraries || bundle.libraries
const integrity = device.integrity || bundle.integrity

const body = renderToStaticMarkup(createElement('div', {}, [
  createElement(HowItWorks, { key: 'how', open: process.env.PREVIEW_HOWTO !== 'closed', onToggle: noop }),
  createElement(VerdictBar, { key: 'v', status: { ...scan, hosts: selected ? { [selected]: deviceEntry || {} } : {} } }),
  createElement(HostsPanel, { key: 'h', onChanged: noop, initialHosts: labels.map((label) => ({
    label, target: (scan.hosts[label] || {}).target || 'local' })) }),
  createElement(UpdatesPanel, { key: 'u', entry: deviceEntry, hostLabel: selected }),
  createElement(IntegrityPanel, { key: 'i', reading: integrity, busy: false, seconds: 0,
                                  onRead: noop, onRebaseline: noop, onImport: noop }),
  createElement(LanguagesPanel, { key: 'l', libraries, onCheck: noop, busy: false }),
  createElement(TodoPanel, { key: 't', bundle, selected, onSelect: noop }),
  createElement(CommandsPanel, { key: 'c', bundle, selected, where }),
  createElement('div', { key: 'gaps', style: { marginTop: '38px', paddingTop: '16px' } },
    createElement(GapsPanel, { coverage: bundle.coverage || null, selected }))
]))

writeFileSync(process.env.OUT, `<!doctype html><html><head><meta charset="utf-8">
<title>Patch Sentinel — preview</title><style>
:root{--foreground:#c9d6dd;--muted-foreground:#7f8d97;--accent:#4de3d0;--border:#22303a;--card:#0b1116}
body{margin:0;background:#0a0f13;color:var(--foreground);font-family:Inter,system-ui,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
</style></head><body><div class="wrap">${body}</div></body></html>`)
console.log('wrote', process.env.OUT)
JS
PREVIEW="$preview" OUT="$out" PREVIEW_HOST="${2:-}" node render.mjs

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
