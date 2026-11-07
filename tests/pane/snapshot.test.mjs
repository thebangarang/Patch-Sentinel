// Render the whole pane to a standalone HTML file so it can be looked at, not just asserted on.
// Uses the same stub data as the render checks; the app injects its own theme variables, so this file
// carries the ones the pane reads.
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { readFileSync, writeFileSync } from 'node:fs'
import { PatchSentinel } from './pane.mjs'

const data = JSON.parse(readFileSync(process.env.PANE_DATA || './pane-data.json', 'utf8'))
const body = renderToStaticMarkup(createElement(PatchSentinel, { compact: false }))

const html = `<!doctype html><html><head><meta charset="utf-8"><style>
:root{--foreground:#c9d6dd;--muted-foreground:#7f8d97;--accent:#4de3d0;--border:#22303a;--card:#0b1116}
body{margin:0;background:#0a0f13;color:var(--foreground);font-family:Inter,system-ui,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:22px}
</style></head><body><div class="wrap">${body}</div></body></html>`
writeFileSync(process.env.OUT || './pane.html', html)
console.log('wrote', html.length, 'bytes')
