// The whole pane, rendered once — the check that the parts still form one flow.
//
// Two complaints came from this page and neither was visible panel-by-panel: APPLY read as the last
// step of the product (it refused after the click), and it duplicated the plan's own command block.
// So the page-level assertions are about *structure*: one flow, one place to copy the commands, and
// the optional shortcut folded under the plan it belongs to.
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { PatchSentinel } from './pane.mjs'

const html = renderToStaticMarkup(createElement(PatchSentinel, {}))
if (html.length < 500) throw new Error('the page rendered almost nothing')

// the shortcut exists, folds under the plan, and is not a section of its own
if (!html.includes('run it from here instead — optional')) throw new Error(
  'the optional apply shortcut is missing from the page')
if (html.includes('apply from here — optional')) throw new Error(
  'apply is a section again — it duplicates the plan')
if (!html.includes('the fix, as commands')) throw new Error('the plan is not titled as the fix')

// the plan comes before the shortcut, which comes before gaps: the order the work happens in.
// Last occurrence, because the legend at the top repeats every section title.
const planAt = html.lastIndexOf('the fix, as commands')
const shortcutAt = html.indexOf('run it from here instead — optional')
const gapsAt = html.lastIndexOf('gaps')
if (!(planAt < shortcutAt)) throw new Error('the apply shortcut is rendered before the plan')
if (!(shortcutAt < gapsAt)) throw new Error('the apply shortcut is rendered after the gaps')

// the animations are shipped with the page, and they respect a reduced-motion preference
if (!html.includes('ps-sweep')) throw new Error('the scanning keyframes are missing from the page')
if (!html.includes('prefers-reduced-motion')) throw new Error(
  'the scanning animation ignores a reduced-motion preference')
if (!html.includes('ps-scan-track')) throw new Error('the scanning line styles are missing')

// no second copy of the upgrade commands on a page whose plan is not open
if (html.split('sudo apt-get -y full-upgrade').length > 2) throw new Error(
  'the apply commands are duplicated on the page')

console.log('  the page reads plan -> optional shortcut -> gaps, with one command block (' + html.length + ' bytes)')
