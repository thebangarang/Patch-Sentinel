// The whole pane, rendered once — the check that the parts still form one flow.
//
// History worth keeping: APPLY read as the last step of the product (it refused after the click), then
// it lived as a collapsed shortcut under the plan, and in the end it was removed from the pane
// altogether — on the machine Hermes runs on it could only ever refuse. These assertions are about
// *structure*: one flow, one place to copy the commands, and no control that promises to change a
// machine.
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { PatchSentinel } from './pane.mjs'

const html = renderToStaticMarkup(createElement(PatchSentinel, {}))
if (html.length < 500) throw new Error('the page rendered almost nothing')

if (!html.includes('the fix, as commands')) throw new Error('the plan is not titled as the fix')

// the pane offers no way to change a machine: commands only
for (const forbidden of ['run it from here instead', 'apply for real', 'apply — locked',
                         'apply from here']) {
  if (html.includes(forbidden)) throw new Error('the pane still offers an apply control: ' + forbidden)
}

// the commands come before the readings, and the gaps come last
const planAt = html.lastIndexOf('the fix, as commands')
const gapsAt = html.lastIndexOf('gaps')
if (!(planAt < gapsAt)) throw new Error('the commands section is rendered after the gaps')

// the animations are shipped with the page, and they respect a reduced-motion preference
if (!html.includes('ps-sweep')) throw new Error('the scanning keyframes are missing from the page')
if (!html.includes('prefers-reduced-motion')) throw new Error(
  'the scanning animation ignores a reduced-motion preference')
if (!html.includes('ps-scan-track')) throw new Error('the scanning line styles are missing')

// no second copy of the upgrade commands on a page whose plan is not open
if (html.split('sudo apt-get -y full-upgrade').length > 2) throw new Error(
  'the upgrade commands are duplicated on the page')

console.log('  the page reads commands -> readings -> gaps, with no apply control ('
  + html.length + ' bytes)')
