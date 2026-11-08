// The whole pane, rendered once — the check that the parts still form one flow.
//
// History worth keeping: APPLY read as the last step of the product (it refused after the click), then
// it lived as a collapsed shortcut under the plan, and in the end it was removed from the pane
// altogether — on the machine Hermes runs on it could only ever refuse. These assertions are about
// *structure*: one flow, one place to copy the commands, and no control that promises to change a
// machine.
//
// The order is asserted against the source, not only against a rendered string: the bug this guards
// against is the page drawing its sections in a different order from the scan reading them (the scan
// walked packages → language stack → integrity while the page drew packages → integrity → language
// stack), which no amount of rendering a single string catches.
import { readFileSync } from 'node:fs'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { PatchSentinel } from './pane.mjs'

const paneSource = readFileSync(new URL('./pane.mjs', import.meta.url), 'utf8')
const html = renderToStaticMarkup(createElement(PatchSentinel, {}))
if (html.length < 500) throw new Error('the page rendered almost nothing')

// 1. the sections are declared in the order a reader follows them
const sectionsBlock = paneSource.slice(paneSource.indexOf('const SECTIONS = ['))
const declared = [...sectionsBlock.slice(0, sectionsBlock.indexOf('\n]\n'))
  .matchAll(/\{ key: '([a-z]+)'/g)].map((match) => match[1])
const wanted = ['servers', 'packages', 'integrity', 'libs', 'gaps', 'todo', 'plan']
if (declared.join(',') !== wanted.join(',')) {
  throw new Error('the sections are declared out of order: ' + declared.join(' -> '))
}

// 2. the page draws them in that same order — the readings first, then the answer, then the commands
const drawn = ['UpdatesPanel', 'IntegrityPanel', 'LanguagesPanel', 'GapsPanel', 'TodoPanel',
               'CommandsPanel']
let previous = -1
for (const component of drawn) {
  const at = paneSource.indexOf('jsx(' + component)
  if (at < 0) throw new Error('the page never draws ' + component)
  if (at < previous) throw new Error('the page draws ' + component + ' out of order')
  previous = at
}

// 3. the pane offers no way to change a machine: commands only
for (const forbidden of ['run it from here instead', 'apply for real', 'apply — locked',
                         'apply from here', 'ApplyGate']) {
  if (paneSource.includes(forbidden)) {
    throw new Error('the pane still offers an apply control: ' + forbidden)
  }
}
if (!paneSource.includes("title: 'the fix commands'")) {
  throw new Error('the commands section is not titled "the fix commands"')
}

// 4. the animations are shipped with the page, and respect a reduced-motion preference
if (!html.includes('ps-sweep')) throw new Error('the scanning keyframes are missing from the page')
if (!html.includes('prefers-reduced-motion')) throw new Error(
  'the scanning animation ignores a reduced-motion preference')
if (!html.includes('ps-scan-track')) throw new Error('the scanning line styles are missing')

// 5. no second copy of the upgrade commands on a page whose plan is not open
if (html.split('sudo apt-get -y full-upgrade').length > 2) throw new Error(
  'the upgrade commands are duplicated on the page')

console.log('  the page reads servers -> readings -> gaps -> to do -> commands, drawn in declared '
  + 'order, with no apply control (' + html.length + ' bytes)')
