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
import { PatchSentinel, UpdatesPanel, LanguagesPanel } from './pane.mjs'

const noop = () => {}

const paneSource = readFileSync(new URL('./pane.mjs', import.meta.url), 'utf8')
const html = renderToStaticMarkup(createElement(PatchSentinel, {}))
if (html.length < 500) throw new Error('the page rendered almost nothing')

// 1. the sections are declared in the order a reader follows them
const sectionsBlock = paneSource.slice(paneSource.indexOf('const SECTIONS = ['))
const declared = [...sectionsBlock.slice(0, sectionsBlock.indexOf('\n]\n'))
  .matchAll(/\{ key: '([a-z]+)'/g)].map((match) => match[1])
// gaps last: it is a caveat, and between the readings and the commands it pushed the commands off
// the screen of the operator who then had to scroll past a passive section to reach them
const wanted = ['servers', 'packages', 'integrity', 'libs', 'todo', 'plan', 'gaps']
if (declared.join(',') !== wanted.join(',')) {
  throw new Error('the sections are declared out of order: ' + declared.join(' -> '))
}

// 2. the page draws them in that same order — the readings first, then the answer, then the commands
const drawn = ['UpdatesPanel', 'IntegrityPanel', 'LanguagesPanel', 'TodoPanel', 'CommandsPanel',
               'GapsPanel']
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

// 3b. a section's read control is busy when *its* stage of a scan is the one reading, not only when
// the operator pressed it. The operator reported the opposite: "integrity animates, the other two do
// not" — because only integrity's control was tied to the scan stage at all.
for (const marker of ["busy: pkgBusy || (busy && stage === 'scan')",
                      "busy: integrityBusy || (busy && stage === 'integrity')",
                      "busy: libBusy || (busy && stage === 'libraries')"]) {
  if (!paneSource.includes(marker)) {
    throw new Error('a section\'s read control ignores the scan stage: expected ' + marker)
  }
}

// 4. the animations are shipped with the page, and respect a reduced-motion preference
if (!html.includes('ps-sweep')) throw new Error('the scanning keyframes are missing from the page')
if (!html.includes('prefers-reduced-motion')) throw new Error(
  'the scanning animation ignores a reduced-motion preference')
if (!html.includes('ps-scan-track')) throw new Error('the scanning line styles are missing')

// 5. no second copy of the upgrade commands on a page whose plan is not open
if (html.split('sudo apt-get -y full-upgrade').length > 2) throw new Error(
  'the upgrade commands are duplicated on the page')

// 6. gaps is set apart from the flow: the sections above are the scan, this is a note about it
const gapsWrap = paneSource.indexOf('marginTop: \'38px\'')
if (gapsWrap < 0) throw new Error('gaps is not visually separated from the scan flow')

// 7. two sweeps on the page are at the same point of the same wave — the phase comes from the clock,
// not from when each one mounted, which is what makes the header line and a section line look like one
// wave crossing the page
const phaseOf = (element) => {
  const match = renderToStaticMarkup(element).match(/--ps-phase:\s*(-?\d+)ms/)
  return match ? Number(match[1]) : null
}
// The phase must be taken once per mount. Recomputing it on each render looks equivalent and is not:
// writing a new animation-delay onto a running animation moves it, so a pane that polls once a second
// shoved the header line to a different point of the sweep than the section line. Measured in Chromium
// with two tracks, one re-rendered every 200 ms: frozen phases stayed together (fraction 1.020 vs
// 1.018 of their own width), a recomputed phase fell behind (0.232).
if (!paneSource.includes('const phase = useMemo(')) {
  throw new Error('the sweep phase is recomputed on every render, which desynchronises the lines')
}
if (!paneSource.includes('animation: ps-sweep ${SCAN_PERIOD}ms')) {
  throw new Error('the stylesheet and the phase calculation do not share one period')
}
const phaseA = phaseOf(createElement(UpdatesPanel, { entry: null, hostLabel: 'beelink',
                                                     scanning: true }))
const phaseB = phaseOf(createElement(LanguagesPanel, { libraries: null, onCheck: noop,
                                                       busy: true, scanning: true }))
if (phaseA === null || phaseB === null) throw new Error('a sweep carries no phase')
if (!(phaseA <= 0 && phaseA > -1150)) throw new Error('a sweep phase is outside one period: ' + phaseA)
if (Math.abs(phaseA - phaseB) > 30) {
  throw new Error('two sweeps are out of phase: ' + phaseA + ' vs ' + phaseB)
}

console.log('  the page reads servers -> readings -> to do -> commands -> gaps, drawn in declared '
  + 'order, sweeps phase-locked, with no apply control (' + html.length + ' bytes)')
