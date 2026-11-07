// Renders every panel, including the states a user only reaches by clicking.
//
// This file exists because of a shipped crash: "add a host" threw `ReferenceError: target is not
// defined`, and the pane died on click. The reason it reached a user is that the panel had never been
// rendered anywhere — the SSR preview only mounted the six older panels, so the new component's code
// had never run. A component that is never rendered is a component that has never been tested.
//
// Both states of the server panel are rendered here: closed, and open.
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { readFileSync } from 'node:fs'
import { VerdictBar, HostsPanel, NowPanel, UpdatesPanel, LanguagesPanel, PendingPanel, GapsPanel,
         ApplyGate, PatchSentinel, SECTIONS } from './pane.mjs'

const dataPath = process.env.PANE_DATA || '../pane-data.json'
const data = JSON.parse(readFileSync(dataPath, 'utf8'))
const noop = () => {}

const panes = [
  ['servers (closed)', createElement(HostsPanel, { onChanged: noop })],
  ['servers (open)', createElement(HostsPanel, { onChanged: noop, startOpen: true })],
  ['now', createElement(NowPanel, { status: data.status, onRefresh: noop, busy: false })],
  ['updates', createElement(UpdatesPanel, { entry: data.status.hosts[data.hostLabel],
                                            hostLabel: data.hostLabel, onRescan: noop, busy: false })],
  ['libs', createElement(LanguagesPanel, { libraries: data.libraries, onCheck: noop, busy: false })],
  ['plan', createElement(PendingPanel, { hostLabel: data.hostLabel, plan: data.plan, onPlan: noop,
                                         limited: false, planning: false })],
  ['gaps', createElement(GapsPanel, { coverage: data.coverage, selected: data.hostLabel })],
  ['apply', createElement(ApplyGate, { hostLabel: data.hostLabel,
                                       entry: data.status.hosts[data.hostLabel] })]
]

// The three states that used to be unreachable in a check: a row that carries a finding (the code
// path that still called the old function name), the agent's own packages, and a clean machine.
const FIXTURE = {
  answer: 'read 5 package(s) from 2 store(s)',
  packages: [
    { ecosystem: 'PyPI', package: 'urllib3', version: '1.24.1', source: 'pip3', owner: 'machine',
      manager: { tool: 'pip3', path: '/opt/py/bin/pip3', upgrade: '{tool} install -U {spec}' } },
    { ecosystem: 'npm', package: 'lodash', version: '4.17.4', source: "npm's global tree",
      owner: 'machine',
      manager: { tool: 'npm', path: '/usr/bin/npm', upgrade: '{tool} install -g {spec}' } },
    { ecosystem: 'PyPI', package: 'filelock', version: '3.12.0', source: 'pip3', owner: 'hermes',
      manager: { tool: 'pip3', path: '/opt/py/bin/pip3', upgrade: null, owner: 'hermes',
                 why: "part of Hermes's own environment — upgraded by `hermes update`" } }
  ],
  threat: { kev_state: 'measured', kev_catalog: 1769, kev_count: 1,
            exploited: ['CVE-5000-1'], ransomware: ['CVE-5000-1'], scored: 3 },
  vulnerable: [
    { ecosystem: 'PyPI', package: 'urllib3', version: '1.24.1', id: 'CVE-5000-1',
      severity: 'high', fixed: ['1.26.5'], workaround: 'pin urllib3<2 in the embedding app',
      epss: 0.97, kev: { cves: ['CVE-5000-1'], name: 'fixture', added: '2026-01-01',
                          ransomware: true } },
    { ecosystem: 'npm', package: 'lodash', version: '4.17.4', id: 'CVE-5000-2',
      severity: 'critical', fixed: ['4.17.21'], workaround: null },
    { ecosystem: 'PyPI', package: 'filelock', version: '3.12.0', id: 'CVE-5000-3',
      severity: 'moderate', fixed: ['3.20.0'], workaround: null }
  ]
}

for (const [name, libraries] of [['libs (fixture: findings + agent-owned)', FIXTURE],
                                 ['libs (nothing read)', null]]) {
  const html = renderToStaticMarkup(createElement(LanguagesPanel, { libraries, onCheck: noop,
                                                                    busy: false }))
  if (html.length < 20) throw new Error(name + ' rendered nothing')
  if (libraries) {
    if (!html.includes('/opt/py/bin/pip3 install -U')) throw new Error('no resolved pip path in a row')
    if (!html.includes('npm install -g lodash@4.17.21')) throw new Error('no npm fix command')
    // React escapes the apostrophe in text nodes, so assert on the fragment before it
    if (!html.includes('belong to Hermes')) throw new Error('agent-owned block missing')
    // the chip text is lowercase in the DOM (CSS uppercases it)
    if (!html.includes('exploited · ransomware')) throw new Error('the exploited-in-the-wild chip is missing')
    if (!html.includes('epss 97')) throw new Error('the EPSS chip is missing')
    if (!html.includes('known-exploited list')) throw new Error('the KEV header line is missing')
    if (html.includes('/opt/py/bin/pip3 install -U \'filelock')) throw new Error(
      "the agent's own package was given a pip command")
  }
  console.log('  ' + name.padEnd(36) + html.length + ' bytes')
}

// The one-glance verdict: an exploited CVE must outrank everything else on that line.
const verdict = renderToStaticMarkup(createElement(VerdictBar, {
  status: {
    age_seconds: 120,
    threat: { exploited: ['CVE-2021-44228'] },
    blind: [{ class: 'images' }],
    hosts: {
      a: { pending_count: 4, kernel: { verdict: 'kernel-current' }, vendor_lag: [] },
      b: { pending_count: 0, kernel: { verdict: 'kernel-reboot-needed' }, vendor_lag: [{}, {}] }
    }
  }
}))
for (const expected of ['2 servers', '4 updates pending', '2 vendor-lag', '1 exploited',
                        '1 reboot needed', '1 could not look', 'measured']) {
  if (!verdict.includes(expected)) throw new Error('the verdict bar is missing: ' + expected)
}
console.log('  verdict bar names every fact, including the exploited one')

// The legend and the panels read from one array, in one order. This asserts it on the rendered page.
const root = renderToStaticMarkup(createElement(PatchSentinel, {}))
let cursor = -1
for (const section of SECTIONS) {
  // React escapes & as &amp; in text nodes
  const needle = '>' + section.title.replace(/&/g, '&amp;') + '<'
  // the LAST occurrence is the section heading (the first is the legend line), so this proves the
  // panels themselves follow the legend's order, not just that the legend is sorted
  const at = root.lastIndexOf(needle)
  if (at === -1) throw new Error('section "' + section.title + '" never appears on the page')
  if (at < cursor) throw new Error('section "' + section.title + '" is out of order')
  cursor = at
}
console.log('  legend and panels agree on ' + SECTIONS.length + ' sections, in order')

// One refresh control, at the top. Three panels used to carry their own "rescan" button doing the
// same work; the operator could not tell whether they differed.
const refreshButtons = (root.match(/>rescan all</g) || []).length
if (refreshButtons !== 1) {
  throw new Error('expected exactly one rescan control, found ' + refreshButtons)
}
if (root.includes('measuring…')) {
  throw new Error('a per-panel rescan button is still rendered')
}
console.log('  exactly one refresh control, in the header')

let bytes = 0
for (const [name, element] of panes) {
  const html = renderToStaticMarkup(element)
  if (!html || html.length < 20) throw new Error(name + ' rendered nothing')
  bytes += html.length
  console.log('  ' + name.padEnd(16) + html.length + ' bytes')
}
console.log('rendered ' + panes.length + ' panes, ' + bytes + ' bytes total')
