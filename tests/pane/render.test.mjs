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
  scope: 'project',
  project: { root: '/tmp/demo-project', files: { 'api/requirements.txt': 'read: 2 package(s)' } },
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

// The copy control on the system-package list must hand over something a shell can run.
const updates = renderToStaticMarkup(createElement(UpdatesPanel, {
  entry: { pending: [{ package: 'openssl', from: '3.0.1', to: '3.0.2' }], pending_count: 1,
           measured_at: '2026-11-07T10:00:00Z',
           commands: { stage: 'sudo apt-get update && sudo apt-get -y --download-only full-upgrade',
                       apply: 'sudo apt-get -y full-upgrade' },
           where: { kind: 'remote', machine: 'debian@10.0.0.9', how: 'on debian@10.0.0.9, in a terminal there',
                    ssh: 'ssh -p 2223 debian@10.0.0.9' } },
  hostLabel: 'debian-lab'
}))
if (!updates.includes('copy the commands')) throw new Error('the package list has no command copy control')
if (!updates.includes('run them on debian@10.0.0.9')) throw new Error('the package list does not say where')
if (!updates.includes('ssh -p 2223 debian@10.0.0.9')) throw new Error('the ssh line is missing from the update panel')

// An exploited advisory inside Hermes's own environment is worth one line — it is a fact about this
// machine, even though the only lever is `hermes update`.
const AGENT_EXPLOITED = JSON.parse(JSON.stringify(FIXTURE))
AGENT_EXPLOITED.vulnerable = AGENT_EXPLOITED.vulnerable.map((v) => (v.package === 'filelock'
  ? { ...v, kev: { cves: ['CVE-5000-3'], name: 'fixture', added: '2026-01-01', ransomware: false } }
  : v))
const agentExploited = renderToStaticMarkup(createElement(LanguagesPanel, {
  libraries: AGENT_EXPLOITED, onCheck: noop, busy: false }))
if (!agentExploited.includes('sit in packages Hermes itself ships')) throw new Error(
  'an exploited advisory in the agent env is not named')
if (!agentExploited.includes('hermes update')) throw new Error('the agent lever is not stated')

// Every server row carries a device shape: the machine Hermes runs on, a LAN server, a remote host.
const now = renderToStaticMarkup(createElement(NowPanel, {
  status: { hosts: {
    beelink: { label: 'beelink', target: 'local', adapter: 'apt', pending_count: 0,
               os: { id: 'ubuntu', codename: 'resolute' }, status: { exit_code: 0 } },
    nas: { label: 'nas', target: 'root@192.168.1.20:22', adapter: 'apt', pending_count: 2,
           os: { id: 'debian', codename: 'bookworm' }, status: { exit_code: 1 } },
    vps: { label: 'vps', target: 'root@203.0.113.9', adapter: 'apt', pending_count: 0,
           os: { id: 'ubuntu', codename: 'noble' }, status: { exit_code: 0 } }
  }, blind: [], note: '' }, onRefresh: noop, busy: false }))
if ((now.match(/<svg/g) || []).length < 3) throw new Error('a server row has no device icon')
if (!now.includes('the machine Hermes runs on')) throw new Error('the hermes machine icon is missing')
if (!now.includes('a server on the local network')) throw new Error('the LAN server icon is missing')
if (!now.includes('a remote server')) throw new Error('the remote server icon is missing')

for (const [name, libraries] of [['libs (fixture: findings + agent-owned)', FIXTURE],
                                 ['libs (nothing read)', null]]) {
  const html = renderToStaticMarkup(createElement(LanguagesPanel, { libraries, onCheck: noop,
                                                                    busy: false }))
  if (html.length < 20) throw new Error(name + ' rendered nothing')
  if (libraries) {
    if (!html.includes('/opt/py/bin/pip3 install -U')) throw new Error('no resolved pip path in a row')
    if (!html.includes('npm install -g lodash@4.17.21')) throw new Error('no npm fix command')
    // React escapes the apostrophe in text nodes, so assert on the fragment before it
    // Hermes's own packages are measured and then dropped: no count, no paragraph, nothing at all
    // unless one of them is being exploited (the fixture's agent package is not)
    // the *header* must not count the agent's packages. The breakdown line below it may name them —
    // that is the point of the breakdown — so the assertion is scoped to the header.
    const headerAt = html.indexOf('libs &amp; runtimes')
    const header = html.slice(headerAt, headerAt + 220)
    if (header.includes('Hermes')) throw new Error(
      "the agent packages are counted in the libs header again: " + header)
    if (!html.includes('in Hermes&#x27;s env (not counted)')) throw new Error(
      'the breakdown line does not say the agent packages are excluded')
    if (html.includes('ship with Hermes')) throw new Error(
      'the agent packages are mentioned although nothing there is exploited')
    if (html.includes('0 not yet')) throw new Error('the agent-package advisory paragraph is back')
    // the chip text is lowercase in the DOM (CSS uppercases it)
    if (!html.includes('exploited · ransomware')) throw new Error('the exploited-in-the-wild chip is missing')
    if (!html.includes('epss 97')) throw new Error('the EPSS chip is missing')
    // a finding whose fix nobody published gets no arrow and no comment-formatted "command"
    if (!html.includes('1 finding(s) on 2 package(s)')) {
      // the fixture has two packages with findings; the count line must reflect that
      if (!/\d+ finding\(s\) on \d+ package\(s\)/.test(html)) throw new Error(
        'the findings/packages count line is missing')
    }
    if (!html.includes('known-exploited list')) throw new Error('the KEV header line is missing')
    if (!html.includes('project: /tmp/demo-project')) throw new Error('project scope is not shown')
    if (!html.includes('machine-wide')) throw new Error('the way back to machine scope is missing')
    if (html.includes('/opt/py/bin/pip3 install -U \'filelock')) throw new Error(
      "the agent's own package was given a pip command")
  }
  console.log('  ' + name.padEnd(36) + html.length + ' bytes')
}

// The apply gate's refusal must hand over the commands, and gaps must read as a short list first.
const refused = renderToStaticMarkup(createElement(ApplyGate, {
  hostLabel: 'beelink',
  entry: { pending_count: 3, adapter: 'apt' },
  initialResult: { applied: false, dry_run: false, steps: [],
                   reason: 'this user cannot run sudo without a password on that host',
                   handoff: { commands: ['sudo apt-get update && sudo apt-get -y --download-only full-upgrade',
                                         'sudo apt-get -y full-upgrade'],
                              note: 'run these in this order',
                              verify: "apt-get -s dist-upgrade | grep '^Inst '",
                              reversal: 're-install the recorded versions',
                              where: { kind: 'remote',
                                       how: 'on debian@10.0.0.9, in a terminal there',
                                       ssh: 'ssh -p 2223 debian@10.0.0.9' } } }
}))
if (!refused.includes('run it yourself')) throw new Error('the handoff block is missing')
if (!refused.includes('apt-get -y full-upgrade')) throw new Error('the handoff commands are missing')
if (!refused.includes('copy both')) throw new Error('the handoff copy control is missing')
// the apply control must not look ready before the host has said it allows it
if (!refused.includes('apply — locked') && !refused.includes('apply for real')) throw new Error(
  'the apply button has no locked/unlocked label')
if (!refused.includes('connect: ssh -p 2223 debian@10.0.0.9')) throw new Error('the handoff does not say where')
if (!refused.includes('then check: apt-get -s dist-upgrade')) throw new Error('the verify command is missing')

const gaps = renderToStaticMarkup(createElement(GapsPanel, {
  selected: 'beelink',
  coverage: { gaps: [
    { gap: 'docker socket refused', kind: 'blocked', state: 'unreadable',
      why: 'the daemon refused the request', next: 'add the user to the docker group' },
    { gap: 'in-image CVEs', kind: 'limit', state: 'not measured', why: 'STRUCTURAL-DETAIL',
      next: 'needs an image scanner' },
    { gap: 'project lockfiles', kind: 'limit', state: 'not measured', why: 'SECOND-DETAIL' }
  ] }
}))
if (!gaps.includes('1 fixable')) throw new Error('the fixable count is missing')
if (!gaps.includes('2 inherent limits')) throw new Error('the inherent-limit count is missing')
if (!gaps.includes('explain them')) throw new Error('the detail toggle is missing')
if (gaps.includes('STRUCTURAL-DETAIL')) throw new Error('inherent limits must start collapsed')
if (!gaps.includes('add the user to the docker group')) throw new Error('a fixable gap must show its fix')
console.log('  apply handoff and collapsed gaps render as designed')

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
