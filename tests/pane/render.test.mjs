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
import { VerdictBar, HostsPanel, TodoPanel, CommandsPanel, ScanButton, HowItWorks, UpdatesPanel,
         LanguagesPanel, IntegrityPanel,
         GapsPanel, PatchSentinel, SECTIONS } from './pane.mjs'

const dataPath = process.env.PANE_DATA || '../pane-data.json'
const data = JSON.parse(readFileSync(dataPath, 'utf8'))
const noop = () => {}

// The integrity reading: never read yet, a finished reading, and a finding. It renders real rows and
// must never print a clean bill of health — "no evidence of tampering in the surfaces read" is the
// strongest sentence this section is allowed to say.
const integrityFinding = {
  host: 'beelink', read_at: Math.floor(Date.now() / 1000) - 90,
  integrity: {
    state: 'finding', account: 'hermes', root: false,
    note: 'hermes: 14 packaged file(s) could not be read, so this check cannot see them — run it as root for the whole set',
    tamper: { state: 'finding', changed_count: 1, conffile_count: 2, missing_count: 0,
              unreadable_count: 14, changed: ['/usr/bin/ssh'] },
    preload: { state: 'ok', entries: [] },
    listeners: { state: 'finding', count: 36, new: ['tcp:4444'], baseline_count: 36 }
  },
  answers: [
    { check: 'package checksums', state: 'finding', detail: '1 file(s) changed, 2 conffile(s) edited by the operator', items: ['/usr/bin/ssh'] },
    { check: 'preload hook', state: 'ok', detail: '/etc/ld.so.preload is empty', items: [] },
    { check: 'listening sockets', state: 'finding', detail: '1 reachable from the network',
      items: ['tcp:4444 · reachable from the network · python'],
      advice: "Held by python (pid 77): `python -m http.server 4444`. If you did not start that, "
              + "look closer — `sudo ss -lntup | grep -F ':4444'` names the program and its pid. If you "
              + "did, re-baseline so these stop being new." }
  ],
  answer: 'integrity: 1 package-managed file(s) no longer match (or are gone) — first: /usr/bin/ssh'
}
const integrityHtml = renderToStaticMarkup(
  createElement(IntegrityPanel, { reading: integrityFinding, busy: false, seconds: 0,
                                  onRead: noop, onRebaseline: noop }))
if (!integrityHtml.includes('package checksums')) throw new Error('the integrity rows are missing')
if (!integrityHtml.includes('tcp:4444')) throw new Error('the new socket is not named')
if (!integrityHtml.includes('what this cannot see')) throw new Error('the limits toggle is missing')
// the finding must say what to do next, with a command that can be pasted
if (!integrityHtml.includes('If you did, re-baseline so these stop being new')) throw new Error(
  'the socket finding carries no advice')
if (!integrityHtml.includes('ss -lntup')) throw new Error('the advice names no command')
if (!integrityHtml.includes('could not be read')) throw new Error('the non-root caveat is missing')
if (integrityHtml.includes('not compromised<')) throw new Error('the panel claimed a host is not compromised')
// a local check animates inside its own section, never at the top of the page
const libsBusy = renderToStaticMarkup(
  createElement(LanguagesPanel, { libraries: data.libraries || data, onCheck: noop, busy: true }))
if (!libsBusy.includes('ps-scan-track')) throw new Error(
  'the libs check shows no progress line inside its section')
if (!libsBusy.includes('every project virtualenv')) throw new Error(
  'the libs progress line does not say what it is reading')

// the servers section renders its list from a fetch, so its device icons are verified in the
// standalone preview (scripts/preview_pane.sh) rather than here — an SSR render of that panel is
// always its empty state.

const integrityEmpty = renderToStaticMarkup(
  createElement(IntegrityPanel, { reading: null, busy: false, seconds: 0, onRead: noop, onRebaseline: noop }))
if (!integrityEmpty.includes('read it')) throw new Error('the not-read-yet state has no button')

const panes = [
  ['servers (closed)', createElement(HostsPanel, { onChanged: noop })],
  ['servers (open)', createElement(HostsPanel, { onChanged: noop, startOpen: true })],
  ['what must be done', createElement(TodoPanel, { bundle: { scan: data.status },
                                                    selected: data.hostLabel, onSelect: noop })],
  ['updates', createElement(UpdatesPanel, { entry: data.status.hosts[data.hostLabel],
                                            hostLabel: data.hostLabel, onRescan: noop, busy: false })],
  ['libs', createElement(LanguagesPanel, { libraries: data.libraries, onCheck: noop, busy: false })],
  ['the fix, as commands', createElement(CommandsPanel, {
    bundle: { scan: data.status, plans: { plans: { [data.hostLabel]: data.plan } } },
    selected: data.hostLabel, where: null })],
  ['gaps', createElement(GapsPanel, { coverage: data.coverage, selected: data.hostLabel })]
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
const now = renderToStaticMarkup(createElement(TodoPanel, {
  bundle: { scan: { hosts: {
    beelink: { label: 'beelink', target: 'local', adapter: 'apt', pending_count: 0,
               measured_at: '2026-11-08T10:00:00Z',
               os: { id: 'ubuntu', codename: 'resolute' }, status: { exit_code: 0 } },
    nas: { label: 'nas', target: 'root@192.168.1.20:22', adapter: 'apt', pending_count: 2,
           os: { id: 'debian', codename: 'bookworm' }, status: { exit_code: 1 } },
    vps: { label: 'vps', target: 'root@203.0.113.9', adapter: 'apt', pending_count: 0,
           os: { id: 'ubuntu', codename: 'noble' }, status: { exit_code: 0 } }
  }, blind: [], note: '' } }, selected: null, onSelect: noop }))   // null = every device, for the icon test
if ((now.match(/<svg/g) || []).length < 3) throw new Error('a server row has no device icon')
if (!now.includes('the machine Hermes runs on')) throw new Error('the hermes machine icon is missing')
if (!now.includes('a server on the local network')) throw new Error('the LAN server icon is missing')
if (!now.includes('a remote server')) throw new Error('the remote server icon is missing')
// a measured_at arrives as an ISO string here and as an epoch second from the integrity reading;
// the first shape once rendered as "NaN d ago"
if (now.includes('NaN')) throw new Error('an ISO timestamp rendered as NaN')

// The verdict line used to say "measured never measured" when it was handed a bundle (no
// age_seconds) instead of the /status route. It must fall back to the newest measured_at.
const verdictFromBundle = renderToStaticMarkup(createElement(VerdictBar, {
  status: { hosts: { beelink: { label: 'beelink', measured_at: new Date().toISOString() } },
            blind: [], note: '' }
}))
if (verdictFromBundle.includes('never measured')) {
  throw new Error('a bundle without age_seconds printed "measured never measured"')
}
if (!/measured (just now|[0-9]+ min ago)/.test(verdictFromBundle)) {
  throw new Error('the verdict line carries no age at all')
}

// The bundle is written stage by stage, so the pane renders partial shapes while a scan runs. A
// devices-only bundle (no `scan` key yet) crashed the whole page on `bundle.scan.hosts` when the scan
// started — every section must render from any of these.
const PARTIALS = [
  ['empty', {}],
  // a plan with a step on purpose: the command block is what read `bundle.scan.hosts` unguarded
  ['devices only (mid-run)', { devices: { beelink: {
    libraries: FIXTURE, integrity: null, scan: null, measured_at: null,
    plan: { steps: [{ action: 'Upgrade bash', command: 'sudo apt-get install bash',
                      risk: 'low', downtime: 'none', why: 'CVE-2014-6271', verify: 'apt-cache policy bash',
                      reversal: 'see /var/log/apt/history.log' }] } } } }],
  ['devices with a scan', { devices: { beelink: { scan: { hosts: { beelink: { label: 'beelink' } } } } } }],
  // the shape the previous release wrote (one fleet-wide scan): a user who upgrades without scanning
  // must still get a readable pane
  ['fleet bundle (previous release)', {
    scan: { hosts: { beelink: { label: 'beelink', target: 'local', pending_count: 0 } }, blind: [], note: '' },
    libraries: FIXTURE,
    plans: { plans: { beelink: { steps: [{ action: 'a', command: 'sudo apt-get install bash',
                                           risk: 'low', downtime: 'none', why: 'w', verify: 'v', reversal: 'r' }] } } }
  }]
]
for (const [name, bundle] of PARTIALS) {
  for (const [section, element] of [
    ['what must be done', createElement(TodoPanel, { bundle, selected: 'beelink', onSelect: noop })],
    ['the fix, as commands', createElement(CommandsPanel, { bundle, selected: 'beelink', where: null })],
    ['servers', createElement(HostsPanel, { onChanged: noop, bundle, initialHosts: [{ label: 'beelink', target: 'local' }] })]
  ]) {
    try {
      renderToStaticMarkup(element)
    } catch (err) {
      throw new Error(section + ' crashed on a ' + name + ' bundle: ' + err.message)
    }
  }
}
console.log('  every section renders from a partial bundle')

// The button must name the device that will be measured, and while running, the device being measured.
// It said "measuring beelink" with webasix selected, twice.
const idle = renderToStaticMarkup(createElement(ScanButton, {
  selected: 'webasix', busy: false, stage: null, currentHost: null, seconds: 0, onClick: noop }))
if (!idle.includes('scan all · webasix')) throw new Error('the idle button does not name the device: ' + idle)
const running = renderToStaticMarkup(createElement(ScanButton, {
  selected: 'webasix', busy: true, stage: 'integrity', currentHost: 'webasix', seconds: 12, onClick: noop }))
if (!running.includes('integrity · webasix')) throw new Error('the running button names another device: ' + running)
if (running.includes('beelink')) throw new Error('the running button shows a device that was not asked for')
console.log('  the scan button names the device it will measure')

// A first-time user must not need the repository: the pane carries the four steps, and the same verb
// for the same action in both panels (it used to say "read again" in one and "re-check" in the other).
const howto = renderToStaticMarkup(createElement(HowItWorks, { open: true, onToggle: noop }))
for (const phrase of ['pick a device', 'press scan all', 'read what must be done', 'copy the commands',
                      'never calls a machine clean', 'No credential is stored']) {
  if (!howto.includes(phrase)) throw new Error('the how-to is missing: ' + phrase)
}
const howtoClosed = renderToStaticMarkup(createElement(HowItWorks, { open: false, onToggle: noop }))
if (howtoClosed.includes('press scan all')) throw new Error('the closed how-to still renders its steps')
if (!howtoClosed.includes('how this works')) throw new Error('the closed how-to has no way back in')

const neverRead = renderToStaticMarkup(createElement(IntegrityPanel, {
  reading: null, busy: false, seconds: 0, onRead: noop, onRebaseline: noop }))
if (!neverRead.includes('read it')) throw new Error('the integrity panel does not offer a first read')
if (neverRead.includes('read again')) throw new Error('the integrity panel offers a re-read before a read')
const libsNever = renderToStaticMarkup(createElement(LanguagesPanel, { libraries: null, onCheck: noop,
                                                                     busy: false }))
if (!libsNever.includes('read it')) throw new Error('the libs panel does not use the same verb as integrity')
console.log('  the how-to is in the pane, and both panels use the same verb')

// Every section shows its own sweep while its stage runs, so the operator can see where the run is —
// the top line is the run, these are the parts.
const bundleForScan = { scan: data.status, plans: { plans: { [data.hostLabel]: data.plan } },
                        devices: {} }
for (const [name, element] of [
  ['system packages', createElement(UpdatesPanel, {
    entry: data.status.hosts[data.hostLabel], hostLabel: data.hostLabel, scanning: true })],
  ['libs & runtimes', createElement(LanguagesPanel, {
    libraries: FIXTURE, onCheck: noop, busy: false, scanning: true })],
  ['the fix, as commands', createElement(CommandsPanel, {
    bundle: bundleForScan, selected: data.hostLabel, where: null, scanning: true })]
]) {
  const html = renderToStaticMarkup(element)
  if (!html.includes('ps-scan-track')) throw new Error(name + ' shows no progress while its stage runs')
}
for (const [name, element] of [
  ['system packages', createElement(UpdatesPanel, {
    entry: data.status.hosts[data.hostLabel], hostLabel: data.hostLabel, scanning: false })],
  ['libs & runtimes', createElement(LanguagesPanel, {
    libraries: FIXTURE, onCheck: noop, busy: false, scanning: false })]
]) {
  if (renderToStaticMarkup(element).includes('ps-scan-track')) {
    throw new Error(name + ' animates when nothing is running')
  }
}
console.log('  every section animates while its own stage runs, and only then')

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
    if (!html.includes('hermes update') || !html.includes('not counted above')) throw new Error(
      'the summary does not say the agent packages are excluded')
    if (html.includes('ship with Hermes')) throw new Error(
      'the agent packages are mentioned although nothing there is exploited')
    if (html.includes('0 not yet')) throw new Error('the agent-package advisory paragraph is back')
    // the chip text is lowercase in the DOM (CSS uppercases it)
    if (!html.includes('exploited · ransomware')) throw new Error('the exploited-in-the-wild chip is missing')
    if (!html.includes('epss 97')) throw new Error('the EPSS chip is missing')
    // the summary is a labelled list now, one fact per line — not a paragraph
    if (!html.includes('ADVISORIES') && !html.includes('advisories')) throw new Error(
      'the advisories line is missing')
    if (!/\d+ on \d+ package\(s\)/.test(html)) throw new Error(
      'the advisories line does not say how many findings sit on how many packages')
    if (!html.includes('known-exploited list')) throw new Error('the KEV header line is missing')
    if (!html.includes('project: /tmp/demo-project')) throw new Error('project scope is not shown')
    if (!html.includes('machine-wide')) throw new Error('the way back to machine scope is missing')
    if (html.includes('/opt/py/bin/pip3 install -U \'filelock')) throw new Error(
      "the agent's own package was given a pip command")
  }
  console.log('  ' + name.padEnd(36) + html.length + ' bytes')
}

// The pane has no APPLY control: every device is patched from its own terminal, and the commands
// section is the only place a machine change is offered. The gated tool stays for the agent.
const paneSource = readFileSync(new URL('./pane.mjs', import.meta.url), 'utf8')
if (/run it from here instead/i.test(paneSource)) {
  throw new Error('the pane still offers the apply shortcut')
}
if (/apply for real|apply — locked/.test(paneSource)) {
  throw new Error('the pane still renders an apply control')
}

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
console.log('  no apply control in the pane; gaps render as designed')

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

// The legend and the sections read from one array, in one order. The full page renders without data
// (it fetches in an effect, which a server render never runs), so the order is asserted on the legend
// line — and each section is rendered with its own fixture further up, which proves it carries its title.
const root = renderToStaticMarkup(createElement(PatchSentinel, {}))
const legendLine = SECTIONS.map((section) => section.title).join('  →  ')
if (!root.includes(legendLine.replace(/&/g, '&amp;'))) {
  throw new Error('the legend does not list the sections in order: ' + legendLine)
}
for (const section of SECTIONS) {
  if (!root.includes(section.title.replace(/&/g, '&amp;'))) {
    throw new Error('section "' + section.title + '" is not named anywhere')
  }
}
console.log('  legend names all ' + SECTIONS.length + ' sections, in order')

// One refresh control, at the top, and it names the device it will measure. Three panels used to carry
// their own "rescan" button doing the same work; the operator could not tell whether they differed.
const refreshButtons = (root.match(/>scan all</g) || []).length
if (refreshButtons !== 1) {
  throw new Error('expected exactly one scan control, found ' + refreshButtons)
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
