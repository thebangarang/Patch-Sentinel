/**
 * Patch Sentinel — desktop half (the pane).
 *
 * Three panels, in this order, because that is the order a person needs them:
 *   NOW      what answered, for which host, and how old the measurement is
 *   PENDING  the ranked plan — command, risk, downtime, verify, reversal — with a copy control
 *   GAPS     what could not be looked at. This panel is never green and never empty.
 *
 * Loaded uncompiled by Hermes Desktop: plain ESM, UI written as jsx()/jsxs() calls, imports
 * limited to @hermes/plugin-sdk, react and react/jsx-runtime.
 *
 * The colour rule is the product's honesty layer, made visible: green means every check on that
 * host answered AND nothing is pending. Anything unmeasured is grey; anything blind is red. A
 * pane that shows green because it has no data is the failure this plugin exists to prevent.
 */

import { host } from '@hermes/plugin-sdk'
import * as sdk from '@hermes/plugin-sdk'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { jsx as hostJsx } from 'react/jsx-runtime'

// The automatic runtime's third argument to jsx()/jsxs() is the KEY, not the children — pass a
// child there and React renders the element with nothing inside it, which is a silently empty
// pane. These two thin adapters take children as the third argument (and lift `key` out of the
// props, where the runtime wants it), so the call sites below read the way JSX would have.
function element(type, props, children) {
  const raw = props || {}
  const next = { ...raw }
  const key = next.key
  delete next.key
  if (children !== undefined) {
    // Array children are a list: give each element a stable key so React does not warn on every
    // render. Rebuilding through the runtime is the only way to set a key on an existing element.
    next.children = Array.isArray(children)
      ? children.map((child, index) =>
          child && child.$$typeof && child.key == null
            ? hostJsx(child.type, { ...child.props }, 'k' + index)
            : child)
      : children
  }
  return key === undefined ? hostJsx(type, next) : hostJsx(type, next, key)
}

const jsx = (type, props, ...kids) =>
  element(type, props, kids.length === 0 ? undefined : kids.length === 1 ? kids[0] : kids)

const jsxs = jsx

const ID = 'patch-sentinel'
const ROUTE = '/patch-sentinel'

let REST = null

// Theme tokens first, HUD accents second: the app paints the surface, we only tint the data.
const C = {
  text: 'var(--ui-text-primary, var(--foreground, inherit))',
  dim: 'var(--ui-text-secondary, var(--muted-foreground, #888))',
  faint: 'var(--ui-text-tertiary, #777)',
  accent: 'var(--ui-accent, #35d6d6)',
  border: 'var(--ui-stroke-secondary, rgba(128,128,128,0.32))',
  panel: 'var(--ui-surface-secondary, rgba(128,128,128,0.06))',
  danger: 'var(--ui-danger, #d92d20)',
  warn: 'var(--ui-warning, #b54708)',
  ok: 'var(--ui-success, #067647)'
}

const MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace'

function call(path, options) {
  if (!REST) return Promise.reject(new Error('the pane is not attached to the plugin route'))
  return REST(path, options)
}

/** A sentence with `a command` in it, rendered so the command is what you would paste. */
function withCode(text) {
  return String(text || '').split('`').map((part, index) => (
    index % 2
      ? jsx('span', { key: index, style: { fontFamily: MONO, color: C.accent } }, part)
      : jsx('span', { key: index }, part)
  ))
}

/** `read_at` is an epoch second, `ago` takes an age. Mixing them printed "20765 d ago". */
function agoAt(epoch) {
  if (!epoch) return null
  return ago(Math.max(0, Math.floor(Date.now() / 1000 - epoch)))
}

function ago(seconds) {
  if (seconds === null || seconds === undefined) return 'never measured'
  if (seconds < 90) return 'just now'
  if (seconds < 3600) return Math.round(seconds / 60) + ' min ago'
  if (seconds < 86400) return Math.round(seconds / 3600) + ' h ago'
  return Math.round(seconds / 86400) + ' d ago'
}

/** The one rule the colours mean. Returns {level, why}. */
function stateOf(entry) {
  if (!entry) return { level: 'grey', why: 'not measured' }
  const outcomes = entry.outcomes || {}
  const blind = Object.entries(outcomes).filter(([, v]) => v === 'unmeasured' || v === 'unreadable' || v === 'refused')
  const kernel = (entry.kernel || {}).verdict
  const pending = entry.pending_count || 0
  const lag = (entry.vendor_lag || []).length
  if (blind.length) {
    return { level: 'red', why: blind.map(([k, v]) => k + ': ' + v).join(', ') }
  }
  if (lag) {
    return { level: 'amber', why: lag + ' fix(es) exist upstream but not in this archive' }
  }
  if (pending > 0 || (kernel && kernel !== 'kernel-current' && kernel !== 'kernel-unknown')) {
    return { level: 'amber', why: pending + ' pending, kernel ' + (kernel || '?') }
  }
  if (kernel === 'kernel-unknown') return { level: 'grey', why: 'kernel not measurable here' }
  return { level: 'green', why: 'every check answered, nothing pending' }
}

const LEVEL_COLOUR = { green: C.ok, amber: C.warn, red: C.danger, grey: C.faint }

/**
 * One ordered list, used twice: the legend at the top and the title of each section below. Keeping
 * them in a single array is what stops the legend from describing an order the pane does not use —
 * which is exactly what happened when the legend was six hand-written lines and the pane gained a
 * seventh panel above them.
 */
const SECTIONS = [
  { key: 'servers', title: 'servers',
    blurb: 'the machines this pane answers for (this one included). A server is added only after a '
         + 'probe of it succeeds; addresses only, never a key.' },
  { key: 'overview', title: 'overview',
    blurb: 'one row per server: what the last scan measured, and how old that measurement is.' },
  { key: 'packages', title: 'system packages',
    blurb: "the distro's own update list (apt, dnf, pacman, zypper), every package it would upgrade." },
  { key: 'integrity', title: 'integrity',
    blurb: 'is this host still running what was installed on it? Package checksums, the preload hook '
         + 'and the listening sockets compared with the baseline this plugin recorded. A patch scanner '
         + 'reads versions; an intrusion does not change a version. It never says "not compromised".' },
  { key: 'libs', title: 'libs & runtimes',
    blurb: 'what each language toolchain has installed machine-wide, checked against OSV: npm, pip, '
         + 'PHP, Ruby, Rust, .NET, Maven and Go.' },
  { key: 'plan', title: 'the fix, as commands',
    blurb: 'the system packages above turned into ordered commands to paste where you are allowed '
         + 'to patch (risk, downtime, how to verify, how to undo). This is the normal way to apply '
         + 'an update; everything else here is measurement.' },
  { key: 'gaps', title: 'gaps',
    blurb: 'what this scan could not see. Red here is a fact about the scan, not the server.' },
]
const SECTION = SECTIONS.reduce((acc, section) => { acc[section.key] = section; return acc }, {})

/** Every section gets the legend's slim bar — one colour for all of them, so the page reads as
 *  blocks without six competing accents. The bar separates; the section title distinguishes. */
function sectionStyle() {
  return { marginBottom: '20px', paddingLeft: '11px', borderLeft: '2px solid ' + C.accent }
}

/**
 * Four device shapes: the machine Hermes runs on, a server on the local network, a remote host, and
 * anything whose address says neither. The shape is a hint; the label is still the truth.
 */
function deviceKind(entry) {
  const target = String((entry && entry.target) || '')
  if (!target || target === 'local') return 'hermes'
  const host = target.split('@').pop().split(':')[0]
  if (!host) return 'hermes'
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(host)
      || host === 'localhost' || host === '127.0.0.1' || host.endsWith('.local')
      || host.endsWith('.lan') || host.endsWith('.internal')) return 'lan'
  return 'remote'
}

const DEVICE_COLOUR = { hermes: '#4de3d0', lan: '#8ab4f8', remote: '#e3b341', other: '#7a8b99' }

function deviceIcon(kind, size = 12) {
  const colour = DEVICE_COLOUR[kind] || DEVICE_COLOUR.other
  const common = { width: size, height: size, viewBox: '0 0 16 16', fill: 'none',
                   stroke: colour, strokeWidth: 1.3, strokeLinecap: 'round',
                   strokeLinejoin: 'round', 'aria-hidden': 'true',
                   style: { flex: '0 0 auto', marginRight: '6px', verticalAlign: '-2px' } }
  const title = { hermes: 'the machine Hermes runs on', lan: 'a server on the local network',
                  remote: 'a remote server', other: 'another device' }[kind] || 'device'
  if (kind === 'hermes') {
    // a terminal window with a prompt: this is the box the agent lives in
    return jsxs('svg', { ...common, role: 'img' }, [
      jsx('title', { key: 't' }, title),
      jsx('rect', { key: 'r', x: 1.5, y: 2.5, width: 13, height: 11, rx: 2 }),
      jsx('path', { key: 'p1', d: 'M4.5 6.5l2 1.5-2 1.5' }),
      jsx('path', { key: 'p2', d: 'M8.5 10h3' })
    ])
  }
  if (kind === 'lan') {
    // a rack unit: two shelves and a status dot
    return jsxs('svg', { ...common, role: 'img' }, [
      jsx('title', { key: 't' }, title),
      jsx('rect', { key: 'a', x: 2, y: 3, width: 12, height: 4, rx: 1 }),
      jsx('rect', { key: 'b', x: 2, y: 9, width: 12, height: 4, rx: 1 }),
      jsx('circle', { key: 'c', cx: 12, cy: 5, r: 0.7, fill: colour, stroke: 'none' })
    ])
  }
  if (kind === 'remote') {
    // a globe: somewhere else, reached over the network
    return jsxs('svg', { ...common, role: 'img' }, [
      jsx('title', { key: 't' }, title),
      jsx('circle', { key: 'a', cx: 8, cy: 8, r: 6 }),
      jsx('path', { key: 'b', d: 'M2 8h12' }),
      jsx('path', { key: 'c', d: 'M8 2c2.5 2.6 2.5 9.4 0 12M8 2c-2.5 2.6-2.5 9.4 0 12' })
    ])
  }
  return jsxs('svg', { ...common, role: 'img' }, [
    jsx('title', { key: 't' }, title),
    jsx('rect', { key: 'a', x: 3, y: 3, width: 10, height: 10, rx: 2 }),
    jsx('path', { key: 'b', d: 'M8 6.5v3M8 11.2v.1' })
  ])
}

/** `env:/home/x/projects/api/.venv` → `projects/api/.venv` — enough to recognise the project. */
function envName(source) {
  if (!source || source.indexOf('env:') !== 0) return ''
  const parts = source.slice(4).split('/').filter(Boolean)
  return parts.slice(-2).join('/')
}

/** The newest of a list of versions, by numeric segments (`2.10` sorts above `2.9`). */
function newestVersion(list) {
  const key = (v) => String(v).split(/[.\-+]/).map((part) => parseInt(part, 10) || 0)
  return (list || []).slice().sort((a, b) => {
    const left = key(a)
    const right = key(b)
    for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
      if ((left[i] || 0) !== (right[i] || 0)) return (left[i] || 0) - (right[i] || 0)
    }
    return 0
  }).pop()
}

/**
 * The command that closes a finding — built from the store the package was actually read out of,
 * with the absolute path of the binary that answered. "python3 -m pip install -U x" was the old
 * advice and it was wrong twice: on a host whose system python has no pip it fails outright, and the
 * package usually lives in a venv or a toolchain, not in that python at all. pipx and uv tools cannot
 * be upgraded by pip in any case. When the backend says there is no machine-wide command, this says
 * so instead of inventing one. Exported because a string a user will paste deserves its own tests.
 */
/**
 * The command that upgrades one row, or a comment saying why there is none.
 *
 * A row read from a project environment carries that environment's own installer (`<venv>/bin/pip`,
 * or `uv pip install --python <venv>/bin/python` for a uv-made venv with no pip). A row with no
 * manager is a comment — never a command that cannot run.
 */
function fixCommandFor(row, fix) {
  const eco = String(row.ecosystem || '').toLowerCase()
  const manager = row.manager || null
  // the exact first-fixed version, not ">= that": a `>=` spec let pip install 4.2.9 where 4.2.1 was
  // the fix, and a major jump inside a project is a breakage the operator did not ask for
  // "no fix published" must never become a command that names a version: `pkg==latest` is not a
  // version and pip rejects it. A manager whose command takes no version at all (pipx upgrades the
  // tool to whatever is current) is still a real action, so the guard is about `{spec}`.
  if (!fix && manager && String(manager.upgrade || '').includes('{spec}')) {
    return '# ' + row.package + ': no published fix for this advisory yet — nothing to install'
  }
  if (!fix && !manager) {
    return '# ' + row.package + ': no published fix for this advisory yet — nothing to install'
  }
  const spec = eco === 'npm'
    ? row.package + '@' + fix
    : "'" + row.package + '==' + fix + "'"
  if (row.owner === 'hermes') {
    return '# ' + row.package + ': part of Hermes\'s own environment — upgraded with `hermes update`, '
      + 'not by hand'
  }
  if (!manager) {
    return '# ' + row.package + ': no store on this machine owns it — nothing to run here'
  }
  if (!manager.upgrade) {
    return '# ' + row.package + ': ' + (manager.why || 'no machine-wide command upgrades it')
  }
  const store = String(row.source || '').replace(/^env:/, '')
  return String(manager.upgrade)
    .split('{tool}').join(manager.path || manager.tool)
    .split('{spec}').join(spec)
    .split('{pkg}').join(row.package)
    .split('{ver}').join(fix || 'latest')
    .split('{python}').join(store + '/bin/python')
}

/** Kept for the row renderer, which has the aggregated finding rather than a fixed version. */
function buildFixCommand(row, found) {
  const fix = found && found.fixes && found.fixes.length ? newestVersion(found.fixes) : null
  return fixCommandFor(row, fix)
}

/** Numeric-segment comparison, the same ordering the pane uses to pick the newest fix. */
function compareVersions(left, right) {
  const key = (value) => String(value || '').split(/[.\-+]/).map((part) => parseInt(part, 10) || 0)
  const a = key(left)
  const b = key(right)
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) - (b[i] || 0)
  }
  return 0
}

/**
 * Only rows whose named fix is *ahead* of what is installed. An advisory that says "fixed in 9.0.3"
 * against an installed 9.1.1 is not an upgrade — proposing it would be a downgrade, and the honest
 * reading is that the advisory's range and its fix disagree.
 */
function actionableFixes(rows) {
  return (rows || []).filter((row) => row.fix && compareVersions(row.fix, row.version) > 0)
}

/**
 * One block for the copy control: a finding per *package*, not per advisory and not per environment.
 * The old list repeated `pillow` nine times because it mapped every advisory row, and every
 * environment, separately — a paste of that fixed nothing and read like a broken tool.
 */
function fixBlock(rows) {
  const groups = new Map()
  for (const row of rows) {
    const key = row.package + '|' + (row.version || '') + '|' + (row.fix || '')
    const group = groups.get(key) || { row, rows: [] }
    group.rows.push(row)
    groups.set(key, group)
  }
  const lines = []
  for (const group of groups.values()) {
    const row = group.row
    const fix = row.fix || null
    const stores = group.rows.map((item) => String(item.source || '')).filter(Boolean)
    const unique = Array.from(new Set(stores))
    const head = '# ' + row.package + (row.version ? ' ' + row.version : '')
      + (fix ? ' → ' + fix : '')
      + (unique.length > 1 ? ' — ' + unique.length + ' places carry it' : '')
    lines.push(head)
    for (const item of group.rows) lines.push(fixCommandFor(item, fix))
  }
  return lines.join('\n')
}

function dot(level) {
  return jsx('span', {
    'aria-hidden': 'true',
    style: {
      display: 'inline-block', width: '8px', height: '8px', borderRadius: '2px',
      background: LEVEL_COLOUR[level] || C.faint, flex: '0 0 auto',
      boxShadow: level === 'green' ? '0 0 6px ' + LEVEL_COLOUR.green : 'none'
    }
  })
}

/**
 * A scan that takes 20-60 s needs to look like it is working. These are CSS animations injected once
 * with the pane: a sweeping line while a measurement runs, and a breathing dot on the control that
 * started it. No dependency, no canvas, nothing that runs when nothing is being measured.
 */
const SCAN_CSS = `
@keyframes ps-sweep { 0% { transform: translateX(-100%); } 100% { transform: translateX(320%); } }
@keyframes ps-breathe { 0%, 100% { opacity: 0.35; } 50% { opacity: 1; } }
@keyframes ps-spin { to { transform: rotate(360deg); } }
.ps-scan-track { position: relative; overflow: hidden; height: 2px; border-radius: 2px;
  background: rgba(255,255,255,0.06); }
.ps-scan-track::after { content: ''; position: absolute; top: 0; left: 0; height: 2px; width: 32%;
  background: linear-gradient(90deg, transparent, #4de3d0, transparent); animation: ps-sweep 1.15s
  cubic-bezier(0.4, 0, 0.2, 1) infinite; }
.ps-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #4de3d0;
  margin-right: 6px; animation: ps-breathe 1.2s ease-in-out infinite; }
.ps-ring { display: inline-block; width: 9px; height: 9px; margin-right: 6px; border-radius: 50%;
  border: 1px solid transparent; border-top-color: #4de3d0; border-right-color: #4de3d0;
  animation: ps-spin 0.8s linear infinite; }
@media (prefers-reduced-motion: reduce) {
  .ps-scan-track::after, .ps-dot, .ps-ring { animation: none; }
}`

/** The sweeping line, shown while any measurement is running. */
function ScanLine({ label }) {
  return jsxs('div', { style: { marginBottom: '10px' } }, [
    jsx('div', { className: 'ps-scan-track' }),
    label
      ? jsx('div', {
          style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.dim, marginTop: '4px',
                   letterSpacing: '0.06em' }
        }, label)
      : null
  ])
}

/** A small status pill. Colour carries the meaning; the text never relies on colour alone. */
function chip(text, colour, title) {
  return jsx('span', {
    title: title || text,
    style: {
      fontFamily: MONO, fontSize: '0.6875rem', letterSpacing: '0.08em', textTransform: 'uppercase',
      padding: '1px 6px', borderRadius: '8px', whiteSpace: 'nowrap',
      color: colour, border: '1px solid ' + colour, background: 'transparent'
    }
  }, text)
}

function label(text, extra) {
  // section headings carry the HUD accent: bigger, spaced, with a rule under them and a faint glow,
  // so the eye can jump between panels without reading a word
  return jsx('div', {
    style: {
      fontFamily: MONO, fontSize: '0.8125rem', letterSpacing: '0.18em', fontWeight: 700,
      textTransform: 'uppercase', color: C.accent, paddingBottom: '4px',
      borderBottom: '1px solid ' + C.accent, display: 'inline-block',
      textShadow: '0 0 12px rgba(53, 214, 214, 0.28)', ...(extra || {})
    }
  }, text)
}

function Copy({ text, what, label }) {
  const [done, setDone] = useState(false)
  const onClick = useCallback(async () => {
    try {
      if (sdk.host && sdk.host.copyText) await sdk.host.copyText(text)
      else if (navigator.clipboard) await navigator.clipboard.writeText(text)
      setDone(true)
      setTimeout(() => setDone(false), 1400)
    } catch (err) {
      setDone(false)
    }
  }, [text])
  return jsx('button', {
    type: 'button',
    onClick,
    title: what ? 'Copy ' + what : 'Copy',
    style: {
      fontFamily: MONO, fontSize: '0.75rem', padding: '2px 8px', cursor: 'pointer',
      color: done ? C.ok : C.dim, background: 'transparent',
      border: '1px solid ' + C.border, borderRadius: '3px'
    }
  }, done ? 'copied' : (label || 'copy'))
}

// --------------------------------------------------------------------------- the verdict bar

/**
 * The answer to "am I ok?" in one line, before any panel is read: how many servers answered, what is
 * pending, what is being exploited, and what could not be looked at. Each chip is a fact from the
 * stored scan, and the age is printed beside it — a verdict without its timestamp is a rumour.
 */
function VerdictBar({ status }) {
  if (!status) return null
  const hosts = Object.values(status.hosts || {})
  if (!hosts.length) return null
  const pending = hosts.reduce((total, entry) => total + (entry.pending_count || 0), 0)
  const lag = hosts.reduce((total, entry) => total + ((entry.vendor_lag || []).length), 0)
  const exploited = (status.threat && status.threat.exploited) || []
  const blind = (status.blind || []).length
  const kernelWaiting = hosts.filter((entry) => (entry.kernel || {}).verdict === 'kernel-reboot-needed').length
  // installed is not in effect: the packaging system asked for a reboot, or a service is still
  // mapping a library that was replaced on disk
  const restartOwed = hosts.some((entry) => (entry.services || {}).reboot_required)
  const stuckServices = hosts.reduce((total, entry) => total + ((entry.services || {}).services || []).length, 0)
  return jsxs('div', {
    style: {
      display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center', marginBottom: '12px',
      padding: '7px 9px', border: '1px solid ' + C.border, borderRadius: '4px', background: C.panel
    }
  }, [
    chip(hosts.length + ' server' + (hosts.length === 1 ? '' : 's'), C.dim, 'servers in the inventory'),
    chip(pending ? pending + ' update' + (pending === 1 ? '' : 's') + ' pending' : 'nothing pending',
         pending ? C.warn : C.ok, 'package updates the distro would install'),
    lag ? chip(lag + ' vendor-lag', C.warn, 'a fix exists upstream, the archive does not carry it yet') : null,
    exploited.length ? chip(exploited.length + ' exploited', C.danger,
                            'CISA KEV: ' + exploited.join(', ')) : null,
    restartOwed ? chip('reboot owed', C.warn,
                       'the packaging system recorded a reboot-required flag — the update is installed, '
                       + 'not in effect') : null,
    stuckServices ? chip(stuckServices + ' service(s) stale', C.warn,
                         'services still mapping a library that has been replaced on disk — they run '
                         + 'the old code until restarted') : null,
    kernelWaiting ? chip(kernelWaiting + ' reboot needed', C.warn,
                         'a kernel was installed but the running one is older') : null,
    blind ? chip(blind + ' could not look', C.danger, 'see gaps — this is a fact about the scan') : null,
    jsx('span', { style: { flex: 1 } }),
    jsx('span', { style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.faint } },
      'measured ' + ago(status.age_seconds))
  ])
}

// --------------------------------------------------------------------------- HOSTS

/** Add or remove a server. Addresses only — never a credential. */
function HostsPanel({ onChanged, startOpen, initialTest }) {
  const [hosts, setHosts] = useState(null)
  const [open, setOpen] = useState(!!startOpen)
  const [newLabel, setNewLabel] = useState('')
  const [newTarget, setNewTarget] = useState('')
  const [test, setTest] = useState(initialTest || null)
  const [busy, setBusy] = useState(false)
  const [removing, setRemoving] = useState(null)
  const [typed, setTyped] = useState('')

  const load = useCallback(async () => {
    try {
      const answer = await call('/hosts')
      setHosts((answer && answer.hosts) || [])
    } catch (err) {
      setHosts([])
    }
  }, [])

  useEffect(() => { load() }, [load])

  const runTest = useCallback(async () => {
    setBusy(true)
    setTest(null)
    try {
      setTest(await call('/hosts/test', { method: 'POST', body: { label: newLabel, target: newTarget } }))
    } catch (err) {
      setTest({ ok: false, reason: String(err && err.message ? err.message : err) })
    } finally {
      setBusy(false)
    }
  }, [newLabel, newTarget])

  const add = useCallback(async () => {
    setBusy(true)
    try {
      const answer = await call('/hosts', { method: 'POST', body: { label: newLabel, target: newTarget } })
      if (answer && answer.hosts) {
        setHosts(answer.hosts)
        setNewLabel('')
        setNewTarget('')
        setTest(null)
        setOpen(false)
        if (onChanged) onChanged()
      } else {
        setTest({ ok: false, reason: (answer && answer.reason) || 'the host was not added' })
      }
    } finally {
      setBusy(false)
    }
  }, [newLabel, newTarget, onChanged])

  const remove = useCallback(async (host) => {
    setBusy(true)
    try {
      const answer = await call('/hosts/remove', {
        method: 'POST', body: { label: host.label, confirm: typed }
      })
      if (answer && answer.hosts) {
        setHosts(answer.hosts)
        setRemoving(null)
        setTyped('')
        if (onChanged) onChanged()
      } else {
        setTest({ ok: false, reason: (answer && answer.reason) || 'the host was not removed' })
      }
    } finally {
      setBusy(false)
    }
  }, [typed, onChanged])

  return jsxs('section', { style: sectionStyle('servers') }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label(SECTION.servers.title),
      jsx('span', { style: { flex: 1 } }),
      jsx('span', { style: { fontFamily: MONO, fontSize: '0.75rem', color: C.faint } },
        hosts ? hosts.length + ' server(s)' : '…'),
      jsx('button', {
        type: 'button',
        onClick: () => { setOpen((v) => !v); setTest(null) },
        style: {
          fontFamily: MONO, fontSize: '0.75rem', padding: '3px 9px', cursor: 'pointer',
          color: open ? C.accent : C.dim, background: 'transparent',
          border: '1px solid ' + (open ? C.accent : C.border), borderRadius: '3px'
        }
      }, open ? 'close' : 'add a server')
    ]),
    (hosts || []).map((host) => jsxs('div', {
      key: host.label,
      style: {
        display: 'grid', gridTemplateColumns: '1fr auto auto', gap: '8px', alignItems: 'baseline',
        fontFamily: MONO, fontSize: '0.75rem', padding: '3px 0',
        borderTop: '1px solid ' + C.border
      }
    }, [
      jsx('span', { style: { color: C.text } }, host.label),
      jsx('span', { style: { color: C.dim } }, host.target === 'local' ? 'this machine' : host.target),
      removing === host.label
        ? jsxs('span', { style: { display: 'flex', gap: '4px' } }, [
            jsx('input', {
              value: typed,
              onChange: (event) => setTyped(event.target.value),
              placeholder: 'type ' + host.label,
              style: {
                width: '7rem', fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 4px',
                background: 'transparent', color: C.text, border: '1px solid ' + C.danger,
                borderRadius: '2px'
              }
            }),
            jsx('button', {
              type: 'button',
              onClick: () => remove(host),
              disabled: busy || typed !== host.label,
              title: 'removes the host and its measurement history',
              style: {
                fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 6px',
                cursor: typed === host.label ? 'pointer' : 'not-allowed',
                color: typed === host.label ? C.danger : C.faint, background: 'transparent',
                border: '1px solid ' + C.border, borderRadius: '2px'
              }
            }, 'remove')
          ])
        : jsx('button', {
            type: 'button',
            onClick: () => { setRemoving(host.label); setTyped('') },
            disabled: host.target === 'local',
            title: host.target === 'local'
              ? 'the machine this plugin runs on is always in the inventory'
              : 'remove this host',
            style: {
              fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 6px',
              cursor: host.target === 'local' ? 'default' : 'pointer',
              color: host.target === 'local' ? C.faint : C.dim, background: 'transparent',
              border: '1px solid ' + C.border, borderRadius: '2px'
            }
          }, '×')
    ])),
    open
      ? jsxs('div', { style: { marginTop: '8px', padding: '8px', border: '1px solid ' + C.border, borderRadius: '3px', background: C.panel } }, [
          jsxs('div', { style: { display: 'flex', gap: '6px', marginBottom: '5px' } }, [
            jsx('input', {
              value: newLabel, onChange: (e) => { setNewLabel(e.target.value); setTest(null) },
              placeholder: 'name it (e.g. vps)', 
              style: {
                flex: '0 0 30%', fontFamily: MONO, fontSize: '0.75rem', padding: '3px 6px',
                background: 'transparent', color: C.text, border: '1px solid ' + C.border,
                borderRadius: '3px'
              }
            }),
            jsx('input', {
              value: newTarget, onChange: (e) => { setNewTarget(e.target.value); setTest(null) },
              placeholder: 'user@host:port, an ssh alias, or local',
              style: {
                flex: 1, fontFamily: MONO, fontSize: '0.75rem', padding: '3px 6px',
                background: 'transparent', color: C.text, border: '1px solid ' + C.border,
                borderRadius: '3px'
              }
            })
          ]),
          jsxs('div', { style: { display: 'flex', gap: '6px', alignItems: 'center' } }, [
            jsx('button', {
              type: 'button', onClick: runTest, disabled: busy || !newLabel,
              style: {
                fontFamily: MONO, fontSize: '0.75rem', padding: '3px 9px',
                cursor: busy || !newLabel ? 'default' : 'pointer',
                color: C.accent, background: 'transparent',
                border: '1px solid ' + C.border, borderRadius: '3px'
              }
            }, busy ? '…' : 'test'),
            jsx('button', {
              type: 'button', onClick: add, disabled: busy || !test || !test.ok,
              title: test && test.ok ? 'save it to the inventory' : 'a host is only added after a probe of it succeeded',
              style: {
                fontFamily: MONO, fontSize: '0.75rem', padding: '3px 9px',
                cursor: test && test.ok ? 'pointer' : 'not-allowed',
                color: test && test.ok ? C.ok : C.faint, background: 'transparent',
                border: '1px solid ' + (test && test.ok ? C.ok : C.border), borderRadius: '3px'
              }
            }, 'add'),
            jsx('span', { style: { fontSize: '0.75rem', color: C.faint } },
              'addresses only — the key stays in ssh')
          ]),
          test
            ? jsxs('div', { style: { marginTop: '6px' } }, [
                test.ok
                  ? jsx('div', { style: { fontSize: '0.75rem', color: C.ok, lineHeight: 1.4 } },
                      'reached it: ' + (test.adapter || '?') + ' · ' + ((test.os && test.os.id) || '?') + '/'
                      + ((test.os && test.os.codename) || '?') + ' · kernel '
                      + ((test.kernel && test.kernel.verdict) || '?') + ' · ' + (test.pending || 0) + ' pending')
                  : jsxs('div', {}, [
                      jsxs('div', { style: { display: 'flex', gap: '6px', alignItems: 'baseline' } }, [
                        chip('stopped at ' + (test.stage || 'unknown'), C.danger,
                             'the stage ssh failed at, in the order it tries them'),
                        jsx('span', { style: { fontSize: '0.75rem', color: C.dim } },
                          test.reason || 'the host did not answer')
                      ]),
                      test.hint
                        ? jsx('div', { style: { fontSize: '0.75rem', color: C.text, marginTop: '3px', lineHeight: 1.45 } },
                            test.hint)
                        : null,
                      test.fix
                        ? jsxs('div', { style: { display: 'flex', gap: '6px', alignItems: 'baseline', marginTop: '4px' } }, [
                            jsx('code', {
                              style: {
                                fontFamily: MONO, fontSize: '0.6875rem', color: C.accent,
                                background: C.panel, padding: '2px 6px', borderRadius: '3px',
                                border: '1px solid ' + C.border, wordBreak: 'break-all'
                              }
                            }, test.fix),
                            jsx(Copy, { text: test.fix, label: 'copy' })
                          ])
                        : null
                    ])
              ])
            : null
        ])
      : null
  ])
}

// --------------------------------------------------------------------------- NOW

function NowPanel({ status }) {
  const hosts = status && status.hosts ? Object.values(status.hosts) : []
  const blind = (status && status.blind) || []
  const rows = hosts.map((entry) => {
    const level = stateOf(entry)
    const kernel = entry.kernel || {}
    return jsxs('div', {
      key: entry.label,
      style: {
        display: 'grid', gridTemplateColumns: '10px 1fr auto', gap: '8px',
        alignItems: 'baseline', padding: '7px 0', borderTop: '1px solid ' + C.border
      }
    }, [
      dot(level.level),
      jsxs('div', {}, [
        jsxs('div', { style: { display: 'flex', gap: '6px', alignItems: 'center' } }, [
          deviceIcon(deviceKind(entry)),
          jsx('span', { style: { fontWeight: 600, fontSize: '0.8125rem' } }, entry.label),
          jsx('span', { fontFamily: MONO, fontSize: '0.6875rem', color: C.accent },
            (entry.adapter || '?') + ' · ' + ((entry.os && entry.os.id) || '?') + '/' + ((entry.os && entry.os.codename) || '?')),
          // where the answer came from: this machine, or a host the operator declared
          jsx('span', { fontFamily: MONO, fontSize: '0.6875rem', color: C.faint },
            entry.target && entry.target !== 'local' ? 'ssh ' + entry.target : 'this machine')
        ]),
        jsx('div', { style: { fontFamily: MONO, fontSize: '0.8125rem', color: C.dim, marginTop: '2px' } },
          'kernel ' + (kernel.running || '?') + ' → ' + (kernel.verdict || '?')),
        jsx('div', { style: { fontSize: '0.8125rem', color: C.faint, marginTop: '2px' } },
          (entry.pending_count || 0) + ' pending · ' + ((entry.vendor_lag || []).length)
          + ' fix(es) waiting on the vendor · ' + (entry.images || []).length + ' image(s) · ' + level.level),
        (entry.pending || []).length
          ? jsx('div', { style: { fontFamily: MONO, fontSize: '0.75rem', color: C.dim, marginTop: '3px' } },
              (entry.pending || []).slice(0, 3).map((row) => row.package + ' ' + (row.from || '?') + '→' + row.to).join(' · ') +
              (entry.pending_count > 3 ? ' · +' + (entry.pending_count - 3) + ' more' : ''))
          : null
      ]),
      jsxs('div', { style: { textAlign: 'right' } }, [
        jsx('div', { style: { fontFamily: MONO, fontSize: '0.8125rem', color: C.dim } },
          entry.measured_at ? entry.measured_at.replace('T', ' ').slice(0, 19) : '—'),
        jsx('div', { style: { fontSize: '0.75rem', color: C.faint } }, 'measured')
      ])
    ])
  })

  return jsxs('section', { style: sectionStyle('overview') }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label(SECTION.overview.title),
      jsx('span', { style: { flex: 1 } }),
      jsx('span', { style: { fontFamily: MONO, fontSize: '0.75rem', color: C.faint } },
        ago(status ? status.age_seconds : null) + ' · exit ' + (status && status.exit_code !== null && status.exit_code !== undefined ? status.exit_code : '—'))
    ]),
    hosts.length ? rows : jsx('div', { style: { fontSize: '0.75rem', color: C.faint, padding: '6px 0' } },
      (status && status.note) || 'no measurement yet'),
    blind.length
      ? jsx('div', { style: { marginTop: '6px', fontSize: '0.8125rem', color: C.danger } },
          blind.length + ' check(s) could not look — '
          + blind.map((b) => b.host || 'this machine').join(', ') + ' · see GAPS')
      : null
  ])
}

// --------------------------------------------------------------------------- UPDATES

/** The raw update list for the selected host — every package, searchable, copyable. */
function UpdatesPanel({ entry, hostLabel }) {
  const [query, setQuery] = useState('')
  const rows = (entry && entry.pending) || []
  const total = (entry && entry.pending_count) || 0
  const needle = query.trim().toLowerCase()
  const filtered = needle ? rows.filter((r) => (r.package || '').toLowerCase().includes(needle)) : rows
  const shown = filtered
  // the copy control exists to paste something a shell can run. A list of "package 1.2 → 1.3" lines
  // is a reference, not a command — the operator copied it and got no command out of it.
  const commands = entry && entry.commands ? entry.commands : null
  const text = filtered.map((r) => r.package + '  ' + (r.from || '?') + ' → ' + r.to).join('\n')
  const commandBlock = commands
    ? [commands.stage, commands.apply].filter(Boolean).join('\n')
    : ''

  return jsxs('section', { style: sectionStyle('packages') }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label(SECTION.packages.title),
      jsx('span', { style: { flex: 1 } }),
      jsx('span', { fontFamily: MONO, fontSize: '0.75rem', color: total ? C.warn : C.faint },
        hostLabel ? total + ' available' : '—'),
      jsx('span', { style: { fontSize: '0.75rem', color: C.faint } },
        entry && entry.measured_at ? 'measured ' + entry.measured_at.replace('T', ' ').slice(11, 16) + ' UTC' : ''),
      rows.length && commandBlock
        ? jsx(Copy, { text: commandBlock, label: 'copy the commands',
                      what: 'the upgrade commands for ' + (hostLabel || 'this machine') })
        : null,
      rows.length ? jsx(Copy, { text, label: 'copy list', what: 'the package list' }) : null
    ]),
    entry && entry.where && (rows.length || (entry.vendor_lag || []).length)
      ? jsxs('div', { style: { fontSize: '0.75rem', color: C.faint, marginBottom: '5px', lineHeight: 1.45 } }, [
          jsx('span', { style: { fontFamily: MONO, color: C.dim } },
            (entry.where.kind === 'remote' ? 'run them on ' + entry.where.machine : 'run them on this machine')
            + ' — ' + (entry.where.how || 'in a terminal there')),
          entry.where.ssh ? jsx('span', { style: { fontFamily: MONO, color: C.dim } }, ' · ' + entry.where.ssh) : null
        ])
      : null,
    // a release the vendor stopped patching: "nothing pending" there is not a healthy host
    entry && entry.support && entry.support.state === 'end-of-life'
      ? jsxs('div', {
          style: {
            borderLeft: '2px solid ' + C.danger, background: C.panel, padding: '5px 8px',
            marginBottom: '6px', borderRadius: '3px'
          }
        }, [
          jsx('div', { style: { fontSize: '0.8125rem', color: C.danger, fontWeight: 600 } },
            'this release is past standard support (ended ' + entry.support.ends + ')'),
          jsx('div', { style: { fontSize: '0.75rem', color: C.dim, marginTop: '2px', lineHeight: 1.45 } },
            'No new fixes are published for it, so an empty pending list here means nobody is going to '
            + 'publish one — not that the machine is patched.'
            + (entry.support.pro && entry.support.pro.outcome === 'ok' && (entry.support.pro.enabled || []).length
                ? ' Ubuntu Pro is attached (' + entry.support.pro.enabled.join(', ') + '), which may still '
                  + 'carry fixes.'
                : ''))
        ])
      : null,
    // subscribed to the pocket that carries a fix? a configuration fact, not a vendor delay
    entry && entry.pockets && entry.pockets.outcome === 'ok'
      && !(entry.pockets.pockets || {}).security
      ? jsx('div', {
          style: { fontSize: '0.75rem', color: C.warn, marginBottom: '5px' }
        }, 'no security pocket is enabled on this host — a fix the vendor published may not be '
           + 'delivered here at all')
      : null,
    // whose feed answered, and how old it is: SUSE's OVAL for a release that left support stops
    // moving, and a stopped feed is not a vendor delay
    entry && entry.vendor_feed && entry.vendor_feed.stale
      ? jsxs('div', {
          style: {
            borderLeft: '2px solid ' + C.warn, background: C.panel, padding: '5px 8px',
            marginBottom: '6px', borderRadius: '3px'
          }
        }, [
          jsx('div', { style: { fontSize: '0.8125rem', color: C.warn, fontWeight: 600 } },
            (entry.vendor_feed.product || 'the vendor feed') + ' was last refreshed '
            + String(entry.vendor_feed.feed_date || '').replace(' GMT', '')
            + (entry.vendor_feed.age_days !== null && entry.vendor_feed.age_days !== undefined
                ? ' — ' + entry.vendor_feed.age_days + ' days ago' : '')),
          jsx('div', { style: { fontSize: '0.75rem', color: C.dim, marginTop: '2px', lineHeight: 1.45 } },
            'A stale feed is not a vendor delay: the release has probably left support, so no new '
            + 'fixes are published for it. Lag rows below are a snapshot of that feed\'s last run.')
        ])
      : null,
    // the lag check itself can be unmeasured (a family with no feed) — say it rather than let the
    // absence of rows read as "no lag"
    entry && (entry.vendor_state === 'unsupported' || entry.vendor_state === 'unmeasured')
      ? jsxs('div', {
          style: {
            borderLeft: '2px solid ' + C.border, background: C.panel, padding: '6px 8px',
            marginBottom: '6px', borderRadius: '3px'
          }
        }, [
          jsx('div', { style: { fontSize: '0.8125rem', color: C.warn, fontWeight: 600 } },
            'vendor lag: ' + (entry.vendor_state === 'unsupported' ? 'no feed for this family' : 'unmeasured')),
          jsx('div', { style: { fontSize: '0.75rem', color: C.dim, marginTop: '2px', lineHeight: 1.45 } },
            entry.vendor_reason || 'the vendor-lag check did not run here')
        ])
      : null,
    // only when it can change an answer: no pending rows and no lag rows means the stale index is
    // hiding nothing, so it is not shown at all
    entry && entry.vendor_index_fresh === false
      && ((entry.pending || []).length || (entry.vendor_lag || []).length)
      ? jsxs('div', {
          style: { fontSize: '0.75rem', color: C.warn, marginBottom: '4px', lineHeight: 1.45 }
        }, [
          jsx('span', {}, (entry.vendor_index_note
            || 'the archive index on this host is older than 48 h') + ' — '),
          entry.commands && entry.commands.refresh
            ? jsx('span', { style: { fontFamily: MONO, color: C.accent } }, entry.commands.refresh)
            : null,
          jsx('span', {}, ' then rescan')
        ])
      : null,
    (entry && entry.vendor_lag || []).length
      ? jsxs('div', {
          style: {
            borderLeft: '2px solid ' + C.danger, background: C.panel, padding: '6px 8px',
            marginBottom: '6px', borderRadius: '3px'
          }
        }, [
          jsx('div', { style: { fontSize: '0.8125rem', color: C.danger, fontWeight: 600 } },
            entry.vendor_lag.length + ' fix(es) exist upstream but not in this archive yet'),
          jsx('div', { style: { fontSize: '0.75rem', color: C.dim, marginTop: '2px', lineHeight: 1.4 } },
            'The advisory names a fixed version the archive does not offer, so nothing on this host can '
            + 'close it yet. Not the same as "nothing to do".'),
          entry.vendor_lag.slice(0, 6).map((row, index) => jsx('div', {
            key: index,
            style: { fontFamily: MONO, fontSize: '0.75rem', color: C.text, marginTop: '3px' }
          }, row.package + '  ' + row.installed + ' → ' + row.fixed_version
             + '  (' + (row.notice || 'advisory') + ')'))
        ])
      : null,
    rows.length
      ? jsxs('div', {}, [
          jsx('input', {
            value: query,
            onChange: (event) => setQuery(event.target.value),
            placeholder: 'filter by package name',
            style: {
              width: '100%', boxSizing: 'border-box', fontFamily: MONO, fontSize: '0.8125rem',
              padding: '3px 7px', marginBottom: '5px', background: 'transparent', color: C.text,
              border: '1px solid ' + C.border, borderRadius: '3px'
            }
          }),
          jsx('div', {
            style: {
              maxHeight: '240px', overflowY: 'auto', overscrollBehavior: 'contain',
              border: '1px solid ' + C.border, borderRadius: '3px', background: C.panel,
              padding: '2px 6px'
            }
          }, shown.map((row, index) => jsxs('div', {
              key: index,
              style: {
                display: 'grid', gridTemplateColumns: '1fr auto', gap: '10px',
                fontFamily: MONO, fontSize: '0.75rem', padding: '2px 0',
                borderTop: '1px solid ' + C.border
              }
            }, [
              jsx('span', { style: { color: C.text, wordBreak: 'break-all' } }, row.package),
              jsx('span', { style: { color: C.dim, textAlign: 'right' } },
                (row.from || '?') + ' → ' + row.to)
            ]))),
          filtered.length
            ? jsx('div', { style: { fontSize: '0.75rem', color: C.faint, marginTop: '4px' } },
                filtered.length + ' row(s) in the box above — it scrolls; copy gets all of them')
            : null,
          entry && entry.pending_truncated
            ? jsx('div', { style: { fontSize: '0.75rem', color: C.warn, marginTop: '3px' } },
                'the stored scan kept the first ' + rows.length + ' of ' + total + ' — rescan for the rest')
            : null
        ])
      : jsx('div', { style: { fontSize: '0.75rem', color: C.faint, padding: '6px 0' } },
          entry ? 'nothing available — this host is up to date, as measured'
                : 'no measurement for this host yet — press rescan above')
  ])
}

// --------------------------------------------------------------------------- LANGUAGES

/** What the language check actually read, and what it found. Nothing runs until you ask. */
function LanguagesPanel({ libraries, onCheck, busy }) {
  const [projectPath, setProjectPath] = useState('')
  const [query, setQuery] = useState('')
  // a list of 130 rows where 127 say "clean" buries the three that matter: findings first, the rest
  // behind an explicit "show all" — the count of what was checked is still on screen either way
  const [showAll, setShowAll] = useState(false)
  // findings nobody has fixed are collapsed: they are facts, not tasks. An acknowledgement needs a
  // reason, so it is a two-step control (click, type, confirm) rather than a mute button.
  const [showNoFix, setShowNoFix] = useState(false)
  const [ackFor, setAckFor] = useState(null)
  const [ackReason, setAckReason] = useState('')
  const [ackBusy, setAckBusy] = useState(false)
  const [showAcked, setShowAcked] = useState(false)
  // the agent's own dependencies are packages, but they are not the user's to upgrade one by one:
  // they are separated out and collapsed instead of counting as findings against this machine
  const [showHermes, setShowHermes] = useState(false)
  const answered = (libraries && libraries.packages) || []
  const acknowledged = (libraries && libraries.acknowledged) || []
  const hostLabel = (libraries && libraries.host && libraries.host.label) || ''

  // recording an acknowledgement: it needs a reason, it expires, and it names one advisory
  const recordAck = async (row) => {
    setAckBusy(true)
    try {
      await call('/ack', {
        method: 'POST',
        body: { host: hostLabel, ecosystem: row.ecosystem, package: row.package,
                version: row.version, advisory: row.id, reason: ackReason.trim() }
      })
      setAckFor(null)
      setAckReason('')
      await onCheck()
    } catch (err) {
      setAckFor(null)
    } finally {
      setAckBusy(false)
    }
  }

  const reopenAck = async (row) => {
    setAckBusy(true)
    try {
      await call('/ack', {
        method: 'POST',
        body: { host: hostLabel, ecosystem: row.ecosystem, package: row.package,
                version: row.version, advisory: row.id, reason: 'released', action: 'release' }
      })
      await onCheck()
    } catch (err) {
      // a failed release leaves the row acknowledged, which is the safe direction
    } finally {
      setAckBusy(false)
    }
  }
  const vulnerable = (libraries && libraries.vulnerable) || []
  // One key for everything below: ecosystem + package + *version*. Two environments carrying 8.4.2
  // and 9.1.1 are two rows; merging them is how "2 packages" was reported as "12 findings".
  const keyOf = (p) => (p.ecosystem || '') + '/' + p.package + '@' + (p.version || '')
  // if the payload carries findings but no inventory (an older backend, or a host that answered
  // nothing), the findings themselves are the list — a count with no rows is what the operator
  // rightly called broken
  const seen = new Set(answered.map(keyOf))
  const fromFindings = []
  for (const v of vulnerable) {
    const key = keyOf(v)
    if (!seen.has(key)) { seen.add(key); fromFindings.push({ ecosystem: v.ecosystem, package: v.package, version: v.version }) }
  }
  const packages = answered.length ? answered : fromFindings
  const RANK = { critical: 4, high: 3, moderate: 2, low: 1 }
  const foundByPackage = {}
  for (const v of vulnerable) {
    const key = keyOf(v)
    const severity = String(v.severity || '').split(' ')[0].toLowerCase()
    const entry = foundByPackage[key]
      || (foundByPackage[key] = { count: 0, severity: '', fixes: [], ids: [] })
    entry.count += 1
    if (!entry.severity || (RANK[severity] || 0) > (RANK[entry.severity] || 0)) entry.severity = severity
    for (const fix of v.fixed || []) if (fix && !entry.fixes.includes(fix)) entry.fixes.push(fix)
    if (v.id) entry.ids.push(v.id)
    // why is it still open: nobody published a fix, or the vendor declined
    if (!entry.fixState || entry.fixState === 'fixed') entry.fixState = v.fix_state || entry.fixState
    // the vendor's own workaround, when the advisory carries one: what to do while the patch is not
    // installed yet (disable a feature, validate input, set a flag)
    if (!entry.workaround && v.workaround) entry.workaround = v.workaround
    // evidence of exploitation outranks severity: a critical nobody uses is less urgent than a
    // moderate that is in ransomware campaigns today
    if (v.kev) {
      entry.kev = entry.kev || v.kev
      entry.kevCount = (entry.kevCount || 0) + 1
      if (v.kev.ransomware) entry.ransomware = true
    }
    if (typeof v.epss === 'number' && (entry.epss === undefined || v.epss > entry.epss)) {
      entry.epss = v.epss
    }
  }
  const hit = new Set(Object.keys(foundByPackage))
  const needle = query.trim().toLowerCase()
  const ownerOf = (p) => (p && p.owner) || 'machine'
  const matchingAll = packages.filter((p) => !needle || (p.package || '').toLowerCase().includes(needle))
  // split by whose package it is, before the findings-first view is built
  const mine = matchingAll.filter((p) => ownerOf(p) !== 'hermes')
  const agentOwned = matchingAll.filter((p) => ownerOf(p) === 'hermes')
  const findingsOn = (list) => {
    const keys = new Set(list.map(keyOf))
    return vulnerable.filter((v) => keys.has(keyOf(v)))
  }
  const findingsMine = findingsOn(mine)
  const findingsAgent = findingsOn(agentOwned)
  const matching = mine
  const flagged = mine.filter((p) => hit.has(keyOf(p)))
  // Which findings nobody has published a fix for? Those are facts, not tasks: they leave the
  // default list and sit under one line that says so, so the screen shows what can be done.
  const noFixRows = flagged.filter((row) => {
    const found = foundByPackage[keyOf(row)]
    return !(found && Array.isArray(found.fixes) && found.fixes.length)
  })
  const noFixKeys = new Set(noFixRows.map(keyOf))
  // nothing flagged? then the clean list IS the answer, so show it rather than an empty box
  const rows = (showAll || !flagged.length ? matching : flagged)
    .filter((row) => showAll || showNoFix || !noFixKeys.has(keyOf(row)))
    .slice()
    .sort((a, b) => (hit.has(keyOf(b)) ? 1 : 0) - (hit.has(keyOf(a)) ? 1 : 0)
                    || String(a.package).localeCompare(String(b.package)))
  const hidden = matching.length - rows.length
  const readEcosystems = Object.entries((libraries && libraries.by_ecosystem) || {})
    .filter(([, count]) => count > 0).map(([eco]) => eco)
  const missingEcosystems = Object.entries((libraries && libraries.outcomes) || {})
    .filter(([, outcome]) => outcome === 'missing').map(([eco]) => eco)
  const environmentCount = new Set(packages.filter((p) => envName(p.source)).map((p) => p.source)).size

  // one entry per package@version@store, carrying the version that closes it — the copy control is
  // read by a shell, so it must not repeat the same package once per advisory or per environment
  const fixRows = Array.from(new Map(flagged.map((row) => {
    const found = foundByPackage[keyOf(row)] || null
    const fix = found && found.fixes && found.fixes.length ? newestVersion(found.fixes) : null
    const key = row.package + '|' + row.version + '|' + (row.source || '')
    return [key, { ...row, fix }]
  })).values())
  const fixText = fixBlock(actionableFixes(fixRows))
  // how many lines a shell would actually run — the number the header quotes and the button shows
  const commandCount = fixText
    ? fixText.split('\n').filter((line) => line && !line.startsWith('#')).length
    : 0
  // An advisory with an empty `fixed` list has no published fix yet, in any version. Saying that
  // separately is the difference between "you are behind" and "nobody has shipped a fix" — the operator
  // ran `hermes update` and saw 40 advisories either way, which reads as if the update did nothing.
  const withFix = (rows) => rows.filter((v) => Array.isArray(v.fixed) && v.fixed.length)
  const mineWithFix = withFix(findingsMine)

  return jsxs('section', { style: sectionStyle('libs') }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label(SECTION.libs.title),
      jsx('span', { style: { flex: 1 } }),
      libraries
        ? jsx('span', {
            style: {
              fontFamily: MONO, fontSize: '0.75rem',
              // red is for something to do: an exploited finding, or one with a command to run.
              // A finding nobody has fixed yet is neutral — it is a fact, not a task.
              color: findingsMine.some((v) => v.kev) ? C.danger
                : commandCount ? C.warn : C.faint
            }
          },
            mine.length + ' package(s) · '
            + (findingsMine.length
                ? (commandCount
                    ? findingsMine.length + ' finding(s) · ' + mineWithFix.length + ' with a fix · '
                      + commandCount + ' command(s) to run'
                    : findingsMine.length + ' finding(s) · nothing to run — no published fix someone '
                      + 'could install')
                : 'nothing to upgrade'))
        : null,
      flagged && flagged.length && commandCount
        ? jsx(Copy, { text: fixText,
                      label: 'copy ' + commandCount + ' command' + (commandCount === 1 ? '' : 's') })
        // no second sentence: the header already says "nothing to run" and why. Saying it twice in
        // the same row is how a screen with nothing to do reads like a to-do list.
        : null,
      jsx('button', {
        type: 'button',
        onClick: () => onCheck(),
        disabled: busy,
        title: 'Reads the global npm tree and the pip environment on PATH, then asks osv.dev',
        style: {
          fontFamily: MONO, fontSize: '0.75rem', padding: '3px 9px', cursor: busy ? 'default' : 'pointer',
          color: busy ? C.faint : C.accent, background: 'transparent',
          border: '1px solid ' + C.border, borderRadius: '3px'
        }
      }, busy ? [jsx('span', { key: 'dot', className: 'ps-dot' }), 'checking'] : libraries ? 're-check' : 'check')
    ]),
    libraries
      ? jsxs('div', {}, [
          // a project is what ships; the machine-wide view cannot see what a lockfile pins
          jsxs('div', { style: { display: 'flex', gap: '6px', marginBottom: '5px' } }, [
            jsx('input', {
              value: projectPath,
              onChange: (event) => setProjectPath(event.target.value),
              placeholder: "a project's lockfiles — /path/to/repo (npm, pip, go, cargo, composer, bundler, pub)",
              style: {
                flex: 1, fontFamily: MONO, fontSize: '0.75rem', padding: '3px 7px',
                background: 'transparent', color: C.text, border: '1px solid ' + C.border,
                borderRadius: '3px'
              }
            }),
            jsx('button', {
              type: 'button',
              onClick: () => onCheck(projectPath.trim()),
              disabled: busy || !projectPath.trim(),
              title: 'reads every lockfile under that directory and asks OSV about the pinned versions',
              style: {
                fontFamily: MONO, fontSize: '0.75rem', padding: '3px 9px',
                cursor: busy || !projectPath.trim() ? 'default' : 'pointer',
                color: busy || !projectPath.trim() ? C.faint : C.accent, background: 'transparent',
                border: '1px solid ' + C.border, borderRadius: '3px'
              }
            }, 'check project'),
            libraries.scope === 'project'
              ? jsx('button', {
                  type: 'button',
                  onClick: () => onCheck(),
                  disabled: busy,
                  title: 'back to what this machine has installed',
                  style: {
                    fontFamily: MONO, fontSize: '0.75rem', padding: '3px 9px', cursor: 'pointer',
                    color: C.dim, background: 'transparent',
                    border: '1px solid ' + C.border, borderRadius: '3px'
                  }
                }, 'machine-wide')
              : null
          ]),
          libraries.scope === 'project' && libraries.project
            ? jsxs('div', { style: { marginBottom: '5px' } }, [
                jsx('div', { style: { fontSize: '0.8125rem', color: C.text } },
                  'project: ' + libraries.project.root),
                jsx('div', { style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.faint, marginTop: '2px', lineHeight: 1.45 } },
                  Object.entries(libraries.project.files).map(([name, state]) => name + ' — ' + state).join(' · '))
              ])
            : null,
          jsx('div', { style: { fontSize: '0.8125rem', color: C.faint, marginBottom: '4px' } },
            (libraries.answer || '')
            + (readEcosystems.length ? ' · read: ' + readEcosystems.join(', ') : '')
            + (missingEcosystems.length
                ? ' · not installed here: ' + missingEcosystems.join(', ') : '')),
          // where that number comes from: the count mixes environments, stores and the agent's own
          // env, and two readers of the same payload quoted two different totals when it did not say
          packages.length
            ? jsx('div', { style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.faint, marginBottom: '5px' } },
                [
                  environmentCount
                    ? environmentCount + ' project environment(s): ' + packages.filter((p) => envName(p.source)).length
                    : 'no project environment found',
                  packages.filter((p) => !envName(p.source) && p.owner !== 'hermes').length + ' from language stores',
                  packages.filter((p) => p.owner === 'hermes').length + ' in Hermes\'s env (not counted)'
                ].join(' · '))
            : null,
          vulnerable.length
            ? jsx('div', {
                style: { fontSize: '0.75rem', color: C.faint, marginBottom: '4px' },
                title: 'One advisory per exact version; the fix column is the first version that closes it.'
              }, findingsMine.length + ' finding(s) on ' + flagged.length
                 + ' package(s) · one row per advisory, the fix column closes it')
            : null,
          (libraries.threat && libraries.threat.kev_count)
            ? jsx('div', {
                style: { fontSize: '0.8125rem', color: C.danger, marginBottom: '4px', fontWeight: 600 }
              }, libraries.threat.kev_count + ' advisory(ies) here are in CISA\'s known-exploited list'
                + (libraries.threat.ransomware && libraries.threat.ransomware.length
                    ? ' — ' + libraries.threat.ransomware.length + ' used in ransomware campaigns' : ''))
            : null,
          !Array.isArray(libraries.packages)
            ? jsx('div', { style: { fontSize: '0.8125rem', color: C.warn, marginBottom: '4px' } },
                'this answer carries no package list — the backend behind this pane is older than the pane. '
                + 'Restart the app so both halves load the same build.')
            : null,
          jsxs('div', { style: { display: 'flex', gap: '6px', marginBottom: '5px' } }, [
            jsx('input', {
              value: query,
              onChange: (event) => setQuery(event.target.value),
              placeholder: 'filter packages',
              style: {
                flex: 1, fontFamily: MONO, fontSize: '0.8125rem', padding: '3px 7px',
                background: 'transparent', color: C.text, border: '1px solid ' + C.border,
                borderRadius: '3px'
              }
            }),
            flagged.length
              ? jsx('button', {
                  type: 'button',
                  onClick: () => setShowAll((current) => !current),
                  title: 'the packages with no advisory are still counted, just not listed',
                  style: {
                    fontFamily: MONO, fontSize: '0.75rem', padding: '3px 9px', cursor: 'pointer',
                    color: showAll ? C.accent : C.dim, background: 'transparent',
                    border: '1px solid ' + (showAll ? C.accent : C.border), borderRadius: '3px'
                  }
                }, showAll ? 'findings only' : 'show all ' + matching.length)
              : null
          ]),
          jsx('div', {
            style: {
              maxHeight: '240px', overflowY: 'auto', overscrollBehavior: 'contain',
              border: '1px solid ' + C.border, borderRadius: '3px', background: C.panel,
              padding: '2px 6px'
            }
          }, rows.map((row, index) => {
            const found = hit.has(keyOf(row)) ? foundByPackage[keyOf(row)] : null
            const fix = found && found.fixes.length ? newestVersion(found.fixes) : null
            return jsxs('div', {
              key: index,
              style: { padding: '2px 0', borderTop: '1px solid ' + C.border }
            }, [
              jsxs('div', {
                style: {
                  display: 'grid', gridTemplateColumns: '1fr auto', gap: '10px',
                  fontFamily: MONO, fontSize: '0.75rem'
                }
              }, [
                jsx('span', { style: { color: C.text, wordBreak: 'break-all' } },
                  row.package + '@' + row.version + '  ' + (row.ecosystem || '')
                  + (envName(row.source) ? '  · ' + envName(row.source) : '')),
                jsx('span', { style: { color: found ? C.danger : C.faint, textAlign: 'right' } },
                  found
                    ? found.count + ' advisor' + (found.count === 1 ? 'y' : 'ies')
                      + (found.severity ? ' · ' + found.severity : '')
                      + (fix && compareVersions(fix, row.version) <= 0
                            ? ' · installed is past the named fix — the advisory disagrees with itself'
                         : fix ? ' · fix ' + fix
                             : found.fixState === "won't-fix" ? ' · vendor declined to fix'
                             : found.fixState === 'unknown' ? ' · fix state unknown'
                             : ' · no fix published')
                    : 'clean'),
              ]),
              found && (found.kev || found.epss !== undefined)
                ? jsxs('div', { style: { display: 'flex', gap: '5px', marginTop: '3px', flexWrap: 'wrap' } }, [
                    found.kev
                      ? chip(found.ransomware ? 'exploited · ransomware' : 'exploited in the wild',
                             C.danger,
                             'CISA KEV: ' + (found.kev.cves || []).join(', ')
                             + (found.kev.added ? ' (added ' + found.kev.added + ')' : ''))
                      : null,
                    found.epss !== undefined
                      ? chip('epss ' + (found.epss * 100).toFixed(1) + '%', C.warn,
                             'probability of exploitation in the next 30 days (FIRST EPSS)')
                      : null
                  ])
                : null,
              // no arrow to a comment: a row whose only "command" is a sentence ("no published fix")
              // used to print `→ # diskcache: …`, which reads like something to run and is not
              found && !String(buildFixCommand(row, found)).startsWith('#')
                ? jsx('div', {
                    style: {
                      fontFamily: MONO, fontSize: '0.6875rem', color: C.faint,
                      marginTop: '1px', wordBreak: 'break-all'
                    }
                  }, '→ ' + buildFixCommand(row, found))
                : null,
              found && found.workaround
                ? jsx('div', {
                    style: { fontSize: '0.6875rem', color: C.warn, marginTop: '2px', lineHeight: 1.4 }
                  }, 'workaround, from the advisory: ' + found.workaround.slice(0, 260)
                     + (found.workaround.length > 260 ? '…' : ''))
                : null,
              noFixKeys.has(keyOf(row))
                ? (ackFor === keyOf(row)
                    ? jsxs('div', {
                        style: { display: 'flex', gap: '4px', marginTop: '3px', alignItems: 'center' }
                      }, [
                        jsx('input', {
                          key: 'reason',
                          value: ackReason,
                          onChange: (event) => setAckReason(event.target.value),
                          placeholder: 'why is this accepted? (required, kept with the record)',
                          style: {
                            flex: 1, fontFamily: MONO, fontSize: '0.6875rem', padding: '2px 6px',
                            background: 'transparent', color: C.text,
                            border: '1px solid ' + C.border, borderRadius: '3px'
                          }
                        }),
                        jsx('button', {
                          key: 'ok', type: 'button', disabled: ackBusy || !ackReason.trim(),
                          onClick: () => recordAck(row),
                          style: {
                            fontFamily: MONO, fontSize: '0.6875rem', padding: '2px 7px',
                            cursor: ackReason.trim() ? 'pointer' : 'default',
                            color: ackReason.trim() ? C.accent : C.faint,
                            background: 'transparent', border: '1px solid ' + C.border,
                            borderRadius: '3px'
                          }
                        }, 'record'),
                        jsx('button', {
                          key: 'no', type: 'button',
                          onClick: () => { setAckFor(null); setAckReason('') },
                          style: {
                            fontFamily: MONO, fontSize: '0.6875rem', padding: '2px 7px',
                            cursor: 'pointer', color: C.dim, background: 'transparent',
                            border: '1px solid ' + C.border, borderRadius: '3px'
                          }
                        }, 'cancel')
                      ])
                    : jsx('button', {
                        type: 'button',
                        onClick: () => { setAckFor(keyOf(row)); setAckReason('') },
                        title: 'records this advisory as accepted, with your reason, for 90 days',
                        style: {
                          marginTop: '3px', fontFamily: MONO, fontSize: '0.6875rem',
                          padding: '1px 7px', cursor: 'pointer', color: C.dim,
                          background: 'transparent', border: '1px solid ' + C.border,
                          borderRadius: '3px'
                        }
                      }, 'acknowledge'))
                : null
            ])
          })),
          // an acknowledgement is a record, not a filter: it stays on screen with its reason and its
          // end date, and it can be reopened. Nothing is ever deleted by it.
          acknowledged.length
            ? jsxs('div', { style: { marginTop: '4px' } }, [
                jsx('button', {
                  key: 'toggle',
                  type: 'button',
                  onClick: () => setShowAcked((current) => !current),
                  style: {
                    fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 7px', cursor: 'pointer',
                    color: showAcked ? C.accent : C.faint, background: 'transparent',
                    border: '1px solid ' + C.border, borderRadius: '3px'
                  }
                }, (showAcked ? 'hide ' : 'show ') + acknowledged.length + ' acknowledged'),
                showAcked
                  ? jsx('div', { style: { marginTop: '3px' } }, acknowledged.map((row, index) => {
                      const ack = row.ack || {}
                      const until = ack.until
                        ? new Date(ack.until * 1000).toISOString().slice(0, 10) : 'no end date'
                      return jsxs('div', {
                        key: index,
                        style: {
                          display: 'flex', gap: '6px', alignItems: 'baseline',
                          fontSize: '0.6875rem', color: C.faint, marginBottom: '2px'
                        }
                      }, [
                        jsx('span', { key: 'id', style: { fontFamily: MONO, color: C.dim } },
                          row.package + '@' + row.version + ' · ' + row.id),
                        jsx('span', { key: 'why', style: { flex: 1 } },
                          '“' + (ack.reason || 'no reason recorded') + '” · until ' + until),
                        jsx('button', {
                          key: 'reopen',
                          type: 'button',
                          onClick: () => reopenAck(row),
                          title: 'puts the finding back into the count',
                          style: {
                            fontFamily: MONO, fontSize: '0.6875rem', padding: '0 6px',
                            cursor: 'pointer', color: C.dim, background: 'transparent',
                            border: '1px solid ' + C.border, borderRadius: '3px'
                          }
                        }, 'reopen')
                      ])
                    }))
                  : null
              ])
            : null,
          noFixKeys.size && !showAll
            ? jsxs('div', {
                style: { display: 'flex', alignItems: 'center', gap: '6px', marginTop: '4px' }
              }, [
                jsx('button', {
                  key: 'toggle',
                  type: 'button',
                  onClick: () => setShowNoFix((current) => !current),
                  title: 'an advisory with no fixed version cannot be installed — the operator can '
                         + 'record it as accepted, with a reason and an end date',
                  style: {
                    fontFamily: MONO, fontSize: '0.75rem', padding: '2px 8px', cursor: 'pointer',
                    color: showNoFix ? C.accent : C.dim, background: 'transparent',
                    border: '1px solid ' + (showNoFix ? C.accent : C.border), borderRadius: '3px'
                  }
                }, (showNoFix ? 'hide ' : 'show ') + noFixKeys.size + ' package(s) / '
                   + noFixRows.length + ' advisory(ies) with no published fix'),
                jsx('span', { key: 'why', style: { fontSize: '0.6875rem', color: C.faint } },
                  'nothing to run — the advisory names no fixed version')
              ])
            : null,
          !rows.length
            ? jsx('div', { style: { fontSize: '0.8125rem', color: C.faint } },
                needle ? 'nothing matches the filter'
                  : noFixKeys.size ? 'no finding here has a fix to install — the line above lists the '
                                     + 'ones that do not'
                  : 'nothing was read')
            : null,
          // "3 packages, 0 findings" with no explanation is the empty state that reads as broken
          libraries && mine.length && !flagged.length
            ? jsx('div', {
                style: { fontSize: '0.8125rem', color: C.ok, marginTop: '3px' }
              }, 'nothing to upgrade here: ' + mine.length + ' package(s) read and no published '
               + 'advisory names these versions. The copy control appears when there is a command '
               + 'to copy.')
            : null,
          hidden > 0
            ? jsx('div', { style: { fontSize: '0.75rem', color: C.faint, marginTop: '3px' } },
                hidden + ' more package(s) read and clean (no advisory names their version) — '
                + '“show all ' + matching.length + '” lists them')
            : jsx('div', { style: { fontSize: '0.75rem', color: C.faint, marginTop: '3px' } },
                rows.length + ' row(s) in the box above — it scrolls, the filter narrows'),
          // Hermes's own environment is measured, but it is not an alert. The only lever is
          // `hermes update`, and an advisory there clears when the agent ships past it — so a count
          // of them is a wall the operator rightly called noise. Named only when one of them is
          // being exploited: that is a fact about this machine, whatever the fix path is.
          agentOwned.length && findingsAgent.some((v) => v.kev)
            ? jsxs('div', {
                style: {
                  marginTop: '8px', padding: '5px 8px', borderLeft: '2px solid ' + C.warn,
                  borderRadius: '3px'
                }
              }, [
                jsxs('div', {
                  style: { display: 'flex', alignItems: 'baseline', gap: '8px', fontSize: '0.75rem', color: C.warn }
                }, [
                  jsx('span', {}, findingsAgent.filter((v) => v.kev).length
                    + ' exploited advisory(ies) sit in packages Hermes itself ships — `hermes update` '
                    + 'is the lever, and this machine cannot close it sooner'),
                  jsx('span', { style: { flex: 1 } }),
                  jsx('button', {
                    type: 'button',
                    onClick: () => setShowHermes((current) => !current),
                    style: {
                      fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 7px', cursor: 'pointer',
                      color: showHermes ? C.accent : C.faint, background: 'transparent',
                      border: '1px solid ' + C.border, borderRadius: '2px'
                    }
                  }, showHermes ? 'hide' : 'show')
                ]),
                showHermes
                  ? jsx('div', {
                      style: {
                        fontFamily: MONO, fontSize: '0.6875rem', color: C.faint, marginTop: '3px',
                        maxHeight: '90px', overflowY: 'auto', wordBreak: 'break-all'
                      }
                    }, agentOwned.map((row) => jsx('div', { key: keyOf(row) },
                        row.package + '@' + row.version
                        + (hit.has(keyOf(row)) ? '  · ' + foundByPackage[keyOf(row)].count + ' advisory(ies)' : ''))))
                  : null
              ])
            : null
        ])
      : jsx('div', { style: { fontSize: '0.75rem', color: C.faint, padding: '6px 0' } },
          'not read yet — press check. It reads npm\'s global tree and the pip environment on PATH; '
          + 'project lockfiles are not read automatically (see GAPS).')
  ])
}

// --------------------------------------------------------------------------- PENDING


/**
 * Integrity: is this host still running what was installed on it?
 *
 * The reading takes tens of seconds (a package database is large), so it is never run by a scan and
 * never run silently: the section shows the last reading with its age, and a button takes a fresh one.
 * Three rows, each either measured or saying why not — and the section never prints "not compromised".
 */
function IntegrityPanel({ reading, busy, seconds, onRead, onRebaseline, onImport }) {
  const [open, setOpen] = useState(false)
  const [pasteOpen, setPasteOpen] = useState(false)
  const [pasteText, setPasteText] = useState('')
  const state = reading && reading.integrity
  const answers = (reading && reading.answers) || []
  const age = agoAt(reading && reading.read_at)
  const tone = (value) => (value === 'finding' ? C.danger
    : value === 'ok' ? C.ok
    : value === 'baseline' ? C.warn : C.faint)

  return jsxs('section', { style: sectionStyle('integrity') }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label(SECTION.integrity.title),
      jsx('span', {
        style: { fontSize: '0.6875rem', color: C.faint }
      }, state
        ? (age ? 'read ' + age : 'read')
        : 'not read yet'),
      jsx('button', {
        type: 'button',
        onClick: () => onRead(),
        disabled: busy,
        title: 'verifies package checksums, the preload hook and the listening sockets — about a '
               + 'minute on a full package database',
        style: {
          marginLeft: 'auto', fontFamily: MONO, fontSize: '0.75rem', padding: '3px 9px',
          cursor: busy ? 'default' : 'pointer', color: busy ? C.faint : C.accent,
          background: 'transparent', border: '1px solid ' + C.border, borderRadius: '3px'
        }
      }, busy
        ? [jsx('span', { key: 'dot', className: 'ps-dot' }), ' reading' + (seconds ? ' ' + seconds + 's' : '')]
        : (state ? 'read again' : 'read integrity'))
    ]),
    busy
      ? jsx(ScanLine, { label: 'verifying package checksums, the preload hook and the listening sockets'
                               + (seconds ? ' · ' + seconds + ' s' : '') })
      : null,
    !state && !busy
      ? jsx('div', { style: { fontSize: '0.8125rem', color: C.dim, lineHeight: 1.5 } },
          'Not measured yet. This is the one check that answers whether what is installed is still '
          + 'what was installed — package checksums, a preloaded library hook, and sockets that were '
          + 'not there before. It takes about a minute and runs only when you ask.')
      : state ? jsxs('div', {}, [
          jsx('div', {
            style: { fontSize: '0.8125rem', color: tone(state.state), marginBottom: '4px' }
          }, reading.answer || ''),
          jsx('div', {
            style: {
              border: '1px solid ' + C.border, borderRadius: '3px', background: C.panel,
              padding: '4px 7px'
            }
          }, answers.map((row, index) => jsxs('div', {
            key: index,
            style: { padding: '2px 0', borderTop: index ? '1px solid ' + C.border : 'none' }
          }, [
            jsxs('div', {
              key: 'line',
              style: { display: 'flex', gap: '8px', alignItems: 'baseline' }
            }, [
            jsx('span', {
              key: 'chip',
              style: {
                fontFamily: MONO, fontSize: '0.6875rem', textTransform: 'uppercase',
                letterSpacing: '0.04em', color: tone(row.state), minWidth: '74px'
              }
            }, row.state === 'baseline' ? 'baseline' : row.state === 'ok' ? 'measured'
              : row.state === 'finding' ? 'finding' : 'could not look'),
            jsx('span', {
              key: 'what', style: { fontSize: '0.8125rem', color: C.text, minWidth: '132px' }
            }, row.check),
            jsx('span', {
              key: 'detail',
              style: { flex: 1, fontSize: '0.75rem', color: C.dim, wordBreak: 'break-word' }
            }, (row.detail || '')
               + ((row.items || []).length ? ' — ' + row.items.slice(0, 4).join(', ') : ''))
            ]),
            row.advice
              ? jsx('div', {
                  key: 'advice',
                  style: { fontSize: '0.6875rem', color: C.faint, marginTop: '2px', lineHeight: 1.55 }
                }, withCode(row.advice))
              : null
          ]))),
          reading.integrity && reading.integrity.note
            ? jsx('div', {
                style: { fontSize: '0.75rem', color: C.warn, marginTop: '4px', lineHeight: 1.55 }
              }, withCode(reading.integrity.note))
            : null,
          // a reading only root can take: the operator runs the command, the pane reads the paste.
          // Labelled as theirs — this is coverage the plugin did not measure itself.
          reading.integrity && reading.integrity.tamper && reading.integrity.tamper.command
            ? (pasteOpen
                ? jsxs('div', { style: { marginTop: '5px' } }, [
                    jsx('div', {
                      key: 'hint',
                      style: { fontSize: '0.6875rem', color: C.faint, marginBottom: '3px' }
                    }, 'Paste what ' + reading.integrity.tamper.command + ' printed — even a run that '
                       + 'printed nothing. The pane reads it and says what it found; it never runs '
                       + 'sudo itself.'),
                    jsx('textarea', {
                      key: 'box',
                      value: pasteText,
                      onChange: (event) => setPasteText(event.target.value),
                      rows: 4,
                      spellCheck: false,
                      placeholder: '??5?????? c /etc/default/ufw',
                      style: {
                        width: '100%', fontFamily: MONO, fontSize: '0.6875rem', padding: '4px 6px',
                        background: 'transparent', color: C.text, border: '1px solid ' + C.border,
                        borderRadius: '3px', resize: 'vertical'
                      }
                    }),
                    jsxs('div', {
                      key: 'row', style: { display: 'flex', gap: '5px', marginTop: '4px' }
                    }, [
                      jsx('button', {
                        key: 'go', type: 'button', disabled: busy || !pasteText.trim(),
                        onClick: async () => {
                          const answer = await onImport(pasteText)
                          if (answer !== false) { setPasteOpen(false); setPasteText('') }
                        },
                        style: {
                          fontFamily: MONO, fontSize: '0.6875rem', padding: '2px 8px',
                          cursor: pasteText.trim() ? 'pointer' : 'default',
                          color: pasteText.trim() ? C.accent : C.faint, background: 'transparent',
                          border: '1px solid ' + C.border, borderRadius: '3px'
                        }
                      }, 'read the paste'),
                      jsx('button', {
                        key: 'x', type: 'button',
                        onClick: () => { setPasteOpen(false); setPasteText('') },
                        style: {
                          fontFamily: MONO, fontSize: '0.6875rem', padding: '2px 8px',
                          cursor: 'pointer', color: C.dim, background: 'transparent',
                          border: '1px solid ' + C.border, borderRadius: '3px'
                        }
                      }, 'cancel')
                    ])
                  ])
                : jsxs('div', {
                    style: { display: 'flex', gap: '8px', alignItems: 'center', marginTop: '4px' }
                  }, [
                    jsx('button', {
                      key: 'paste',
                      type: 'button',
                      onClick: () => setPasteOpen(true),
                      title: 'the pane cannot elevate; paste the output of the command above and it '
                             + 'will read it, labelled as a run you made',
                      style: {
                        fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 7px', cursor: 'pointer',
                        color: (reading.integrity.tamper.covered ? C.ok : C.dim),
                        background: 'transparent', border: '1px solid ' + C.border, borderRadius: '3px'
                      }
                    }, reading.integrity.tamper.covered
                      ? 'paste another root reading'
                      : 'paste the root output'),
                    reading.integrity.root_reading
                      ? jsx('span', {
                          key: 'when', style: { fontSize: '0.6875rem', color: C.faint }
                        }, 'root reading pasted ' + (agoAt(reading.integrity.root_reading.at)
                          || 'earlier') + ': ' + reading.integrity.root_reading.changed_count
                          + ' file(s) changed, ' + reading.integrity.root_reading.conffile_count
                          + ' conffile(s)')
                      : null
                  ]))
            : null,
          jsxs('div', { style: { display: 'flex', gap: '8px', alignItems: 'center', marginTop: '5px' } }, [
            jsx('button', {
              key: 'why',
              type: 'button',
              onClick: () => setOpen((current) => !current),
              style: {
                fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 7px', cursor: 'pointer',
                color: open ? C.accent : C.faint, background: 'transparent',
                border: '1px solid ' + C.border, borderRadius: '3px'
              }
            }, open ? 'hide what this cannot see' : 'what this cannot see'),
            reading.integrity && reading.integrity.listeners
              && reading.integrity.listeners.state !== 'unmeasured'
              ? jsx('button', {
                  key: 'rebase',
                  type: 'button',
                  onClick: () => onRebaseline(),
                  disabled: busy,
                  title: 'accepts the sockets listening right now as the known set — use it after you '
                         + 'deploy something, not to silence a port you do not recognise',
                  style: {
                    fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 7px',
                    cursor: busy ? 'default' : 'pointer', color: C.dim, background: 'transparent',
                    border: '1px solid ' + C.border, borderRadius: '3px'
                  }
                }, 're-baseline the sockets')
              : null
          ]),
          open
            ? jsx('div', {
                style: { fontSize: '0.75rem', color: C.faint, marginTop: '4px', lineHeight: 1.5 }
              }, 'A rootkit that hides from dpkg and ss, a fileless attack, an intrusion that restored the '
               + 'checksums afterwards, and anything living only in memory are all invisible here. A '
               + 'clean reading means no evidence of tampering in the three surfaces above — not that '
               + 'this host is uncompromised. For that you need an EDR (Wazuh, auditd rules, Falco) and '
               + 'a place to send its alerts.')
            : null
        ]) : null
  ])
}

function PendingPanel({ hostLabel, plan, onPlan, limited, planning, where, libraryFindings }) {
  const steps = (plan && plan.steps) || []
  const refusals = (plan && plan.refusals) || []
  // the commands are the product; APPLY is a shortcut that most hosts cannot allow
  const whereLine = where
    ? (where.kind === 'remote'
        ? 'run them on ' + where.machine + (where.ssh ? ' — `' + where.ssh + '` — or prefix each one with it'
                                                  : ' — in a terminal there')
        : 'run them in a terminal on this machine, as yourself (the plugin\'s own sudo is not yours)')
    : ''

  return jsxs('section', { style: sectionStyle('plan') }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label(SECTION.plan.title),
      jsx('span', { style: { flex: 1 } }),
      jsx('button', {
        type: 'button',
        onClick: () => onPlan(hostLabel),
        disabled: planning || !hostLabel,
        title: planning ? 'measuring the host and turning it into commands'
                        : 'turns this host\'s pending updates into ordered commands, each with a way back',
        style: {
          fontFamily: MONO, fontSize: '0.75rem', padding: '3px 9px',
          cursor: planning || !hostLabel ? 'default' : 'pointer',
          color: planning ? C.accent : C.dim, background: 'transparent',
          border: '1px solid ' + C.border, borderRadius: '3px'
        }
      }, planning ? 'planning…' : steps.length ? 're-plan' : 'commands for ' + (hostLabel || 'this machine')),
      steps.length
        ? jsx(Copy, { text: steps.map((step) => step.command).join('\n'), what: 'all the steps' })
        : null
    ]),
    steps.length > 1
      ? jsxs('div', { style: { fontSize: '0.75rem', color: C.faint, marginBottom: '6px', lineHeight: 1.45 } }, [
          jsx('div', {}, 'These run in this order, top to bottom: the first refreshes the metadata and '
            + 'downloads (it changes nothing), the second installs.'),
          whereLine
            ? jsx('div', { style: { fontFamily: MONO, marginTop: '2px', color: C.dim } },
                whereLine)
            : null
        ])
      : null,
    steps.length
      ? steps.map((step, index) => jsxs('div', {
          key: index,
          style: {
            border: '1px solid ' + C.border, borderLeft: '2px solid ' + C.accent,
            borderRadius: '3px', padding: '8px 10px', marginBottom: '6px', background: C.panel
          }
        }, [
          jsxs('div', { style: { display: 'flex', gap: '8px', alignItems: 'baseline' } }, [
            jsx('span', { style: { fontFamily: MONO, fontSize: '0.75rem', color: C.accent } }, String(index + 1).padStart(2, '0')),
            jsx('span', { style: { flex: 1, fontSize: '0.8125rem', fontWeight: 600 } }, step.action),
            jsx(Copy, { text: step.command, what: 'the command' })
          ]),
          jsx('div', {
            style: {
              fontFamily: MONO, fontSize: '0.8125rem', color: C.text, marginTop: '4px',
              whiteSpace: 'pre-wrap', wordBreak: 'break-all'
            }
          }, step.command),
          jsx('div', { style: { fontSize: '0.8125rem', color: C.dim, marginTop: '4px' } },
            'risk ' + step.risk + ' · downtime ' + step.downtime),
          jsx('div', { style: { fontSize: '0.8125rem', color: C.faint, marginTop: '3px' } }, step.why),
          jsxs('div', { style: { fontSize: '0.8125rem', color: C.faint, marginTop: '3px' } }, [
            'verify: ', jsx('span', { style: { fontFamily: MONO } }, step.verify || '—'),
            '  ·  reverse: ', jsx('span', { style: { fontFamily: MONO } }, step.reversal || '—')
          ])
        ]))
      : jsx('div', { style: { fontSize: '0.75rem', color: libraryFindings ? C.dim : C.faint, padding: '6px 0' } },
          planning ? 'measuring the host — this can take a few seconds over ssh'
          : limited ? 'planning needs a host — pick one in NOW first'
          : libraryFindings
            ? 'nothing to install on the system: the scan found 0 pending package updates. The '
              + libraryFindings + ' library finding(s) above are fixed in their own stores — the copy '
              + 'control in libs & runtimes carries those commands, and this panel is only about the '
              + 'distro\'s package manager.'
          : plan ? 'the plan came back empty'
          : 'no plan yet — press “plan for …” to turn this host into commands'),
    refusals.length
      ? jsxs('div', {
          style: {
            marginTop: '6px', padding: '7px 9px', borderLeft: '2px solid ' + C.warn,
            background: C.panel, borderRadius: '3px'
          }
        }, [
          jsx('div', { style: { fontSize: '0.8125rem', color: C.warn, fontWeight: 600 } },
            'no steps — ' + refusals.map((r) => r.reason).join(' · ')),
          refusals.some((r) => r.detail)
            ? jsx('div', { style: { fontSize: '0.8125rem', color: C.faint, marginTop: '3px' } },
                refusals.map((r) => r.detail).filter(Boolean).join(' · '))
            : null
        ])
      : null
  ])
}

// --------------------------------------------------------------------------- GAPS

/**
 * One gap. Fixable ones are always open — they are the reason a row is not green and they are the
 * only ones with an action. Inherent limits are one line each until you ask for the detail: seven
 * paragraphs of "what this scan structurally cannot see" is a wall that reads as a broken product,
 * and the operator said so.
 */
function gapRow(gap, index, expanded) {
  const blocked = gap.kind === 'blocked'
  return jsxs('div', {
    key: index,
    style: {
      display: 'grid', gridTemplateColumns: '8px 1fr', gap: '8px', padding: '4px 0',
      borderTop: '1px solid ' + C.border
    }
  }, [
    dot(blocked ? 'red' : 'faint'),
    jsxs('div', {}, [
      jsxs('div', { style: { display: 'flex', gap: '6px', alignItems: 'baseline', flexWrap: 'wrap' } }, [
        jsx('span', { style: { fontSize: '0.75rem', color: blocked ? C.text : C.dim } }, gap.gap),
        jsx('span', { style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.faint } },
          gap.state)
      ]),
      blocked || expanded
        ? jsx('div', { style: { fontSize: '0.8125rem', color: C.faint, marginTop: '2px', lineHeight: 1.45 } },
            gap.why || '')
        : null,
      (blocked || expanded) && gap.next
        ? jsx('div', {
            style: { fontSize: '0.8125rem', marginTop: '3px', lineHeight: 1.45,
                     color: blocked ? C.warn : C.dim }
          }, (blocked ? 'to clear it: ' : 'what would close it: ') + gap.next)
        : null
    ])
  ])
}

/**
 * Gaps are scoped: `hosts` is "every" or the labels it concerns. With a host selected, the panel
 * shows what applies to *that* host — the operator's complaint was a wall of other machines' gaps.
 */
function GapsPanel({ coverage, selected }) {
  const [open, setOpen] = useState(false)
  const all = (coverage && coverage.gaps) || []
  const appliesTo = (gap) => gap.hosts === 'every' || !Array.isArray(gap.hosts)
    ? true : gap.hosts.includes(selected)
  const mine = all.filter(appliesTo)
  const elsewhere = all.length - mine.length
  const blocked = mine.filter((gap) => gap.kind === 'blocked')
  const limits = mine.filter((gap) => gap.kind !== 'blocked')

  return jsxs('section', { style: sectionStyle('gaps') }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label(SECTION.gaps.title),
      jsx('span', { style: { flex: 1 } }),
      jsx('span', { style: { fontSize: '0.75rem', color: C.faint } },
        selected ? 'what a scan of ' + selected + ' cannot see' : 'what this scan cannot see')
    ]),
    jsx('div', { style: { fontSize: '0.8125rem', color: C.faint, lineHeight: 1.45, marginBottom: '4px' } },
      'What this scan did not look at — a fact about the scan, not a fault on the host.'),
    blocked.length
      ? jsxs('div', { style: { marginBottom: '6px' } }, [
          jsx('div', { style: { fontSize: '0.75rem', color: C.danger, letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '2px' } },
            blocked.length + ' fixable — why a row is not green'),
          blocked.map((gap, index) => gapRow(gap, index, true))
        ])
      : null,
    limits.length
      ? jsxs('div', { style: { display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '2px' } }, [
          jsx('span', {
            style: { fontSize: '0.75rem', color: C.faint, letterSpacing: '0.08em', textTransform: 'uppercase' }
          }, limits.length + ' inherent limit' + (limits.length === 1 ? '' : 's')),
          jsx('span', { style: { flex: 1 } }),
          jsx('button', {
            type: 'button',
            onClick: () => setOpen((value) => !value),
            style: {
              fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 7px', cursor: 'pointer',
              color: open ? C.accent : C.faint, background: 'transparent',
              border: '1px solid ' + C.border, borderRadius: '2px'
            }
          }, open ? 'hide detail' : 'explain them')
        ])
      : null,
    limits.map((gap, index) => gapRow(gap, index, open)),
    elsewhere
      ? jsx('div', { style: { fontSize: '0.75rem', color: C.faint, marginTop: '6px' } },
          elsewhere + ' more gap(s) concern other hosts — switch host at the top to read them')
      : null,
    all.length ? null : jsx('div', { style: { fontSize: '0.8125rem', color: C.warn } },
      'coverage has not been read yet — an empty gap list is not a claim that nothing is missed')
  ])
}

// --------------------------------------------------------------------------- APPLY GATE

function ApplyGate({ hostLabel, entry, initialResult, probe }) {
  const [typed, setTyped] = useState('')
  const [result, setResult] = useState(initialResult || null)
  const [busy, setBusy] = useState(false)
  const armed = Boolean(hostLabel) && typed.trim() === hostLabel

  /**
   * Apply runs as a job too. A real upgrade took 105 s on the Fedora VM; the renderer's bridge cuts a
   * call at 30 s, so a synchronous apply would report a timeout *while the machine is being patched* —
   * the one message that invites a second, duplicate apply. Start it, follow it, show what it returned.
   */
  const run = useCallback(async (dryRun) => {
    if (!armed || busy || !entry) return
    setBusy(true)
    setResult(null)
    try {
      const started = await call('/apply', {
        method: 'POST',
        body: { host: hostLabel, confirm: typed.trim(), dry_run: dryRun }
      })
      if (started && started.error) {
        setResult({ applied: false, reason: 'the apply could not start: ' + started.error })
        return
      }
      let job = null
      for (let tick = 0; tick < 400; tick += 1) {
        await new Promise((resolve) => { setTimeout(resolve, 1500) })
        try {
          const jobs = await call('/jobs')
          job = (jobs && jobs.apply) || null
        } catch (err) {
          continue
        }
        if (job && !job.running) break
      }
      if (job && job.error) {
        setResult({ applied: false, reason: 'the apply failed: ' + job.error })
      } else if (job && job.result) {
        setResult(job.result)
      } else {
        setResult({ applied: false,
                    reason: 'the apply job is still running — check again in a moment, do not run it twice' })
      }
    } catch (err) {
      setResult({ applied: false, reason: String(err && err.message ? err.message : err) })
    } finally {
      setBusy(false)
    }
  }, [armed, busy, hostLabel, typed, entry])

  const steps = (result && result.steps) || []
  const measured = Boolean(entry)
  const blocked = Boolean(probe && probe.known && !probe.ok)
  const count = measured ? (entry.pending_count || 0) : null
  const nothingToDo = measured && count === 0
  // a host that has not answered the preflight is not a host this control may touch
  const ready = armed && measured && !nothingToDo && Boolean(probe && probe.ok)
  return jsxs('div', { style: { borderLeft: '2px solid ' + C.border, paddingLeft: '9px', marginTop: '2px' } }, [
    jsx('div', { style: { fontSize: '0.75rem', color: C.dim, marginBottom: '4px' } },
      !measured
        ? 'Nothing has been measured for ' + (hostLabel || 'this host') + ' yet — press rescan above, then come back.'
        : nothingToDo
          ? 'The scan found 0 updates on ' + hostLabel + ', so there is nothing to stage and nothing to apply. The buttons are disabled because the work is already done — not because something is broken. Rescan after you change something.'
          : 'Optional shortcut: it runs the same commands as the plan above, from here, without you '
            + 'opening a terminal. It can only work where the account Hermes runs as ('
            + ((probe && probe.where && probe.where.runs_as) || 'the agent user')
            + ') can patch without a password — root over ssh, or a no-prompt rule. Otherwise the '
            + 'plan\'s commands are the way, and nothing is lost by that.'),
    // the precondition, stated before the click instead of after it
    probe === null && measured && !nothingToDo
      ? jsx('div', { style: { fontSize: '0.75rem', color: C.faint, marginBottom: '6px' } },
          'checking whether this host allows it…')
      : probe && probe.known
        ? (blocked
            ? jsxs('div', {
                style: {
                  borderLeft: '2px solid ' + C.warn, background: C.panel, padding: '6px 8px',
                  borderRadius: '3px', marginBottom: '6px'
                }
              }, [
                jsx('div', { style: { fontSize: '0.8125rem', color: C.warn, fontWeight: 600 } },
                  'not available on ' + hostLabel + ' — and that is expected'),
                jsx('div', { style: { fontSize: '0.75rem', color: C.dim, marginTop: '2px', lineHeight: 1.45 } },
                  'sudo there asks ' + ((probe.where && probe.where.runs_as) || 'this account')
                  + ' for a password, and this plugin never asks for, holds or forwards one. Use the '
                  + 'plan above: copy the commands, run them '
                  + ((probe.where && probe.where.kind === 'remote')
                      ? 'on ' + probe.where.machine + (probe.where.ssh ? ' (`' + probe.where.ssh + '`)' : '')
                      : 'in a terminal on this machine')
                  + '.'),
                jsx('div', { style: { fontSize: '0.75rem', color: C.dim, marginTop: '2px' } },
                  'The commands and their copy control are in the plan above — nothing is missing here.')
              ])
            : jsx('div', { style: { fontSize: '0.75rem', color: C.ok, marginBottom: '6px' } },
                'this host allows it: ' + ((probe.where && probe.where.runs_as) || 'this account')
                + ' can patch without a password'))
        : null,
    nothingToDo || blocked ? null : jsxs('div', { style: { fontSize: '0.8125rem', color: C.faint, marginBottom: '6px' } }, [
      'Type ',
      jsx('code', {
        style: {
          fontFamily: MONO, color: C.accent, background: C.panel,
          padding: '0 5px', borderRadius: '2px', border: '1px solid ' + C.border
        }
      }, hostLabel || 'the host name'),
      ' exactly — that is the label selected at the top, not the machine\'s hostname. The lock exists so a stray click cannot patch a machine.'
    ]),
    armed ? jsx('div', { style: { fontSize: '0.8125rem', color: C.accent, marginBottom: '6px' } },
      'unlocked — stage first, then apply') : null,
    blocked ? null : jsxs('div', { style: { display: 'flex', gap: '6px', alignItems: 'center' } }, [
      jsx('input', {
        value: typed,
        onChange: (event) => setTyped(event.target.value),
        placeholder: hostLabel || 'host name',
        style: {
          flex: 1, fontFamily: MONO, fontSize: '0.75rem', padding: '4px 8px',
          background: 'transparent', color: C.text, border: '1px solid ' + C.border, borderRadius: '3px'
        }
      }),
      jsx('button', {
        type: 'button',
        onClick: () => run(true),
        disabled: !ready || busy,
        title: !measured ? 'nothing measured for this host yet'
             : nothingToDo ? 'nothing to stage: the scan found 0 updates'
             : !armed ? 'type the host label above to unlock' : 'stages the download, prints the command, changes nothing',
        style: {
          fontFamily: MONO, fontSize: '0.8125rem', padding: '4px 10px',
          cursor: ready && !busy ? 'pointer' : 'not-allowed',
          color: armed ? C.accent : C.faint, background: 'transparent',
          border: '1px solid ' + (armed ? C.accent : C.border), borderRadius: '3px'
        }
      }, busy ? '…' : 'stage (no change)'),
      jsx('button', {
        type: 'button',
        onClick: () => run(false),
        disabled: !ready || busy,
        title: !measured ? 'nothing measured for this host yet'
             : nothingToDo ? 'nothing to apply: the scan found 0 updates'
             : !armed ? 'type the host label above to unlock' : 'applies for real, writes a receipt with the versions before and after',
        style: {
          fontFamily: MONO, fontSize: '0.8125rem', padding: '4px 12px',
          cursor: ready && !busy ? 'pointer' : 'not-allowed',
          color: armed ? C.danger : C.faint, background: 'transparent',
          border: '1px solid ' + (armed ? C.danger : C.border), borderRadius: '3px'
        }
      }, busy ? '…' : ready ? 'apply for real' : nothingToDo ? 'nothing to apply' : 'apply — locked')
    ]),
    result
      ? jsxs('div', { style: { marginTop: '8px', borderTop: '1px dashed ' + C.border, paddingTop: '6px' } }, [
          jsx('div', {
            style: {
              fontFamily: MONO, fontSize: '0.8125rem',
              color: result.applied ? C.ok : (result.dry_run ? C.accent : C.warn)
            }
          }, (result.applied ? 'applied — ' : (result.dry_run ? 'staged, nothing changed — ' : 'refused — ')) + (result.reason || '')),
          result.expected
            ? jsx('div', { style: { fontSize: '0.75rem', color: C.dim, marginTop: '2px' } },
                'the name this gate expects: ' + result.expected)
            : null,
          steps.length
            ? jsx('div', { style: { marginTop: '4px' } }, steps.map((step, index) =>
                jsx('div', {
                  key: index,
                  style: { fontFamily: MONO, fontSize: '0.75rem', color: step.ok ? C.dim : C.danger }
                }, step.action + ' · rc ' + step.rc + ' · ' + step.duration_s + 's' + (step.ok ? '' : ' · ' + (step.output || '').slice(0, 160)))))
            : null,
          result.receipt
            ? jsx('div', { style: { marginTop: '4px', fontSize: '0.75rem', color: C.faint } },
                'receipt written · ' + (result.receipt.outcome || '') + ' · reboot owed: ' + String(Boolean(result.reboot_required)))
            : null,
          // a refusal that hands you the work is worth more than one that ends the conversation
          result.handoff && (result.handoff.commands || []).length
            ? jsxs('div', {
                style: {
                  marginTop: '6px', padding: '6px 8px', background: C.panel,
                  border: '1px solid ' + C.border, borderRadius: '3px'
                }
              }, [
                jsxs('div', { style: { display: 'flex', alignItems: 'baseline', gap: '8px' } }, [
                  jsx('span', { style: { fontSize: '0.75rem', color: C.dim } },
                    'run it yourself — ' + ((result.handoff.where && result.handoff.where.how) || 'by hand')),
                  jsx('span', { style: { flex: 1 } }),
                  jsx(Copy, { text: result.handoff.commands.join('\n'), label: 'copy both' })
                ]),
                result.handoff.where && result.handoff.where.ssh
                  ? jsx('div', {
                      style: {
                        fontFamily: MONO, fontSize: '0.6875rem', color: C.text, marginTop: '3px',
                        wordBreak: 'break-all'
                      }
                    }, 'connect: ' + result.handoff.where.ssh)
                  : null,
                result.handoff.commands.map((command, index) => jsxs('div', {
                  key: index,
                  style: {
                    fontFamily: MONO, fontSize: '0.6875rem', color: C.accent, marginTop: '3px',
                    wordBreak: 'break-all'
                  }
                }, [String(index + 1) + '. ', command])),
                result.handoff.verify
                  ? jsx('div', { style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.dim, marginTop: '3px', wordBreak: 'break-all' } },
                      'then check: ' + result.handoff.verify)
                  : null,
                result.handoff.reversal
                  ? jsx('div', { style: { fontSize: '0.6875rem', color: C.faint, marginTop: '2px', lineHeight: 1.45 } },
                      'to undo: ' + result.handoff.reversal)
                  : null,
                result.handoff.note
                  ? jsx('div', { style: { fontSize: '0.6875rem', color: C.faint, marginTop: '3px', lineHeight: 1.45 } },
                      result.handoff.note)
                  : null,
                result.handoff.where && result.handoff.where.note
                  ? jsx('div', { style: { fontSize: '0.6875rem', color: C.warn, marginTop: '2px', lineHeight: 1.45 } },
                      result.handoff.where.note)
                  : null
              ])
            : null
        ])
      : null
  ])
}

// --------------------------------------------------------------------------- root

export { VerdictBar, HostsPanel, NowPanel, UpdatesPanel, LanguagesPanel, IntegrityPanel, PendingPanel,
         GapsPanel, ApplyGate,
         buildFixCommand, fixBlock, actionableFixes, SECTIONS }

export function PatchSentinel({ compact }) {
  const [status, setStatus] = useState(null)
  const [coverage, setCoverage] = useState(null)
  const [busy, setBusy] = useState(false)
  const [selected, setSelected] = useState(null)
  const [plan, setPlan] = useState(null)
  const [planning, setPlanning] = useState(false)
  const [health, setHealth] = useState(null)
  const [libraries, setLibraries] = useState(null)
  // integrity is a slow reading with its own button, so it has its own state and its own "read at"
  const [integrity, setIntegrity] = useState(null)
  const [integrityBusy, setIntegrityBusy] = useState(false)
  const [integritySeconds, setIntegritySeconds] = useState(0)
  const [libBusy, setLibBusy] = useState(false)
  const [scanSeconds, setScanSeconds] = useState(0)
  const [scanError, setScanError] = useState(null)
  // APPLY is the plan's shortcut, folded under it and closed by default. The preflight is asked here,
  // not inside the control, so the closed row can already say whether this host allows it — the
  // operator's complaint was that APPLY looked like the flow's last step and then refused.
  const [applyOpen, setApplyOpen] = useState(false)
  const [applyProbe, setApplyProbe] = useState(null)

  useEffect(() => {
    let live = true
    setApplyProbe(null)
    if (!selected) return () => { live = false }
    call('/apply/preflight?host=' + encodeURIComponent(selected))
      .then((state) => { if (live) setApplyProbe(state) })
      .catch(() => { if (live) setApplyProbe({ ok: false, known: false, reason: 'the preflight did not answer' }) })
    return () => { live = false }
  }, [selected])

  // the stored reading for the selected host: cheap, so it loads with the page and never probes
  const loadIntegrity = useCallback(async (label) => {
    if (!label) { setIntegrity(null); return }
    try {
      setIntegrity(await call('/integrity?host=' + encodeURIComponent(label)))
    } catch (err) {
      setIntegrity(null)
    }
  }, [])

  useEffect(() => { loadIntegrity(selected) }, [selected, loadIntegrity])

  /**
   * Take a fresh reading. It is a job, not a request: verifying a package database takes tens of
   * seconds and a renderer call is cut at 30. `action: baseline` re-records the socket set.
   */
  const readIntegrity = useCallback(async (action) => {
    if (integrityBusy || !selected) return
    setIntegrityBusy(true)
    setIntegritySeconds(0)
    try {
      const started = await call('/integrity', {
        method: 'POST', body: { host: selected, action: action || 'check' }
      })
      if (started && started.error) return
      for (let tick = 0; tick < 160; tick += 1) {
        await new Promise((resolve) => { setTimeout(resolve, 1500) })
        let job = null
        try { job = ((await call('/jobs')) || {}).integrity || null } catch (err) { continue }
        if (job && job.seconds) setIntegritySeconds(job.seconds)
        if (job && !job.running) break
      }
      await loadIntegrity(selected)
    } catch (err) {
      setIntegrity({ host: selected, read_at: null, integrity: null, answers: [],
                     answer: 'the reading could not be taken: ' + String(err && err.message ? err.message : err) })
    } finally {
      setIntegrityBusy(false)
    }
  }, [integrityBusy, selected, loadIntegrity])

  // a paste is parsed by the backend and merged into the stored reading; false means "not read"
  const importIntegrity = useCallback(async (output) => {
    try {
      const answer = await call('/integrity', {
        method: 'POST', body: { host: selected, action: 'import', output }
      })
      if (answer && answer.exit_code === 2) return false
      await loadIntegrity(selected)
      return answer
    } catch (err) {
      return false
    }
  }, [selected, loadIntegrity])

  const load = useCallback(async () => {
    try {
      const [nextStatus, nextCoverage, nextHealth] = await Promise.all([
        call('/status'), call('/coverage'), call('/health').catch(() => null)
      ])
      setStatus(nextStatus)
      setCoverage(nextCoverage)
      setHealth(nextHealth)
      const labels = Object.keys((nextStatus && nextStatus.hosts) || {})
      setSelected((current) => current || labels[0] || null)
    } catch (err) {
      setStatus({ hosts: {}, blind: [], note: 'the plugin route did not answer: ' + String(err) })
    }
  }, [])

  /**
   * The one refresh control. The scan runs as a job on the backend because a renderer call is cut off
   * at 30 s and a two-server scan takes 40-60: answering inside the request told the operator it timed
   * out while the work was still finishing. So: start it, follow it, then read the stored answer.
   */
  const rescan = useCallback(async () => {
    if (busy) return
    setBusy(true)
    setScanError(null)
    setScanSeconds(0)
    try {
      const started = await call('/scan', { method: 'POST', body: {} })
      if (started && started.error) {
        setScanError('the scan could not start: ' + started.error)
        return
      }
      // follow the job; 1.5 s apart, up to ~5 minutes
      for (let tick = 0; tick < 200; tick += 1) {
        await new Promise((resolve) => { setTimeout(resolve, 1500) })
        let job = null
        try {
          const jobs = await call('/jobs')
          job = (jobs && jobs.scan) || null
        } catch (err) {
          continue                       // a poll that fails once is not a failed scan
        }
        if (job && job.seconds) setScanSeconds(job.seconds)
        if (job && !job.running) {
          if (job.error) setScanError('the scan failed: ' + job.error)
          break
        }
      }
      await load()
      setPlan(null)                      // the plan belonged to the old measurement
    } catch (err) {
      setScanError(String(err && err.message ? err.message : err))
    } finally {
      setBusy(false)
    }
  }, [busy, load])

  const doPlan = useCallback(async (label) => {
    if (!label) return
    setPlanning(true)
    setPlan(null)
    try {
      setPlan(await call('/plan', { method: 'POST', body: { host: label } }))
    } catch (err) {
      setPlan({ steps: [], refusals: [{ reason: String(err && err.message ? err.message : err) }] })
    } finally {
      setPlanning(false)
    }
  }, [])

  // the language check hits the network and takes seconds: it runs when asked, never on open
  const checkLibraries = useCallback(async (projectPath) => {
    setLibBusy(true)
    try {
      const query = projectPath ? '?project=' + encodeURIComponent(projectPath) : ''
      setLibraries(await call('/libraries' + query))
    } catch (err) {
      setLibraries({ answer: 'could not look: ' + (err && err.message ? err.message : err),
                     packages: [], vulnerable: [] })
    } finally {
      setLibBusy(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  // this machine first, then the declared hosts alphabetically: the local row is the one you act on
  const labels = useMemo(() => {
    const hosts = (status && status.hosts) || {}
    return Object.keys(hosts).sort((a, b) => {
      const localA = hosts[a] && hosts[a].target === 'local' ? 0 : 1
      const localB = hosts[b] && hosts[b].target === 'local' ? 0 : 1
      return localA - localB || a.localeCompare(b)
    })
  }, [status])

  return jsxs('div', {
    style: {
      padding: compact ? '10px 12px' : '18px 22px',
      color: C.text, fontSize: '0.8125rem',
      maxWidth: compact ? 'none' : '900px',
      // the app chrome turns selection off; a pane full of package names and commands is worthless
      // if you cannot copy a line out of it
      userSelect: 'text', WebkitUserSelect: 'text'
    }
  }, [
    jsx('style', {}, `
      .ps-title {
        font-family: ${MONO}; font-size: 1.0625rem; font-weight: 700; letter-spacing: 0.22em;
        text-transform: uppercase; color: #35d6d6; position: relative; display: inline-block;
        text-shadow: 0 0 14px rgba(53, 214, 214, 0.35);
      }
      .ps-title::before, .ps-title::after {
        content: attr(data-text); position: absolute; inset: 0; overflow: hidden;
        pointer-events: none;
      }
      .ps-title::before { color: #ff2d6f; opacity: 0.55; animation: ps-glitch-a 4.2s infinite; }
      .ps-title::after  { color: #9affe8; opacity: 0.45; animation: ps-glitch-b 3.1s infinite; }
      @keyframes ps-glitch-a {
        0%, 88%, 100% { clip-path: inset(0 0 100% 0); transform: translateX(0); }
        89% { clip-path: inset(8% 0 62% 0); transform: translateX(-2px); }
        92% { clip-path: inset(52% 0 18% 0); transform: translateX(2px); }
        95% { clip-path: inset(80% 0 2% 0);  transform: translateX(-1px); }
      }
      @keyframes ps-glitch-b {
        0%, 84%, 100% { clip-path: inset(100% 0 0 0); transform: translateX(0); }
        86% { clip-path: inset(30% 0 44% 0); transform: translateX(1px); }
        90% { clip-path: inset(64% 0 10% 0); transform: translateX(-2px); }
      }
      @media (prefers-reduced-motion: reduce) {
        .ps-title::before, .ps-title::after { animation: none; opacity: 0; }
      }
    `),
    jsxs('div', { style: { display: 'flex', gap: '8px', alignItems: 'baseline', marginBottom: '10px' } }, [
      jsx('span', { className: 'ps-title', 'data-text': 'Patch Sentinel' }, 'Patch Sentinel'),
      jsx('span', { style: { flex: 1 } }),
      labels.length
        ? jsx('select', {
            value: selected || '',
            onChange: (event) => setSelected(event.target.value),
            style: {
              fontFamily: MONO, fontSize: '0.8125rem', padding: '2px 4px',
              background: 'Canvas', color: 'CanvasText', border: '1px solid ' + C.border,
              borderRadius: '3px', colorScheme: 'light dark'
            }
          }, labels.map((name) => jsx('option', { key: name, value: name }, name)))
        : null,
      jsx('button', {
        type: 'button',
        onClick: rescan,
        disabled: busy,
        title: 're-measure every server in the inventory — the scan runs on the backend and this button '
               + 'follows it, so a long scan no longer looks like a failure',
        style: {
          fontFamily: MONO, fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.06em',
          textTransform: 'uppercase', padding: '7px 16px',
          cursor: busy ? 'default' : 'pointer',
          color: busy ? C.faint : '#06090c', background: busy ? 'transparent' : C.accent,
          border: '1px solid ' + (busy ? C.border : C.accent), borderRadius: '4px'
        }
      }, busy
        ? [jsx('span', { key: 'ring', className: 'ps-ring' }),
           'scanning ' + (scanSeconds ? Math.round(scanSeconds) + ' s' : '…')]
        : 'rescan all')
    ]),
    // the stylesheet is always mounted; the line appears only while something is being measured
    jsx('style', {}, SCAN_CSS),
    busy || libBusy
      ? jsx(ScanLine, {
          label: busy
            ? 'measuring every server — packages, kernel, images, advisories, and whether each patch '
              + 'is in effect'
            : 'reading the language stores, every virtualenv and the jars on disk'
        })
      : null,
    scanError
      ? jsx('div', { style: { fontSize: '0.8125rem', color: C.danger, marginBottom: '8px' } }, scanError)
      : null,
    health && Array.isArray(health.inventory) && health.inventory.length <= 1
      ? jsx('div', { style: { fontSize: '0.8125rem', color: C.warn, marginBottom: '10px' } },
          'the backend loaded an inventory of ' + health.inventory.length + ' host(s)'
          + (health.data_dir ? ' (data dir: ' + health.data_dir + ')' : '')
          + ' — if you declared more, it is running without its settings: restart the app.')
      : null,
    jsxs('div', {
      style: {
        fontSize: '0.8125rem', color: C.faint, lineHeight: 1.5, marginBottom: '14px',
        borderLeft: '2px solid ' + C.border, paddingLeft: '9px'
      }
    }, SECTIONS.map((section) => jsx('div', { key: section.key },
        jsx('b', { style: { color: C.dim } }, section.title), ' — ' + section.blurb))),
    jsx(VerdictBar, { status }),
    jsx(HostsPanel, { onChanged: load }),
    jsx(NowPanel, { status }),
    jsx(UpdatesPanel, { entry: status && status.hosts ? status.hosts[selected] : null,
                        hostLabel: selected }),
    jsx(IntegrityPanel, { reading: integrity, busy: integrityBusy, seconds: integritySeconds,
                          onRead: () => readIntegrity('check'),
                          onRebaseline: () => readIntegrity('baseline'),
                          onImport: importIntegrity }),
    jsx(LanguagesPanel, { libraries, onCheck: checkLibraries, busy: libBusy }),
    jsx(PendingPanel, { hostLabel: selected, plan, onPlan: doPlan, limited: !selected, planning,
                        libraryFindings: (libraries && libraries.vulnerable || [])
                          .filter((row) => row.owner !== 'hermes' && (row.fixed || []).length).length,
                        where: status && status.hosts && status.hosts[selected]
                          ? status.hosts[selected].where : null }),
    // the optional shortcut, folded under the plan it belongs to — not a step of its own
    jsxs('div', { style: { marginBottom: '14px' } }, [
      jsxs('div', { style: { display: 'flex', alignItems: 'baseline', gap: '8px' } }, [
        jsx('button', {
          type: 'button',
          onClick: () => setApplyOpen((current) => !current),
          disabled: !selected,
          title: 'runs the same commands the plan gives you, from here',
          style: {
            fontFamily: MONO, fontSize: '0.75rem', padding: '2px 8px',
            cursor: selected ? 'pointer' : 'default', color: applyOpen ? C.accent : C.faint,
            background: 'transparent', border: '1px solid ' + C.border, borderRadius: '3px'
          }
        }, (applyOpen ? '▾ ' : '▸ ') + 'run it from here instead — optional'),
        jsx('span', { style: { flex: 1 } }),
        jsx('span', {
          style: {
            fontFamily: MONO, fontSize: '0.6875rem',
            color: applyProbe && applyProbe.known && !applyProbe.ok ? C.warn : C.faint
          }
        }, applyProbe === null ? 'checking this host…'
           : !applyProbe.known ? 'unknown'
           : applyProbe.ok ? 'allowed on ' + selected
           : 'not available on ' + selected + ' — sudo needs a password there')
      ]),
      applyOpen
        ? jsx(ApplyGate, { hostLabel: selected, probe: applyProbe,
                           entry: status && status.hosts ? status.hosts[selected] : null })
        : null
    ]),
    jsx(GapsPanel, { coverage, selected }),
    jsx('div', {
      style: {
        marginTop: '12px', paddingTop: '8px', borderTop: '1px solid ' + C.border,
        fontFamily: MONO, fontSize: '0.6875rem',
        color: health && health.ui && health.ui.in_sync === false ? C.warn : C.faint
      }
    }, health && health.ui && health.ui.served
        ? 'pane build ' + health.ui.served.sha +
          (health.ui.in_sync === false
            ? ' — the app is still serving the previous build, reload it'
            : ' · matches the repo') +
          (health.api && health.api.stale
            ? ' · BACKEND STALE — the routes still run the previous code, restart the app'
            : health.api ? ' · backend current' : '')
        : 'pane build unknown — /health did not answer')
  ])
}

export default {
  id: ID,
  name: 'Patch Sentinel',
  defaultEnabled: false,
  register(ctx) {
    REST = (path, options) => ctx.rest(path, options)
    ctx.register({
      id: 'pane',
      area: 'panes',
      title: 'patch sentinel',
      data: { placement: 'right', width: '430px' },
      render: () => jsx(PatchSentinel, { compact: true })
    })
    ctx.registerMany([
      {
        id: 'page',
        area: 'routes',
        data: { path: ROUTE },
        render: () => jsx(PatchSentinel, { compact: false })
      },
      {
        id: 'nav',
        area: 'sidebar.nav',
        data: { path: ROUTE, label: 'Patch Sentinel', codicon: 'shield' }
      },
      {
        id: 'palette',
        area: 'palette',
        data: {
          id: 'patch-sentinel.open',
          label: 'Open Patch Sentinel (patch posture)',
          keywords: ['patch', 'patched', 'cve', 'security', 'updates', 'kernel'],
          run: () => host.navigate(ROUTE)
        }
      }
    ])
  }
}
