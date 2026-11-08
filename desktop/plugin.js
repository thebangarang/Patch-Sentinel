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
function agoAt(stamp) {
  if (!stamp) return null
  // two shapes arrive here: an epoch second (the integrity reading) and an ISO string (a scan's
  // measured_at). Feeding the string to the subtraction printed "NaN d ago".
  const epoch = typeof stamp === 'number' ? stamp : Date.parse(String(stamp)) / 1000
  if (!Number.isFinite(epoch)) return null
  const drift = Math.floor(Date.now() / 1000 - epoch)
  // a reading stamped in the future means the clock moved, and an age is then meaningless — say that
  // rather than print "just now" over a timestamp that cannot be trusted
  if (drift < -120) return 'timestamp is in the future — the clock on this host disagrees with the reader'
  return ago(Math.max(0, drift))
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
// One question per section, one line each. The long explanation lives in the tooltip (`long`), which
// is where a person looks when they want it — a wall of it above the pane is what makes the pane feel
// like documentation instead of an answer.
const SECTIONS = [
  { key: 'servers', title: 'servers', blurb: 'the machines this pane answers for',
    long: 'This machine plus any host you add. Click a name to make it the one the detail sections '
        + 'below are about. A host is added only after a probe of it succeeds, and only the address is '
        + 'stored — never a key.' },
  // The readings come first, in the order the scan reads them, so the page can be followed top to
  // bottom while the run animates. What to do about them, and the commands, come below: an answer
  // before the evidence ends up read as a warning list, and the evidence gets skipped.
  { key: 'packages', title: 'system packages', blurb: "the distro's update list",
    long: 'Every package apt, dnf, pacman or zypper would upgrade, with which USN or advisory names '
        + 'that exact version. Empty means the package manager listed nothing — it stays on screen so '
        + 'a quiet machine does not look like a missing section.' },
  { key: 'integrity', title: 'integrity', blurb: 'is this still what we installed?',
    long: 'Package checksums, the /etc/ld.so.preload hook and the listening sockets against the '
        + 'baseline recorded earlier. A patch scanner reads versions; an intrusion does not change a '
        + 'version. It never says "not compromised".' },
  { key: 'libs', title: 'libs & runtimes', blurb: 'language packages, against OSV',
    long: 'What each toolchain has installed machine-wide and in every project virtualenv — npm, pip, '
        + 'PHP, Ruby, Rust, .NET, Maven, Go, Dart — plus jars on disk and lockfile pins.' },
  { key: 'todo', title: 'what must be done', blurb: 'the actions, per device',
    long: 'Everything the readings above turned into something to do, one device at a time: pending '
        + 'packages, a kernel that is not running, library findings that name a fix, sockets that '
        + 'appeared, files that could not be read. Nothing here is a command — the commands are the '
        + 'section below, so a row can be read before anything is pasted.' },
  { key: 'plan', title: 'the fix commands', blurb: 'the commands to paste, in order',
    long: 'Every command the rows above imply, grouped by device and numbered: the package upgrade '
        + 'steps (with risk, downtime, how to verify and how to undo), the language-store upgrades '
        + 'that have a published fix, and the root verification for files this account cannot read. '
        + 'COPY ALL gives the whole set for every device. Nothing here runs anything: every command is '
        + 'meant to be pasted into a terminal on the device it names.' },
  // Last, and deliberately apart: it is a caveat about the measurement, not a step in it. Sitting
  // between the readings and the commands it pushed the one section everybody needs below the fold.
  { key: 'gaps', title: 'gaps', blurb: 'what this scan could not see',
    long: 'Red here is a fact about the scan, not about the server: a host that did not answer, a feed '
        + 'that refused, a surface with no reader yet.' },
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
  background: linear-gradient(90deg, transparent, #4de3d0, transparent);
  /* the delay is set from the wall clock by ScanLine, so every track on the page is at the same point
     of the same wave — a section that starts animating mid-run joins the wave instead of starting its
     own */
  animation: ps-sweep 1150ms cubic-bezier(0.4, 0, 0.2, 1) infinite;
  animation-delay: var(--ps-phase, 0ms); }
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
    // mounted here as well as at the page root: a panel rendered alone (a preview, a test) must still
    // animate, and a duplicate <style> is harmless
    jsx('style', { key: 'css' }, SCAN_CSS),
    // -now % period: the sweep's position becomes a function of the clock rather than of when this
    // element mounted, which is what makes two lines on the page look like one wave
    jsx('div', { className: 'ps-scan-track', style: { '--ps-phase': -(Date.now() % 1150) + 'ms' } }),
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

function label(text, extra, title) {
  // section headings carry the HUD accent: bigger, spaced, with a rule under them and a faint glow,
  // so the eye can jump between panels without reading a word
  return jsx('div', {
    title: title || undefined,
    style: {
      fontFamily: MONO, fontSize: '0.875rem', letterSpacing: '0.18em', fontWeight: 700,
      textTransform: 'uppercase', color: C.accent, paddingBottom: '4px',
      borderBottom: '1px solid ' + C.accent, display: 'inline-block',
      textShadow: '0 0 12px rgba(53, 214, 214, 0.28)', ...(extra || {})
    }
  }, text)
}

function Copy({ text, what, label, primary }) {
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
      fontFamily: MONO, fontSize: '0.75rem', padding: primary ? '3px 10px' : '2px 8px',
      cursor: 'pointer',
      color: done ? C.ok : (primary ? C.accent : C.dim),
      background: primary ? 'rgba(77,227,208,0.08)' : 'transparent',
      border: '1px solid ' + (done ? C.ok : (primary ? C.accent : C.border)),
      borderRadius: '3px', whiteSpace: 'nowrap'
    }
  }, done ? 'copied' : (label || 'copy'))
}

/**
 * A command is the thing the operator came for, so it gets its own block: where to run it, the text
 * in mono at reading size, and one copy control that says what it copies. Scattering the copy button
 * next to a paragraph is what made "the fix, as commands" feel like documentation.
 */
function Command({ text, where, label }) {
  return jsxs('div', {
    style: {
      border: '1px solid ' + C.border, borderLeft: '2px solid ' + C.accent,
      borderRadius: '4px', background: C.panel, padding: '6px 9px', marginTop: '5px'
    }
  }, [
    jsxs('div', {
      key: 'head',
      style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }
    }, [
      jsx('span', {
        key: 'label',
        style: {
          fontFamily: MONO, fontSize: '0.6875rem', letterSpacing: '0.08em',
          textTransform: 'uppercase', color: C.faint
        }
      }, label || 'run in a terminal'),
      where
        ? jsx('span', { key: 'where', style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.dim } },
            where)
        : null,
      jsx('span', { key: 'spacer', style: { flex: 1 } }),
      jsx(Copy, { key: 'copy', text, label: 'copy', what: 'the command', primary: true })
    ]),
    jsx('pre', {
      key: 'body',
      style: {
        fontFamily: MONO, fontSize: '0.8125rem', lineHeight: 1.55, margin: 0, color: C.text,
        whiteSpace: 'pre-wrap', wordBreak: 'break-word'
      }
    }, text)
  ])
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
    // /status carries `age_seconds`; a bundle carries `measured_at` per host. Feeding the missing
    // field to `ago()` printed "measured never measured".
    jsx('span', { style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.faint } },
      (() => {
        if (status.age_seconds !== undefined && status.age_seconds !== null) {
          return 'measured ' + ago(status.age_seconds)
        }
        const stamps = Object.values(status.hosts || {})
          .map((host) => host && host.measured_at).filter(Boolean).sort()
        return stamps.length ? 'measured ' + (agoAt(stamps[stamps.length - 1]) || 'just now')
                             : 'not measured yet'
      })())
  ])
}

// --------------------------------------------------------------------------- HOSTS

/** Add or remove a server. Addresses only — never a credential. */
function HostsPanel({ onChanged, startOpen, initialTest, initialHosts, onSelect, selected, bundle, onLoaded }) {
  // `initialHosts` exists so the panel can be rendered (and previewed) before its fetch lands; the
  // live pane never passes it
  const [hosts, setHosts] = useState(initialHosts || null)
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
      const list = (answer && answer.hosts) || []
      setHosts(list)
      if (onLoaded) {
        onLoaded(list.map((host) => ({ label: host.label, target: host.target || 'local' })))
      }
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
      label(SECTION.servers.title, null, SECTION.servers.long),
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
      onClick: onSelect ? () => onSelect(host.label) : undefined,
      title: onSelect ? 'show this device in the sections below' : undefined,
      style: {
        display: 'grid', gridTemplateColumns: '10px 1fr auto auto auto', gap: '8px',
        alignItems: 'baseline', fontFamily: MONO, fontSize: '0.75rem', padding: '3px 0',
        borderTop: '1px solid ' + C.border,
        cursor: onSelect ? 'pointer' : 'default'
      }
    }, [
      // the same shape the overview uses: a terminal window for this machine, a rack for a LAN
      // address, a globe for a remote host
      jsx('span', { style: { display: 'inline-flex' } }, deviceIcon(deviceKind(host))),
      jsx('span', {
        style: { color: selected === host.label ? C.accent : C.text,
                 textDecoration: selected === host.label ? 'underline' : 'none' }
      }, host.label),
      jsx('span', { style: { color: C.dim } }, host.target === 'local' ? 'this machine' : host.target),
      (() => {
        // what this device looks like without selecting it: the badge is the only fleet-wide thing
        // left, and it is deliberately one word plus a count
        if (!bundle) return jsx('span', {}, '')
        const scan = ((bundle.devices || {})[host.label] || {}).scan || {}
        const entry = (scan.hosts || {})[host.label] || null
        if (!entry) {
          return jsx('span', { style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.faint } },
                     'not measured')
        }
        const todo = todoRows({ bundle, label: host.label, entry })
        const actions = todo.filter((row) => row.level === 'amber' || row.level === 'red').length
        return jsx('span', {
          style: { fontFamily: MONO, fontSize: '0.6875rem', color: actions ? C.warn : C.ok }
        }, actions ? actions + ' to do' : 'nothing to do')
      })(),
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
              // the row itself selects the device; removing it must not also change what the pane shows
              onClick: (event) => { if (event && event.stopPropagation) event.stopPropagation(); remove(host) },
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

// --------------------------------------------------------------------------- UPDATES

/** The raw update list for the selected host — every package, searchable, copyable. */
function UpdatesPanel({ entry, hostLabel, scanning }) {
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
      label(SECTION.packages.title, null, SECTION.packages.long),
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
    // this section's own sweep: the top line says a run is going, this one says which part is
    scanning
      ? jsx(ScanLine, { label: 'reading the package list — what the archive would install, and which '
                             + 'advisory names that exact version' })
      : null,
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
function LanguagesPanel({ libraries, onCheck, busy, scanning }) {
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
      label(SECTION.libs.title, null, SECTION.libs.long),
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
                ? findingsMine.length + ' finding(s)'
                : 'nothing to upgrade'))
        : null,
      flagged && flagged.length && commandCount
        ? jsx(Copy, { text: fixText, primary: true,
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
      }, busy ? [jsx('span', { key: 'dot', className: 'ps-dot' }), 'reading']
         : libraries ? 'read again' : 'read it')
    ]),
    busy || scanning
      ? jsx(ScanLine, {
          label: 'reading the installed packages, every project virtualenv, the jars on disk and the '
                 + 'lockfile pins'
        })
      : null,
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
          // The answer used to be one paragraph carrying six facts in a single sentence. It is now a
          // short list: one fact per line, a label you can skim past, and the long form in the title.
          jsxs('div', {
            style: { marginBottom: '6px' },
            title: (libraries.answer || '')
          }, [
            jsx(Line, { key: 'a', name: 'advisories',
              children: findingsMine.length
                ? findingsMine.length + ' on ' + flagged.length + ' package(s) — '
                  + (commandCount
                      ? commandCount + ' command(s) to copy, ' + mineWithFix.length + ' with a fix'
                      : 'nothing to run, no published fix')
                : 'none against the exact versions installed' }),
            jsx(Line, { key: 'r', name: 'read', children: [
              packages.length + ' package(s)',
              environmentCount
                ? environmentCount + ' project environments ('
                  + packages.filter((p) => envName(p.source)).length + ' packages)'
                : null,
              packages.filter((p) => !envName(p.source) && p.owner !== 'hermes').length + ' from language stores'
            ].filter(Boolean).join(' · ') }),
            packages.filter((p) => p.owner === 'hermes').length
              ? jsx(Line, { key: 'h', name: 'hermes', children:
                  packages.filter((p) => p.owner === 'hermes').length + ' package(s) ship with the agent — '
                  + '`hermes update` is their lever, not counted above' })
              : null,
            libraries.distro_managed && libraries.distro_managed.advisories
              ? jsx(Line, { key: 'd', name: 'distro', children:
                  libraries.distro_managed.advisories + ' advisory(ies) on '
                  + libraries.distro_managed.packages + ' package(s) the distribution installed ('
                  + (libraries.distro_managed.names || []).join(', ')
                  + ') — fixed through apt/dnf, not by pip' })
              : null,
            (libraries.unversioned || []).length
              ? jsx(Line, { key: 'u', name: 'not compared', children:
                  (libraries.unversioned || []).map((row) => row.package).slice(0, 4).join(', ')
                  + ' at version 0.0.0 — an in-tree install has no published version to match' })
              : null,
            missingEcosystems.length
              ? jsx(Line, { key: 'm', name: 'not here', children:
                  missingEcosystems.join(', ') + ' — not installed on this host, so not read' })
              : null
          ]),
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
          commandCount
            ? jsx(Command, {
                text: fixText,
                label: 'the fix — ' + commandCount + ' command(s)',
                where: '· on ' + (hostLabel || 'this machine')
              })
            : null,
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
/** One labelled fact per line — the shape a person can skim, instead of a paragraph. */
function Line({ name, children }) {
  return jsxs('div', {
    style: { display: 'flex', gap: '8px', alignItems: 'baseline', padding: '1px 0' }
  }, [
    jsx('span', {
      style: {
        minWidth: '104px', flex: '0 0 auto', fontFamily: MONO, fontSize: '0.6875rem',
        letterSpacing: '0.06em', textTransform: 'uppercase', color: C.faint
      }
    }, name),
    jsx('span', { style: { flex: 1, fontSize: '0.75rem', color: C.dim, lineHeight: 1.5 } }, children)
  ])
}

function IntegrityPanel({ reading, busy, seconds, onRead, onRebaseline, onImport, onAttest }) {
  const [limits, setLimits] = useState(false)
  const [pasteOpen, setPasteOpen] = useState(false)
  // what the last paste or attestation changed — a silent success reads as "nothing happened"
  const [notice, setNotice] = useState(null)
  const [pasteText, setPasteText] = useState('')
  const [error, setError] = useState(null)

  const state = reading && reading.integrity
  const answers = (reading && reading.answers) || []
  const tamper = (state && state.tamper) || {}
  const listeners = (state && state.listeners) || {}
  const coverage = state && state.root_coverage
  const age = agoAt(reading && reading.read_at)
  const tone = (value) => (value === 'finding' ? C.danger
    : value === 'ok' ? C.ok : value === 'baseline' ? C.warn : C.faint)

  // One action per row, where the row is. A pile of buttons under the table made the operator ask
  // "what are these for" — each control now sits next to the reading it acts on.
  const smallButton = (text, onClick, title, disabled) => jsx('button', {
    type: 'button', onClick, title, disabled,
    style: {
      fontFamily: MONO, fontSize: '0.6875rem', padding: '2px 8px', whiteSpace: 'nowrap',
      cursor: disabled ? 'default' : 'pointer', color: disabled ? C.faint : C.accent,
      background: 'transparent', border: '1px solid ' + C.border, borderRadius: '3px'
    }
  }, text)

  const submitPaste = async () => {
    setError(null)
    const answer = await onImport(pasteText)
    if (!answer || answer === false || answer.exit_code === 2) {
      setError((answer && answer.reason)
        || 'that paste was not read — it was empty, or this host has no package database to compare '
           + 'it with. Nothing changed.')
      return
    }
    setPasteOpen(false)
    setPasteText('')
    setNotice((answer && answer.answer)
      || 'coverage complete — the root run found nothing changed. The finding is closed.')
  }

  return jsxs('section', { style: sectionStyle('integrity') }, [
    jsxs('div', {
      style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px', flexWrap: 'wrap' }
    }, [
      label(SECTION.integrity.title, null, SECTION.integrity.long),
      jsx('span', { style: { fontSize: '0.75rem', color: C.faint } },
        state ? (age ? 'read ' + age : 'read') : 'not read yet'),
      jsx('button', {
        type: 'button',
        onClick: () => setLimits((current) => !current),
        style: {
          marginLeft: 'auto', fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 7px',
          cursor: 'pointer', color: limits ? C.accent : C.faint, background: 'transparent',
          border: '1px solid ' + C.border, borderRadius: '3px'
        }
      }, limits ? 'hide the limits' : 'what this cannot see'),
      jsx('button', {
        type: 'button',
        onClick: () => onRead(),
        disabled: busy,
        title: 'verifies package checksums, the preload hook and the listening sockets — about a '
               + 'minute on a full package database',
        style: {
          fontFamily: MONO, fontSize: '0.75rem', padding: '3px 10px', cursor: busy ? 'default' : 'pointer',
          color: busy ? C.faint : C.accent, background: 'transparent',
          border: '1px solid ' + C.border, borderRadius: '3px'
        }
      }, busy
        ? [jsx('span', { key: 'ring', className: 'ps-ring' }), 'reading' + (seconds ? ' ' + seconds + 's' : '')]
        : (state ? 'read again' : 'read it'))
    ]),
    limits
      ? jsx('div', {
          style: { fontSize: '0.75rem', color: C.faint, marginBottom: '6px', lineHeight: 1.55 }
        }, 'A rootkit that hides from dpkg and ss, a fileless attack, an intrusion that restored the '
           + 'checksums afterwards, and anything living only in memory are invisible here. A clean '
           + 'reading means no evidence of tampering in the three surfaces below — not that this host '
           + 'is uncompromised. For that you need an EDR (Wazuh, auditd rules, Falco) and a place to '
           + 'send its alerts.')
      : null,
    busy
      ? jsx(ScanLine, {
          label: 'verifying package checksums, the preload hook and the listening sockets'
                 + (seconds ? ' · ' + seconds + ' s' : '')
        })
      : null,
    notice
      ? jsx('div', {
          style: { fontSize: '0.8125rem', color: C.ok, lineHeight: 1.5, marginBottom: '6px',
                   paddingLeft: '9px', borderLeft: '2px solid ' + C.ok }
        }, notice)
      : null,
    !state && !busy
      ? jsx('div', { style: { fontSize: '0.8125rem', color: C.dim, lineHeight: 1.5 } },
          'Not read yet — this is the check that answers “has anything on this host changed without '
          + 'the package manager?” It takes about a minute and runs only when you press the button.')
      : null,
    state
      ? jsxs('div', {}, [
          jsx('div', {
            style: { fontSize: '0.8125rem', color: tone(state.state), marginBottom: '4px', lineHeight: 1.5 }
          }, reading.answer || ''),
          answers.map((row, index) => {
            const isChecksums = row.check === 'package checksums'
            const isSockets = row.check === 'listening sockets'
            return jsxs('div', {
              key: index,
              style: { padding: '5px 0', borderTop: '1px solid ' + C.border }
            }, [
              jsxs('div', {
                key: 'line', style: { display: 'flex', gap: '8px', alignItems: 'baseline', flexWrap: 'wrap' }
              }, [
                chip(row.state === 'baseline' ? 'baseline'
                  : row.state === 'ok' ? 'measured'
                  : row.state === 'finding' ? 'finding' : 'not looked', tone(row.state)),
                jsx('span', {
                  key: 'what', style: { fontSize: '0.8125rem', color: C.text, minWidth: '150px' }
                }, row.check),
                jsx('span', {
                  key: 'detail', style: { flex: 1, fontSize: '0.75rem', color: C.dim, lineHeight: 1.5 }
                }, (row.detail || '')
                   + ((row.items || []).length ? ' — ' + row.items.slice(0, 4).join(' · ') : '')),
                isChecksums && tamper.state !== 'unmeasured'
                  ? (coverage
                      ? jsx('span', {
                          key: 'covered',
                          style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.ok, whiteSpace: 'nowrap' }
                        }, 'root run ' + (agoAt(coverage.at) || 'on file'))
                      : jsxs('span', { key: 'paste-or-clean', style: { display: 'flex', gap: '6px' } }, [
                          smallButton('paste the root output',
                            () => { setPasteOpen(true); setError(null) },
                            'the pane cannot run sudo; paste what the command above printed and it '
                            + 'will read it'),
                          onAttest
                            ? smallButton('it printed nothing', async () => {
                                const answer = await onAttest()
                                if (answer && answer.exit_code !== 2) {
                                  setNotice(answer.answer || 'coverage complete — the finding is closed.')
                                } else if (answer) {
                                  setNotice(null)
                                  setError(answer.reason || 'that could not be recorded')
                                }
                              },
                                'a clean run prints nothing — this records that you ran it as root '
                                + 'and there was nothing to paste')
                            : null
                        ]))
                  : null,
                isSockets && row.state === 'finding'
                  ? smallButton('these are mine — accept them',
                      () => onRebaseline(),
                      'accepts the sockets listening now as the known set; only for ports you meant '
                      + 'to open')
                  : null
              ]),
              row.advice
                ? jsx('div', {
                    key: 'advice',
                    style: { fontSize: '0.6875rem', color: C.faint, marginTop: '3px', lineHeight: 1.55 }
                  }, withCode(row.advice))
                : null
            ])
          }),
          pasteOpen
            ? jsxs('div', {
                style: {
                  marginTop: '6px', padding: '7px 9px', border: '1px solid ' + C.border,
                  borderLeft: '2px solid ' + C.accent, borderRadius: '4px'
                }
              }, [
                jsx('div', {
                  key: 'hint', style: { fontSize: '0.75rem', color: C.faint, marginBottom: '4px' }
                }, 'Run ' + (tamper.command || 'the command') + ' in a terminal, then paste what it '
                   + 'printed here. The pane reads it and labels it as your run, not its own.'),
                jsx('textarea', {
                  key: 'box', value: pasteText,
                  onChange: (event) => setPasteText(event.target.value),
                  rows: 4, spellCheck: false, placeholder: '??5?????? c /etc/default/ufw',
                  style: {
                    width: '100%', fontFamily: MONO, fontSize: '0.75rem', padding: '5px 7px',
                    background: 'transparent', color: C.text, border: '1px solid ' + C.border,
                    borderRadius: '3px', resize: 'vertical'
                  }
                }),
                jsxs('div', {
                  key: 'row', style: { display: 'flex', gap: '5px', marginTop: '4px' }
                }, [
                  jsx('button', {
                    key: 'go', type: 'button', disabled: busy || !pasteText.trim(), onClick: submitPaste,
                    style: {
                      fontFamily: MONO, fontSize: '0.6875rem', padding: '2px 9px',
                      cursor: pasteText.trim() ? 'pointer' : 'default',
                      color: pasteText.trim() ? C.accent : C.faint, background: 'transparent',
                      border: '1px solid ' + C.border, borderRadius: '3px'
                    }
                  }, 'read the paste'),
                  jsx('button', {
                    key: 'x', type: 'button',
                    onClick: () => { setPasteOpen(false); setPasteText(''); setError(null) },
                    style: {
                      fontFamily: MONO, fontSize: '0.6875rem', padding: '2px 9px', cursor: 'pointer',
                      color: C.dim, background: 'transparent', border: '1px solid ' + C.border,
                      borderRadius: '3px'
                    }
                  }, 'cancel')
                ])
              ])
            : null,
          error
            ? jsx('div', {
                style: { fontSize: '0.75rem', color: C.danger, marginTop: '5px', lineHeight: 1.5 }
              }, error)
            : null,
          coverage
            ? jsx('div', {
                style: { fontSize: '0.6875rem', color: C.dim, marginTop: '5px' }
              }, 'your last root run: ' + (coverage.changed_count || 0) + ' file(s) changed, '
                 + (coverage.conffile_count || 0) + ' conffile(s), ' + (agoAt(coverage.at) || 'undated')
                 + (coverage.tool ? ' · ' + coverage.tool : ''))
            : null,
          state.note
            ? jsx('div', {
                style: { fontSize: '0.75rem', color: C.warn, marginTop: '5px', lineHeight: 1.55 }
              }, withCode(state.note))
            : null
        ])
      : null
  ])
}

// ------------------------------------------------------------------ WHAT MUST BE DONE
// One list, one place, every device. The pane used to make the operator assemble this themselves out
// of five sections with their own buttons; the list below is the answer to "what do I have to do",
// and the section after it is the answer to "with what". Rows carry no command — a command belongs in
// "the fix", where it can be copied — they carry the reason it exists.

/** Devices in the order a person reads them: the machine in front of them first, then the rest. */
function orderedHosts(bundle) {
  const devices = (bundle && bundle.devices) || {}
  const entries = (bundle && bundle.scan && bundle.scan.hosts) || {}
  const labels = Object.keys(devices).length ? Object.keys(devices) : Object.keys(entries)
  const target = (label) => {
    const scan = ((devices[label] || {}).scan || {}).hosts || {}
    const entry = scan[label] || entries[label] || {}
    return entry.target === null || entry.target === undefined ? 'local' : String(entry.target)
  }
  return labels.sort((a, b) => {
    const localA = target(a) === 'local' ? 0 : 1
    const localB = target(b) === 'local' ? 0 : 1
    return localA - localB || a.localeCompare(b)
  }).map((label) => {
    const scan = ((devices[label] || {}).scan || {}).hosts || {}
    return { label, entry: scan[label] || entries[label] || {} }
  })
}

/** This device's scan entry, whichever bundle shape it came from. */
function deviceScan(bundle, label) {
  const device = ((bundle && bundle.devices) || {})[label] || {}
  const fromDevice = ((device.scan || {}).hosts || {})[label]
  if (fromDevice) return fromDevice
  return ((bundle && bundle.scan && bundle.scan.hosts) || {})[label] || null
}

/**
 * The answer one device gave for one surface. The bundle keeps a block per device, because "rescan
 * all" reads every host; the older top-level keys are this machine's, kept for an old bundle.
 */
function deviceOf(bundle, label) {
  return ((bundle && bundle.devices) || {})[label] || {}
}

function deviceLibraries(bundle, label) {
  const device = deviceOf(bundle, label)
  if (device.libraries) return device.libraries
  const one = bundle && bundle.libraries
  return one && one.host && one.host.label === label ? one : null
}

function deviceIntegrity(bundle, label) {
  const device = deviceOf(bundle, label)
  if (device.integrity) return device.integrity
  const one = bundle && bundle.integrity
  return one && one.host && one.host.label === label ? one : null
}

function devicePlan(bundle, label) {
  const device = deviceOf(bundle, label)
  if (device.plan) return device.plan
  return ((bundle && bundle.plans && bundle.plans.plans) || {})[label] || null
}

/** Findings that name a fix ahead of the installed version — the only ones with a command. */
function fixableRows(libraries) {
  return ((libraries && libraries.vulnerable) || [])
    .filter((row) => row.owner !== 'hermes' && (row.fixed || []).length)
    .map((row) => ({ ...row, fix: newestVersion(row.fixed) }))
    .filter((row) => row.fix && compareVersions(row.fix, row.version) > 0)
}

function todoRows({ bundle, label, entry }) {
  const rows = []
  const pending = (entry && entry.pending_count) || 0
  const kernel = (entry && entry.kernel) || {}
  if (pending) {
    rows.push({ level: 'amber', what: pending + ' package update' + (pending === 1 ? '' : 's') + ' to install',
                why: (entry && entry.pending_reason) || 'the package manager lists them as available now' })
  }
  if (kernel.verdict && kernel.verdict !== 'kernel-current') {
    rows.push({ level: kernel.verdict === 'kernel-reboot-needed' ? 'amber' : 'grey',
                what: kernel.verdict.replace('kernel-', '').replace(/-/g, ' ') + ' — running '
                      + (kernel.running || '?') + ', installed ' + (kernel.installed || '?'),
                why: kernel.reason || 'the running kernel is not the one on disk' })
  }
  const libraries = deviceLibraries(bundle, label)
  if (libraries) {
    const fixable = fixableRows(libraries)
    const known = (libraries.vulnerable || []).filter((row) => row.owner !== 'hermes')
    const noFix = known.length - fixable.length
    if (fixable.length) {
      const names = Array.from(new Set(fixable.map((row) => row.package + ' ' + row.version)))
      rows.push({ level: 'amber', what: fixable.length + ' library finding(s) with a published fix',
                  why: names.slice(0, 4).join(', ') + (names.length > 4 ? ' and ' + (names.length - 4) + ' more' : '') })
    }
    if (noFix) {
      rows.push({ level: 'grey', what: noFix + ' library finding(s) with no published fix',
                  why: 'an acknowledgement can record them with a reason; no version installs a fix that does not exist' })
    }
    if (!fixable.length && !noFix && libraries.components) {
      rows.push({ level: 'green', what: libraries.components + ' package(s) read, none named by an advisory',
                  why: 'the advisory database named no version of these packages' })
    }
  }
  const integrity = deviceIntegrity(bundle, label)
  if (integrity && integrity.integrity) {
    const state = integrity.integrity
    const tamper = state.tamper || {}
    const listeners = state.listeners || {}
    // the payload truncates the lists (12 changed, 6 unreadable) and carries the real totals beside
    // them; counting the list printed 6 next to a note that said 16
    const changedCount = tamper.changed_count !== undefined ? tamper.changed_count
      : (tamper.changed || []).length
    const goneCount = tamper.missing_count || 0
    const unreadableCount = tamper.unreadable_count !== undefined ? tamper.unreadable_count
      : (tamper.unreadable || []).length
    if (changedCount || goneCount) {
      // "changed" and "gone" are different sentences, and a gone path may be a directory the package
      // ships (apparmor's /etc/apparmor.d/disable is one). The repair list says which, and owns the
      // command that puts it back — a finding with no command is a dead end.
      const repair = (tamper.repair || [])[0]
      const parts = []
      if (changedCount) parts.push(changedCount + ' changed')
      if (goneCount) parts.push(goneCount + ' gone')
      const owner = repair && repair.package ? ' · package ' + repair.package : ''
      const kind = repair && repair.kind === 'directory' ? ' · a directory the package ships' : ''
      rows.push({ level: 'red',
                  what: parts.join(', ') + ' packaged path(s) no longer match'
                        + (goneCount && !changedCount ? ' (gone, not edited)' : ''),
                  why: (repair ? repair.path : '') + owner + kind
                       + (repair && repair.command && repair.command.startsWith('sudo ')
                          ? ' — the reinstall command below puts it back'
                          : ' — nothing claims this path, so no package puts it back') })
    }
    if ((listeners.new || []).length) {
      rows.push({ level: 'red', what: (listeners.new || []).length + ' listening socket(s) not in the baseline',
                  why: 'opened since the baseline was taken — decide whether you opened them' })
    }
    if (unreadableCount && tamper.covered) {
      // the operator already ran the command as root; asking again after every scan is the loop he
      // reported. The row stays — the files are still unreadable to this account — but it is closed.
      const when = tamper.root_coverage && tamper.root_coverage.at
        ? (agoAt(tamper.root_coverage.at) || 'just now') : 'earlier'
      const conffiles = (tamper.root_coverage && tamper.root_coverage.conffile_count) || 0
      rows.push({ level: 'green',
                  what: unreadableCount + ' packaged file(s) this account cannot read — covered by a '
                        + 'root run ' + when,
                  why: 'the root run found nothing changed'
                       + (conffiles ? '; ' + conffiles + ' conffile(s) it reported are edits of yours' : '')
                       + '. Nothing to do until the package database changes' })
    } else if (unreadableCount) {
      rows.push({ level: 'grey', what: unreadableCount + ' packaged file(s) this account cannot read',
                  why: 'not a finding: unreadable is not changed. The command below covers them' })
    }
    if (state.state === 'ok' && !changedCount && !goneCount && !(listeners.new || []).length) {
      rows.push({ level: 'green', what: 'checksums, preload hook and ' + (listeners.count || 0) + ' listening socket(s) read',
                  why: 'no evidence of tampering in the surfaces read — a rootkit that hides is invisible to this' })
    }
  }
  // a blind entry says what class of surface it is (images, advisories, host) and why — the earlier
  // version looked for two keys that are not in the shape and printed "cannot see: a surface"
  for (const blind of ((bundle.scan && bundle.scan.blind) || [])) {
    const where = blind.host || blind.label || ''
    if (where && where !== label) continue
    rows.push({ level: 'grey', what: 'cannot see: ' + (blind.class || blind.source || 'a surface'),
                why: (blind.reason || blind.why || 'it could not be read')
                     + (blind.detail ? ' — ' + blind.detail : '') })
  }
  return rows
}

function TodoPanel({ bundle, selected, onSelect, devices }) {
  // One device, the selected one. A merged list across five machines was the confusion the operator
  // named: the sections below are per device, so this one is too. The servers list carries the badge
  // that says which other device needs attention.
  const all = devices && devices.length ? devices : orderedHosts(bundle)
  const rows = all.filter((row) => !selected || row.label === selected)
  if (!rows.length) return null
  return jsxs('section', { style: sectionStyle('now') }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '6px' } }, [
      label('what must be done', null, 'everything the measurement turned into an action, per device'),
      jsx('span', { style: { flex: 1 } })
    ]),
    rows.map(({ label: name, entry }) => {
      const todo = todoRows({ bundle, label: name, entry })
      const actions = todo.filter((row) => row.level === 'amber' || row.level === 'red').length
      return jsxs('div', {
        key: name,
        style: { marginBottom: '10px', cursor: 'pointer' },
        onClick: () => onSelect && onSelect(name)
      }, [
        jsxs('div', { style: { display: 'flex', gap: '7px', alignItems: 'baseline', marginBottom: '3px' } }, [
          jsx('span', { style: { display: 'inline-flex' } }, deviceIcon(deviceKind(entry || {}))),
          jsx('span', {
            style: { fontFamily: MONO, fontSize: '0.875rem', fontWeight: 600,
                     color: selected === name ? C.accent : C.text }
          }, name),
          jsx('span', {
            style: { fontFamily: MONO, fontSize: '0.6875rem', color: actions ? C.warn : C.ok }
          }, actions ? actions + ' to do' : 'nothing to do'),
          jsx('span', { style: { flex: 1 } }),
          jsx('span', {
            style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.faint }
          }, entry && entry.measured_at ? agoAt(entry.measured_at) || '' : '')
        ]),
        todo.length
          ? todo.map((row, index) => jsxs('div', {
              key: index,
              style: {
                display: 'grid', gridTemplateColumns: '6px 1fr', gap: '7px',
                paddingLeft: '19px', marginBottom: '2px'
              }
            }, [
              // a bullet, not the shared <span> the older panels compose: spreading a React element
              // into a style object copies its internal symbols and React refuses to render it
              jsx('span', {
                style: { color: LEVEL_COLOUR[row.level] || C.faint, fontSize: '0.6875rem', lineHeight: 1.6 }
              }, '●'),
              jsxs('div', {}, [
                jsx('div', { style: { fontSize: '0.8125rem', color: row.level === 'grey' ? C.dim : C.text } }, row.what),
                row.why
                  ? jsx('div', { style: { fontSize: '0.75rem', color: C.faint } }, row.why)
                  : null
              ])
            ]))
          : jsx('div', { style: { paddingLeft: '19px', fontSize: '0.8125rem', color: C.faint } },
              // "measured and nothing to do" and "never measured" are different sentences; printing
              // the second over the first is the kind of quiet lie this plugin exists to avoid
              entry && (entry.pending_count !== undefined || (entry.os && entry.os.id))
                ? 'measured ' + (agoAt(entry.measured_at) || 'just now') + ' — '
                  + ((entry.pending_count || 0) === 0
                      ? 'no package update pending'
                      : entry.pending_count + ' update(s) pending')
                  + ((entry.kernel && entry.kernel.verdict && entry.kernel.verdict !== 'kernel-current')
                      ? ', kernel ' + String(entry.kernel.verdict).replace('kernel-', '').replace(/-/g, ' ')
                      : ', kernel ' + ((entry.kernel && entry.kernel.running) || 'current'))
                  + ' · nothing else to act on here'
                : 'not measured on this device yet — press rescan all')
      ])
    })
  ])
}

// ------------------------------------------------------------------ THE FIX, AS COMMANDS
// Every command the measurement implies, grouped by device, numbered, each copyable on its own and all
// of them copyable at once. A command that cannot be run is not here: an upgrade with no published fix
// is a row in "what must be done", not a line to paste.

function commandsForHost(bundle, name) {
  const out = []
  const plan = devicePlan(bundle, name) || {}
  for (const step of plan.steps || []) {
    out.push({ command: step.command, why: step.action, kind: 'packages',
               detail: (step.risk ? 'risk ' + step.risk + ' · downtime ' + step.downtime + ' · ' : '')
                       + 'verify: ' + (step.verify || '—') + ' · reverse: ' + (step.reversal || '—') })
  }
  const libraries = deviceLibraries(bundle, name)
  if (libraries) {
    for (const row of fixableRows(libraries)) {
      const command = fixCommandFor(row, row.fix)
      if (command && !command.startsWith('#')) {
        out.push({ command, why: row.package + ' ' + row.version + ' → ' + row.fix,
                   detail: row.ecosystem + ' · ' + String(row.source || ''), kind: 'libraries' })
      }
    }
  }
  const integrity = deviceIntegrity(bundle, name)
  if (integrity && integrity.integrity) {
    const tamper = integrity.integrity.tamper || {}
    // a packaged file that differs or is gone is repaired by reinstalling the package that owns it —
    // the owner is resolved on the host, so this is a real command and not a guess
    for (const repair of tamper.repair || []) {
      if (repair.command && repair.command.startsWith('sudo ')) {
        out.push({ command: repair.command, kind: 'repair',
                   why: repair.path + (repair.kind === 'directory' ? ' (a directory)' : '')
                        + ' does not match ' + (repair.package || 'its package'),
                   detail: 'put the file back from the package that ships it; nothing else on this '
                           + 'host can restore it' })
      }
    }
    const unreadableOpen = (tamper.unreadable_count || (tamper.unreadable || []).length) && !tamper.covered
    if (unreadableOpen && tamper.command) {
      out.push({ command: tamper.command, kind: 'verify',
                 why: (tamper.unreadable_count || (tamper.unreadable || []).length)
                      + ' packaged file(s) this account cannot read',
                 detail: 'run it as the account that can read them, then paste the output back into integrity' })
    }
  }
  const seen = new Set()
  return out.filter((row) => {
    if (seen.has(row.command)) return false
    seen.add(row.command)
    return true
  })
}

/** `where` arrives as a structured object; the copy control wants one line of prose. */
function whereLine(where) {
  if (!where) return ''
  if (typeof where === 'string') return where
  if (where.kind === 'remote') {
    return 'run it on ' + (where.machine || 'that host')
      + (where.ssh ? ' — `' + where.ssh + '` — or prefix the command with it' : ' — in a terminal there')
  }
  return where.how || where.note
    || (where.runs_as ? 'run it as ' + where.runs_as + ' in a terminal on this machine'
                      : 'run it in a terminal on this machine')
}

function CommandsPanel({ bundle, selected, where, devices, scanning }) {
  const all = devices && devices.length ? devices : orderedHosts(bundle)
  const hosts = all.filter((row) => !selected || row.label === selected)
  if (!hosts.length) return null
  const blocks = hosts.map(({ label: name }) => ({ name, commands: commandsForHost(bundle, name) }))
  const withCommands = blocks.filter((block) => block.commands.length)
  const quiet = blocks.filter((block) => !block.commands.length).map((block) => block.name)
  const total = withCommands.reduce((sum, block) => sum + block.commands.length, 0)
  const whereText = whereLine(where)

  return jsxs('section', { style: sectionStyle('plan') }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '6px' } }, [
      label('the fix commands', null, 'everything above, as the exact lines to paste — in order'),
      jsx('span', { style: { flex: 1 } }),
      total
        ? jsx(Copy, { text: withCommands.flatMap((block) => block.commands.map((row) => row.command)).join('\n'),
                      what: 'all ' + total + ' commands', label: 'copy all ' + total, primary: true })
        : jsx('span', { style: { fontFamily: MONO, fontSize: '0.75rem', color: C.ok } }, 'nothing to run')
    ]),
    // the plan is built from the measurement that just ran, so it is the last part to light up
    scanning
      ? jsx(ScanLine, { label: 'turning the measurement into ordered commands — with how to verify and '
                             + 'how to undo each one' })
      : null,
    // A device with nothing to run is not a block with an empty body: it is one line, and it says why.
    quiet.length
      ? jsx('div', { style: { fontSize: '0.75rem', color: C.faint, marginBottom: '6px' } },
          quiet.join(', ') + ' — nothing to run: no package update pending and no published library fix')
      : null,
    withCommands.map((block) => jsxs('div', { key: block.name, style: { marginBottom: '10px' } }, [
      jsxs('div', { style: { display: 'flex', gap: '6px', alignItems: 'baseline', marginBottom: '3px' } }, [
        jsx('span', { style: { display: 'inline-flex' } },
            // the bundle is written stage by stage, so it is briefly a devices-only shape during a
            // run: reading `bundle.scan.hosts` unguarded crashed the whole page mid-scan
            deviceIcon(deviceKind((((bundle || {}).scan || {}).hosts || {})[block.name] || {}))),
        jsx('span', {
          style: { fontFamily: MONO, fontSize: '0.8125rem',
                   color: selected === block.name ? C.accent : C.text }
        }, block.name),
        jsx('span', { style: { fontFamily: MONO, fontSize: '0.75rem', color: C.dim } },
            block.commands.length + ' command' + (block.commands.length === 1 ? '' : 's') + ' — in this order')
      ]),
      block.commands.map((row, index) => jsxs('div', {
        key: index,
        style: {
          border: '1px solid ' + C.border, borderLeft: '2px solid ' + C.accent,
          borderRadius: '3px', padding: '7px 9px', marginBottom: '5px', background: C.panel
        }
      }, [
        jsxs('div', { style: { display: 'flex', gap: '7px', alignItems: 'baseline' } }, [
          jsx('span', { style: { fontFamily: MONO, fontSize: '0.75rem', color: C.accent } },
              String(index + 1).padStart(2, '0')),
          jsx('span', { style: { flex: 1, fontSize: '0.8125rem' } }, row.why)
        ]),
        jsx(Command, { text: row.command,
                       label: (block.commands.length > 1 ? 'command ' + (index + 1) + ' for ' + block.name
                                                          : 'the command for ' + block.name)
                              + ' — run it in a terminal',
                       where: index === 0 && block.name === selected ? (whereText || null) : null }),
        row.detail
          ? jsx('div', { style: { fontSize: '0.75rem', color: C.faint, marginTop: '3px' } }, row.detail)
          : null
      ]))
    ]))
  ])
}

// --------------------------------------------------------------------- HOW THIS WORKS
// A first-time user should not need the repository to know what to do. Four steps, one screen, and the
// one rule that explains every red row.

function HowItWorks({ open, onToggle }) {
  if (!open) {
    return jsx('div', { style: { marginBottom: '10px' } }, jsx('button', {
      type: 'button',
      onClick: onToggle,
      style: {
        fontFamily: MONO, fontSize: '0.6875rem', padding: '2px 8px', cursor: 'pointer',
        color: C.faint, background: 'transparent', border: '1px solid ' + C.border, borderRadius: '3px'
      }
    }, '▸ how this works'))
  }
  const step = (index, title, body) => jsxs('div', {
    key: index, style: { display: 'grid', gridTemplateColumns: '14px 1fr', gap: '7px', marginBottom: '3px' }
  }, [
    jsx('span', { style: { fontFamily: MONO, fontSize: '0.75rem', color: C.accent } }, String(index)),
    jsxs('div', {}, [
      jsx('span', { style: { fontSize: '0.8125rem', fontWeight: 600, color: C.text } }, title),
      jsx('span', { style: { fontSize: '0.8125rem', color: C.dim } }, ' ' + body)
    ])
  ])
  return jsxs('section', {
    style: {
      marginBottom: '14px', padding: '9px 11px', background: C.panel,
      border: '1px solid ' + C.border, borderLeft: '2px solid ' + C.accent, borderRadius: '4px'
    }
  }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '6px' } }, [
      jsx('span', {
        style: { fontFamily: MONO, fontSize: '0.6875rem', letterSpacing: '0.12em', textTransform: 'uppercase',
                 color: C.dim }
      }, 'how this works'),
      jsx('span', { style: { flex: 1 } }),
      jsx('button', {
        type: 'button', onClick: onToggle,
        style: {
          fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 7px', cursor: 'pointer',
          color: C.faint, background: 'transparent', border: '1px solid ' + C.border, borderRadius: '3px'
        }
      }, 'hide')
    ]),
    step(1, 'pick a device.', 'Click its name in the servers list. Everything below is about that one machine.'),
    step(2, 'press scan all.', 'It reads packages, kernel, container images, the language '
      + 'stack and file checksums for one device at the same time — about half a minute — and '
      + 'changes nothing.'),
    step(3, 'read what must be done.', 'Every row is something observed, with the reason it matters. '
      + 'Green: measured, nothing to act on. Grey: it could not look, and says so.'),
    step(4, 'copy the commands.', 'They are under “the fix commands”, at the bottom, in order, and say which device '
      + 'to run them on. Run them there, then scan again.'),
    jsx('div', {
      style: { fontSize: '0.75rem', color: C.faint, marginTop: '6px', lineHeight: 1.55,
               paddingTop: '6px', borderTop: '1px solid ' + C.border }
    }, 'It never calls a machine clean when a surface could not be read — those appear as gaps in red, '
       + 'and a gap is a fact about the scan, not about the host. No credential is stored: ssh uses your '
       + 'own agent, and the only thing sent anywhere is package names and versions, to OSV.')
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
      label(SECTION.gaps.title, null, SECTION.gaps.long),
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

// --------------------------------------------------------------------------- root

export { VerdictBar, HostsPanel, TodoPanel, CommandsPanel, ScanButton, HowItWorks, orderedHosts,
         todoRows, commandsForHost,
         fixableRows, UpdatesPanel, LanguagesPanel, IntegrityPanel, GapsPanel,
         buildFixCommand, fixBlock, actionableFixes, SECTIONS }


/**
 * The selected device is one choice for the whole app, not one per surface.
 *
 * The pane and the page are two instances of this component: selecting webasix in one and pressing
 * scan in the other measured *this machine*, because the second instance still held its own default.
 * A module-level store with a subscriber set makes them agree immediately; localStorage remembers the
 * choice across restarts.
 */
const SELECTION = { value: null, listeners: new Set() }

function readSelection() {
  try {
    return window.localStorage.getItem('patch-sentinel.selected') || null
  } catch (err) {
    return null                                   // a render without storage (SSR, a test) is fine
  }
}

function useSelectedDevice() {
  const [value, setValue] = useState(() => SELECTION.value || readSelection())
  useEffect(() => {
    const listener = (next) => setValue(next)
    SELECTION.listeners.add(listener)
    return () => { SELECTION.listeners.delete(listener) }
  }, [])
  const set = useCallback((label) => {
    SELECTION.value = label
    try {
      if (label) window.localStorage.setItem('patch-sentinel.selected', label)
    } catch (err) {
      // a pane that cannot remember the choice still works; it just starts on this machine
    }
    for (const listener of Array.from(SELECTION.listeners)) listener(label)
  }, [])
  return [value, set]
}

/**
 * The one control. Its label is the operator's evidence of *which device* is about to be measured, so
 * it is a component of its own with its own test: a button that says "beelink" while webasix is
 * selected is the failure this had.
 */
const STAGE_LABEL = { scan: 'packages', libraries: 'language stack', integrity: 'integrity',
                      plans: 'commands' }

function ScanButton({ selected, busy, stage, currentHost, seconds, onClick }) {
  return jsx('button', {
    type: 'button',
    onClick,
    disabled: busy,
    title: 'measures every surface of the selected device at once — packages, kernel, images, '
           + 'advisories, the language stack, the integrity reading — then the commands it implies. '
           + 'One press per device; switching devices never re-scans.',
    style: {
      fontFamily: MONO, fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.06em',
      textTransform: 'uppercase', padding: '7px 16px',
      cursor: busy ? 'default' : 'pointer',
      color: busy ? C.faint : '#06090c', background: busy ? 'transparent' : C.accent,
      border: '1px solid ' + (busy ? C.border : C.accent), borderRadius: '4px'
    }
  }, busy
    ? [jsx('span', { key: 'ring', className: 'ps-ring' }),
       (stage && STAGE_LABEL[stage] ? STAGE_LABEL[stage] : 'measuring')
         + (currentHost ? ' · ' + currentHost : '')
         + (seconds ? ' ' + Math.round(seconds) + ' s' : ' …')]
    : selected ? 'scan all · ' + selected : 'scan all')
}

export function PatchSentinel({ compact }) {
  // ONE measurement document, ONE button. Every section renders out of the bundle "rescan all" writes
  // (GET /rescan), so no two of them can disagree about which run they are showing.
  const [bundle, setBundle] = useState({})
  const [busy, setBusy] = useState(false)
  const [stage, setStage] = useState(null)
  // which device the current stage is on: the integrity stage takes tens of seconds per host, and a
  // spinner that does not move reads as a hang
  const [currentHost, setCurrentHost] = useState(null)
  const [seconds, setSeconds] = useState(0)
  const [scanError, setScanError] = useState(null)
  const [selected, setSelected] = useSelectedDevice()
  const [coverage, setCoverage] = useState(null)
  // the inventory, not only the devices that were measured: a machine that has never been scanned must
  // still be selectable, or a fresh install has nothing to press scan on
  const [inventory, setInventory] = useState([])
  const [health, setHealth] = useState(null)
  // the reading order, spelled out on demand — the same array the sections are titled from
  const [legend, setLegend] = useState(false)
  // first open: the four steps. Opening it once and closing it is enough; the link stays in the header.
  const [howto, setHowto] = useState(() => {
    try {
      return !window.localStorage.getItem('patch-sentinel.howto-seen')
    } catch (err) {
      return true
    }
  })
  const toggleHowto = useCallback(() => {
    setHowto((current) => {
      const next = !current
      try {
        if (!next) window.localStorage.setItem('patch-sentinel.howto-seen', '1')
      } catch (err) {
        // a pane that cannot remember this just shows the steps again next time
      }
      return next
    })
  }, [])
  const [libBusy, setLibBusy] = useState(false)
  // a project scan is a different question ("my app's dependencies"), so it is a separate answer kept
  // apart from the machine-wide one instead of overwriting it
  const [libProject, setLibProject] = useState(null)
  // No APPLY control in the pane: it only works where the account Hermes runs as can patch without a
  // prompt, which is never the machine Hermes is on. A control that refuses is friction, and every
  // device is patchable from its own terminal — so the pane hands over commands and nothing else.
  // The gated tool (`cve_apply`) stays for the agent.

  const loadBundle = useCallback(async () => {
    try {
      const answer = await call('/rescan')
      const next = (answer && answer.bundle) || {}
      if (next.scan) {
        setBundle(next)
      } else {
        // an install that never ran "rescan all" may still hold a stored scan: show it rather than an
        // empty pane, and keep the "not measured yet" state honest
        const legacy = await call('/status').catch(() => null)
        setBundle(legacy ? { scan: legacy } : {})
      }
      if (answer && answer.error) setScanError('the last run failed: ' + answer.error)
    } catch (err) {
      setBundle({})
    }
  }, [])

  const loadRest = useCallback(async () => {
    const [nextCoverage, nextHealth, nextHosts] = await Promise.all([
      call('/coverage').catch(() => null), call('/health').catch(() => null),
      call('/hosts').catch(() => null)])
    setCoverage(nextCoverage)
    setHealth(nextHealth)
    setInventory(((nextHosts && nextHosts.hosts) || []).map((host) => ({
      label: host.label, target: host.target || 'local' })))
  }, [])

  useEffect(() => { loadBundle(); loadRest() }, [loadBundle, loadRest])

  // One retry if nothing arrived: a gateway restart, a route that answered 503 once, or a first render
  // that raced the backend all leave `devices` empty, and an empty device list is a pane that can only
  // say "pick a device first" — a dead end the operator cannot get out of.
  useEffect(() => {
    if (inventory.length || Object.keys(bundle.devices || {}).length) return undefined
    const timer = setTimeout(() => { loadBundle(); loadRest() }, 3000)
    return () => clearTimeout(timer)
  }, [bundle, inventory, loadBundle, loadRest])

  const devices = useMemo(() => {
    const measured = orderedHosts(bundle)
    const seen = new Set(measured.map((row) => row.label))
    const rest = inventory.filter((host) => !seen.has(host.label))
      .map((host) => ({ label: host.label, entry: { target: host.target } }))
    return [...measured, ...rest]
  }, [bundle, inventory])
  // devices in reading order: this machine first, then the declared hosts
  const labels = useMemo(() => devices.map((row) => row.label), [devices])
  const entryOf = (label) => deviceScan(bundle, label) || {}
  const hosts = useMemo(() => {
    const out = {}
    for (const row of devices) out[row.label] = row.entry || {}
    return out
  }, [devices])

  // The remembered device can be gone (renamed, removed, or a different machine's inventory). Fall back
  // rather than keep a selection nothing can be measured for.
  useEffect(() => {
    if (!labels.length) return
    if (!selected || !labels.includes(selected)) setSelected(labels[0])
  }, [labels, selected, setSelected])

  /**
   * The one control. It starts the backend run and then follows the bundle: each stage is written as
   * it lands, so packages appear after twenty seconds and the integrity reading fills in behind it,
   * instead of the pane sitting still for a minute and a half.
   */
  const rescanAll = useCallback(async () => {
    if (busy) return
    if (!selected) {
      // pressing with no device measured *this machine* silently, which reads as "the button ignores
      // my selection". A device has to be named first.
      // say what the pane knows: an empty list here is a load problem, not a missing click
      const known = (devices || []).map((row) => row.label)
      setScanError(known.length
        ? 'pick a device first — the pane knows ' + known.length + ' (' + known.join(', ') + '); click '
          + 'its name in the servers list. Nothing was scanned.'
        : 'no device is loaded yet — the inventory did not answer. Nothing was scanned; press again in '
          + 'a moment, and if it persists the gateway is not running the pane route.')
      return
    }
    setBusy(true)
    setScanError(null)
    setSeconds(0)
    setStage('starting')
    try {
      const started = await call('/rescan', { method: 'POST', body: { host: selected } })
      if (started && started.error) {
        setScanError('the run could not start: ' + started.error)
        return
      }
      // A run already in flight is not "my" run: following it showed another device's progress under
      // this button, which is exactly how "I pressed webasix and watched beelink" happens.
      if (started && started.started === false) {
        setScanError('a scan is already running (' + (started.host || 'unknown device')
          + ') — let it finish, then press scan again. Nothing was started for ' + (selected || 'this device') + '.')
        setBusy(false)
        setStage(null)
        setCurrentHost(null)
        return
      }
      // The device the backend says it is measuring must be the one this pane asked for. It was not,
      // once: the route dropped the host and measured this machine for every press, silently.
      if (started && started.host && started.host !== selected) {
        setScanError('the backend started a run for ' + started.host + ' while this pane asked for '
          + selected + ' — it is running an older route, so nothing was measured for ' + selected
          + '. Restart the Hermes gateway, then press scan again.')
        setBusy(false)
        setStage(null)
        setCurrentHost(null)
        return
      }
      // the animation names the device that was asked for, taken from the press rather than from a
      // bundle written by an earlier run
      setCurrentHost(selected || null)
      for (let tick = 0; tick < 240; tick += 1) {
        await new Promise((resolve) => { setTimeout(resolve, 1500) })
        let answer = null
        try {
          answer = await call('/rescan')
        } catch (err) {
          continue                       // a poll that fails once is not a failed run
        }
        if (answer && answer.bundle) {
          setBundle(answer.bundle)
          setStage(answer.bundle.stage || null)
          setCurrentHost(answer.bundle.current_host || selected || null)
        }
        if (answer && answer.seconds) setSeconds(answer.seconds)
        if (answer && !answer.busy) {
          if (answer.error) setScanError('the run failed: ' + answer.error)
          break
        }
      }
      await loadRest()
    } catch (err) {
      setScanError(String(err && err.message ? err.message : err))
    } finally {
      setBusy(false)
      setStage(null)
    }
  // `selected` and `devices` are read inside this callback. Leaving them out of the dependency list
  // closed over the first render's value — null — so every press hit the "pick a device first" branch
  // no matter what the operator had clicked. That is a dead button, and it was this.
  }, [busy, loadRest, selected, devices])

  /** Re-read the stored integrity reading without paying for a whole run (after a baseline/paste). */
  const refreshIntegrity = useCallback(async (label) => {
    if (!label) return null
    const reading = await call('/integrity?host=' + encodeURIComponent(label)).catch(() => null)
    if (reading) {
      // the per-device block is what the sections read; writing only the legacy top-level copy left
      // a paste or an attestation invisible until the next scan
      setBundle((current) => {
        const devices = { ...(current.devices || {}) }
        devices[label] = { ...(devices[label] || {}), integrity: reading }
        return { ...current, devices, integrity: reading }
      })
    }
    return reading
  }, [])

  const readIntegrity = useCallback(async (action) => {
    if (!selected) return
    try {
      await call('/integrity', { method: 'POST', body: { host: selected, action: action || 'check' } })
      for (let tick = 0; tick < 120; tick += 1) {
        await new Promise((resolve) => { setTimeout(resolve, 1500) })
        let job = null
        try { job = ((await call('/jobs')) || {}).integrity || null } catch (err) { continue }
        if (job && !job.running) break
      }
      await refreshIntegrity(selected)
    } catch (err) {
      // the last reading stays on screen, labelled with its age
    }
  }, [selected, refreshIntegrity])

  /** "I ran it as root and it printed nothing" — answered in the request, like a paste. */
  const attestIntegrity = useCallback(async () => {
    if (!selected) return false
    try {
      const answer = await call('/integrity', {
        method: 'POST', body: { host: selected, action: 'attest' }
      })
      await refreshIntegrity(selected)
      return answer
    } catch (err) {
      return false
    }
  }, [selected, refreshIntegrity])

  const importIntegrity = useCallback(async (output) => {
    if (!selected) return false
    try {
      const answer = await call('/integrity', {
        method: 'POST', body: { host: selected, action: 'import', output }
      })
      if (answer && answer.exit_code === 2) return false
      await refreshIntegrity(selected)
      return answer
    } catch (err) {
      return false
    }
  }, [selected, refreshIntegrity])

  const libraries = libProject || bundle.libraries
  const checkLibraries = useCallback(async (projectPath) => {
    setLibBusy(true)
    try {
      const query = projectPath ? '?project=' + encodeURIComponent(projectPath) : ''
      const answer = await call('/libraries' + query)
      if (projectPath) setLibProject(answer)
      else setBundle((current) => ({ ...current, libraries: answer }))
    } catch (err) {
      setLibProject({ answer: 'could not look: ' + (err && err.message ? err.message : err),
                      packages: [], vulnerable: [] })
    } finally {
      setLibBusy(false)
    }
  }, [])

  const where = selected && hosts[selected] ? hosts[selected].where : null

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
      jsx(ScanButton, { selected, busy, stage, currentHost, seconds, onClick: rescanAll })
    ]),
    // the stylesheet is always mounted; the line appears only while something is being measured
    jsx('style', {}, SCAN_CSS),
    // the top line is the global rescan's. Anything else animates inside its own section, next to the
    // control that started it — an animation at the top of the page for a local check reads as a scan.
    busy
      ? jsx(ScanLine, {
          label: (stage && stage !== 'starting' && stage !== 'done'
            ? stage + ' — '
            : '')
            + 'packages, kernel, images, advisories, the language stack, checksums and sockets, '
            + 'then the commands they imply'
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
    // one line, not a wall: the pane already repeats each title above its section
    jsxs('div', {
      style: {
        display: 'flex', alignItems: 'baseline', gap: '10px', flexWrap: 'wrap',
        marginBottom: '12px', paddingLeft: '9px', borderLeft: '2px solid ' + C.border
      }
    }, [
      jsx('span', {
        key: 'order',
        style: { fontFamily: MONO, fontSize: '0.75rem', color: C.dim, letterSpacing: '0.02em' }
      }, SECTIONS.map((section) => section.title).join('  →  ')),
      jsx('button', {
        key: 'toggle',
        type: 'button',
        onClick: () => setLegend((current) => !current),
        style: {
          fontFamily: MONO, fontSize: '0.6875rem', padding: '1px 7px', cursor: 'pointer',
          color: legend ? C.accent : C.faint, background: 'transparent',
          border: '1px solid ' + C.border, borderRadius: '3px'
        }
      }, legend ? 'hide' : 'what each one is')
    ]),
    legend
      ? jsx('div', {
          style: { fontSize: '0.8125rem', color: C.faint, lineHeight: 1.55, marginBottom: '12px',
                   paddingLeft: '9px', borderLeft: '2px solid ' + C.border }
        }, SECTIONS.map((section) => jsx('div', { key: section.key, style: { marginBottom: '3px' } },
            jsx('b', { style: { color: C.dim } }, section.title), ' — ' + section.long)))
      : null,
    (Object.keys(hosts).length
      && !Object.values(hosts).some((host) => host && (host.pending_count !== undefined
        || (host.os && host.os.id))))
      && !busy
      ? jsx('div', {
          style: {
            fontSize: '0.8125rem', color: C.warn, marginBottom: '12px', padding: '7px 10px',
            border: '1px solid ' + C.border, borderLeft: '2px solid ' + C.warn, borderRadius: '4px'
          }
        }, 'Nothing measured yet on these servers — pick a device and press scan all once. It reads '
           + 'every surface of that device at the same time (about thirty seconds locally, longer over '
           + 'ssh) and changes nothing.')
      : null,
    jsx(HowItWorks, { open: howto, onToggle: toggleHowto }),
    jsx(VerdictBar, { status: {
      ...(bundle.scan || {}),
      hosts: selected && hosts[selected] ? { [selected]: hosts[selected] } : {},
      blind: ((bundle.scan && bundle.scan.blind) || []).filter((one) => !one.host || one.host === selected),
      age_seconds: selected && hosts[selected] && hosts[selected].measured_at
        ? Math.max(0, Math.round((Date.now() - Date.parse(hosts[selected].measured_at)) / 1000))
        : null
    }, label: selected }),
    jsx(HostsPanel, { onChanged: loadBundle, onSelect: setSelected, selected, bundle,
                      onLoaded: setInventory }),
    // The readings first, in the order the scan reads them, so the run animates top to bottom. The
    // sections stay on screen whether or not they found something: an empty section that says why it
    // is empty is information, and a section that vanishes reads as a broken pane.
    // No dropdown: the readings below belong to the selected device, and the two facts a reader needs
    // are that every device was measured in the same run and that switching does not re-scan.
    jsx('div', {
      style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.faint, marginBottom: '4px' }
    }, selected
        ? 'readings below: ' + selected
          + (hosts[selected] && hosts[selected].measured_at
              ? ' — measured ' + (agoAt(hosts[selected].measured_at) || 'just now')
              : ' — not measured yet')
          + ' · the button above reads this device only; each device keeps its own last reading'
        : 'click a device name above to choose whose readings these are'),
    jsx(UpdatesPanel, { entry: hosts[selected] || null, hostLabel: selected,
                        scanning: busy && stage === 'scan' }),
    jsx(IntegrityPanel, {
      reading: deviceIntegrity(bundle, selected), busy: busy && stage === 'integrity',
      seconds: busy && stage === 'integrity' ? seconds : 0,
      onRead: () => readIntegrity('check'),
      onRebaseline: () => readIntegrity('baseline'),
      onImport: importIntegrity,
      onAttest: attestIntegrity
    }),
    jsx(LanguagesPanel, { libraries: deviceLibraries(bundle, selected) || libraries,
                          onCheck: checkLibraries, busy: libBusy,
                          scanning: busy && stage === 'libraries' }),
    // The answer comes after the evidence it was built from: what must be done, then the commands.
    jsx(TodoPanel, { bundle, selected, onSelect: setSelected, devices }),
    jsx(CommandsPanel, { bundle, selected, where, devices, scanning: busy && stage === 'plans' }),
    // set apart, and last: a caveat about the measurement rather than a step in it. Between the
    // readings and the commands it pushed the one section everybody needs below the fold.
    jsx('div', {
      key: 'gaps',
      style: { marginTop: '38px', paddingTop: '16px', borderTop: '1px dashed ' + C.border }
    }, jsx(GapsPanel, { coverage, selected })),
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
