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
function buildFixCommand(row, found) {
  const fix = found && found.fixes && found.fixes.length ? newestVersion(found.fixes) : null
  const eco = String(row.ecosystem || '').toLowerCase()
  const manager = row.manager || null
  const spec = eco === 'npm'
    ? row.package + '@' + (fix || 'latest')
    : (fix ? "'" + row.package + '>=' + fix + "'" : row.package)
  if (!manager) {
    return '# ' + row.package + ': upgrade it to ' + (fix || 'the fixed version')
      + ' where it is pinned — this scan did not find the store that owns it'
  }
  if (!manager.upgrade) {
    return '# ' + row.package + ': ' + (manager.why || 'no machine-wide command upgrades it')
  }
  return String(manager.upgrade)
    .split('{tool}').join(manager.path || manager.tool)
    .split('{spec}').join(spec)
    .split('{pkg}').join(row.package)
    .split('{ver}').join(fix || 'latest')
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

function label(text, extra) {
  return jsx('div', {
    style: {
      fontFamily: MONO, fontSize: '0.75rem', letterSpacing: '0.16em', fontWeight: 700,
      textTransform: 'uppercase', color: C.accent, paddingBottom: '3px',
      borderBottom: '1px solid ' + C.accent, display: 'inline-block', ...(extra || {})
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
      fontFamily: MONO, fontSize: '0.625rem', padding: '2px 8px', cursor: 'pointer',
      color: done ? C.ok : C.dim, background: 'transparent',
      border: '1px solid ' + C.border, borderRadius: '3px'
    }
  }, done ? 'copied' : (label || 'copy'))
}

// --------------------------------------------------------------------------- HOSTS

/** Add or remove a server. Addresses only — never a credential. */
function HostsPanel({ onChanged, startOpen }) {
  const [hosts, setHosts] = useState(null)
  const [open, setOpen] = useState(!!startOpen)
  const [newLabel, setNewLabel] = useState('')
  const [newTarget, setNewTarget] = useState('')
  const [test, setTest] = useState(null)
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

  return jsxs('section', { style: { marginBottom: '16px' } }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label('servers'),
      jsx('span', { style: { flex: 1 } }),
      jsx('span', { style: { fontFamily: MONO, fontSize: '0.625rem', color: C.faint } },
        hosts ? hosts.length + ' server(s)' : '…'),
      jsx('button', {
        type: 'button',
        onClick: () => { setOpen((v) => !v); setTest(null) },
        style: {
          fontFamily: MONO, fontSize: '0.625rem', padding: '3px 9px', cursor: 'pointer',
          color: open ? C.accent : C.dim, background: 'transparent',
          border: '1px solid ' + (open ? C.accent : C.border), borderRadius: '3px'
        }
      }, open ? 'close' : 'add a server')
    ]),
    (hosts || []).map((host) => jsxs('div', {
      key: host.label,
      style: {
        display: 'grid', gridTemplateColumns: '1fr auto auto', gap: '8px', alignItems: 'baseline',
        fontFamily: MONO, fontSize: '0.625rem', padding: '3px 0',
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
                width: '7rem', fontFamily: MONO, fontSize: '0.5625rem', padding: '1px 4px',
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
                fontFamily: MONO, fontSize: '0.5625rem', padding: '1px 6px',
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
              fontFamily: MONO, fontSize: '0.5625rem', padding: '1px 6px',
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
                flex: '0 0 30%', fontFamily: MONO, fontSize: '0.625rem', padding: '3px 6px',
                background: 'transparent', color: C.text, border: '1px solid ' + C.border,
                borderRadius: '3px'
              }
            }),
            jsx('input', {
              value: newTarget, onChange: (e) => { setNewTarget(e.target.value); setTest(null) },
              placeholder: 'user@host:port, an ssh alias, or local',
              style: {
                flex: 1, fontFamily: MONO, fontSize: '0.625rem', padding: '3px 6px',
                background: 'transparent', color: C.text, border: '1px solid ' + C.border,
                borderRadius: '3px'
              }
            })
          ]),
          jsxs('div', { style: { display: 'flex', gap: '6px', alignItems: 'center' } }, [
            jsx('button', {
              type: 'button', onClick: runTest, disabled: busy || !newLabel,
              style: {
                fontFamily: MONO, fontSize: '0.625rem', padding: '3px 9px',
                cursor: busy || !newLabel ? 'default' : 'pointer',
                color: C.accent, background: 'transparent',
                border: '1px solid ' + C.border, borderRadius: '3px'
              }
            }, busy ? '…' : 'test'),
            jsx('button', {
              type: 'button', onClick: add, disabled: busy || !test || !test.ok,
              title: test && test.ok ? 'save it to the inventory' : 'a host is only added after a probe of it succeeded',
              style: {
                fontFamily: MONO, fontSize: '0.625rem', padding: '3px 9px',
                cursor: test && test.ok ? 'pointer' : 'not-allowed',
                color: test && test.ok ? C.ok : C.faint, background: 'transparent',
                border: '1px solid ' + (test && test.ok ? C.ok : C.border), borderRadius: '3px'
              }
            }, 'add'),
            jsx('span', { style: { fontSize: '0.625rem', color: C.faint } },
              'addresses only — the key stays in ssh')
          ]),
          test
            ? jsx('div', {
                style: { marginTop: '6px', fontSize: '0.625rem', color: test.ok ? C.ok : C.danger, lineHeight: 1.4 }
              }, test.ok
                ? 'reached it: ' + (test.adapter || '?') + ' · ' + ((test.os && test.os.id) || '?') + '/'
                  + ((test.os && test.os.codename) || '?') + ' · kernel '
                  + ((test.kernel && test.kernel.verdict) || '?') + ' · ' + (test.pending || 0) + ' pending'
                : (test.reason || 'could not reach it') + (test.detail ? ' — ' + test.detail : ''))
            : null
        ])
      : null
  ])
}

// --------------------------------------------------------------------------- NOW

function NowPanel({ status, onRefresh, busy }) {
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
        jsxs('div', { style: { display: 'flex', gap: '6px', alignItems: 'baseline' } }, [
          jsx('span', { style: { fontWeight: 600, fontSize: '0.8125rem' } }, entry.label),
          jsx('span', { fontFamily: MONO, fontSize: '0.5625rem', color: C.accent },
            (entry.adapter || '?') + ' · ' + ((entry.os && entry.os.id) || '?') + '/' + ((entry.os && entry.os.codename) || '?')),
          // where the answer came from: this machine, or a host the operator declared
          jsx('span', { fontFamily: MONO, fontSize: '0.5625rem', color: C.faint },
            entry.target && entry.target !== 'local' ? 'ssh ' + entry.target : 'this machine')
        ]),
        jsx('div', { style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.dim, marginTop: '2px' } },
          'kernel ' + (kernel.running || '?') + ' → ' + (kernel.verdict || '?')),
        jsx('div', { style: { fontSize: '0.6875rem', color: C.faint, marginTop: '2px' } },
          (entry.pending_count || 0) + ' pending · ' + ((entry.vendor_lag || []).length)
          + ' fix(es) waiting on the vendor · ' + (entry.images || []).length + ' image(s) · ' + level.level),
        (entry.pending || []).length
          ? jsx('div', { style: { fontFamily: MONO, fontSize: '0.625rem', color: C.dim, marginTop: '3px' } },
              (entry.pending || []).slice(0, 3).map((row) => row.package + ' ' + (row.from || '?') + '→' + row.to).join(' · ') +
              (entry.pending_count > 3 ? ' · +' + (entry.pending_count - 3) + ' more' : ''))
          : null
      ]),
      jsxs('div', { style: { textAlign: 'right' } }, [
        jsx('div', { style: { fontFamily: MONO, fontSize: '0.6875rem', color: C.dim } },
          entry.measured_at ? entry.measured_at.replace('T', ' ').slice(0, 19) : '—'),
        jsx('div', { style: { fontSize: '0.625rem', color: C.faint } }, 'measured')
      ])
    ])
  })

  return jsxs('section', { style: { marginBottom: '18px' } }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label('now'),
      jsx('span', { style: { flex: 1 } }),
      jsx('span', { style: { fontFamily: MONO, fontSize: '0.625rem', color: C.faint } },
        ago(status ? status.age_seconds : null) + ' · exit ' + (status && status.exit_code !== null && status.exit_code !== undefined ? status.exit_code : '—')),
      jsx('button', {
        type: 'button',
        onClick: onRefresh,
        disabled: busy,
        style: {
          fontFamily: MONO, fontSize: '0.625rem', padding: '3px 9px', cursor: busy ? 'default' : 'pointer',
          color: busy ? C.faint : C.accent, background: 'transparent',
          border: '1px solid ' + C.border, borderRadius: '3px'
        }
      }, busy ? 'measuring…' : 'rescan')
    ]),
    hosts.length ? rows : jsx('div', { style: { fontSize: '0.75rem', color: C.faint, padding: '6px 0' } },
      (status && status.note) || 'no measurement yet'),
    blind.length
      ? jsx('div', { style: { marginTop: '6px', fontSize: '0.6875rem', color: C.danger } },
          blind.length + ' check(s) could not look — '
          + blind.map((b) => b.host || 'this machine').join(', ') + ' · see GAPS')
      : null
  ])
}

// --------------------------------------------------------------------------- UPDATES

/** The raw update list for the selected host — every package, searchable, copyable. */
function UpdatesPanel({ entry, hostLabel, onRescan, busy }) {
  const [query, setQuery] = useState('')
  const rows = (entry && entry.pending) || []
  const total = (entry && entry.pending_count) || 0
  const needle = query.trim().toLowerCase()
  const filtered = needle ? rows.filter((r) => (r.package || '').toLowerCase().includes(needle)) : rows
  const shown = filtered
  const text = filtered.map((r) => r.package + '  ' + (r.from || '?') + ' → ' + r.to).join('\n')

  return jsxs('section', { style: { marginBottom: '18px' } }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label('system packages'),
      jsx('span', { style: { flex: 1 } }),
      jsx('span', { fontFamily: MONO, fontSize: '0.625rem', color: total ? C.warn : C.faint },
        hostLabel ? total + ' available' : '—'),
      jsx('span', { style: { fontSize: '0.625rem', color: C.faint } },
        entry && entry.measured_at ? 'measured ' + entry.measured_at.replace('T', ' ').slice(11, 16) + ' UTC' : ''),
      rows.length ? jsx(Copy, { text, what: 'the update list' }) : null,
      onRescan
        ? jsx('button', {
            type: 'button',
            onClick: onRescan,
            disabled: busy,
            title: 're-measure this host — the list is part of the scan, not a separate query',
            style: {
              fontFamily: MONO, fontSize: '0.625rem', padding: '3px 9px', cursor: busy ? 'default' : 'pointer',
              color: busy ? C.faint : C.accent, background: 'transparent',
              border: '1px solid ' + C.border, borderRadius: '3px'
            }
          }, busy ? 'measuring…' : 'rescan')
        : null
    ]),
    (entry && entry.vendor_lag || []).length
      ? jsxs('div', {
          style: {
            borderLeft: '2px solid ' + C.danger, background: C.panel, padding: '6px 8px',
            marginBottom: '6px', borderRadius: '3px'
          }
        }, [
          jsx('div', { style: { fontSize: '0.6875rem', color: C.danger, fontWeight: 600 } },
            entry.vendor_lag.length + ' fix(es) exist upstream but not in this archive yet'),
          jsx('div', { style: { fontSize: '0.625rem', color: C.dim, marginTop: '2px', lineHeight: 1.4 } },
            'The advisory names a fixed version the archive does not offer, so nothing on this host can '
            + 'close it yet. Not the same as "nothing to do".'),
          entry.vendor_lag.slice(0, 6).map((row, index) => jsx('div', {
            key: index,
            style: { fontFamily: MONO, fontSize: '0.625rem', color: C.text, marginTop: '3px' }
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
              width: '100%', boxSizing: 'border-box', fontFamily: MONO, fontSize: '0.6875rem',
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
                fontFamily: MONO, fontSize: '0.625rem', padding: '2px 0',
                borderTop: '1px solid ' + C.border
              }
            }, [
              jsx('span', { style: { color: C.text, wordBreak: 'break-all' } }, row.package),
              jsx('span', { style: { color: C.dim, textAlign: 'right' } },
                (row.from || '?') + ' → ' + row.to)
            ]))),
          filtered.length
            ? jsx('div', { style: { fontSize: '0.625rem', color: C.faint, marginTop: '4px' } },
                filtered.length + ' row(s) in the box above — it scrolls; copy gets all of them')
            : null,
          entry && entry.pending_truncated
            ? jsx('div', { style: { fontSize: '0.625rem', color: C.warn, marginTop: '3px' } },
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
  const [query, setQuery] = useState('')
  // a list of 130 rows where 127 say "clean" buries the three that matter: findings first, the rest
  // behind an explicit "show all" — the count of what was checked is still on screen either way
  const [showAll, setShowAll] = useState(false)
  const answered = (libraries && libraries.packages) || []
  const vulnerable = (libraries && libraries.vulnerable) || []
  // if the payload carries findings but no inventory (an older backend, or a host that answered
  // nothing), the findings themselves are the list — a count with no rows is what the operator
  // rightly called broken
  const seen = new Set(answered.map((p) => (p.ecosystem || '') + '/' + p.package))
  const fromFindings = []
  for (const v of vulnerable) {
    const key = (v.ecosystem || '') + '/' + v.package
    if (!seen.has(key)) { seen.add(key); fromFindings.push({ ecosystem: v.ecosystem, package: v.package, version: v.version }) }
  }
  const packages = answered.length ? answered : fromFindings
  const RANK = { critical: 4, high: 3, moderate: 2, low: 1 }
  const foundByPackage = {}
  for (const v of vulnerable) {
    const key = (v.ecosystem || '') + '/' + v.package
    const severity = String(v.severity || '').split(' ')[0].toLowerCase()
    const entry = foundByPackage[key]
      || (foundByPackage[key] = { count: 0, severity: '', fixes: [], ids: [] })
    entry.count += 1
    if (!entry.severity || (RANK[severity] || 0) > (RANK[entry.severity] || 0)) entry.severity = severity
    for (const fix of v.fixed || []) if (fix && !entry.fixes.includes(fix)) entry.fixes.push(fix)
    if (v.id) entry.ids.push(v.id)
    // the vendor's own workaround, when the advisory carries one: what to do while the patch is not
    // installed yet (disable a feature, validate input, set a flag)
    if (!entry.workaround && v.workaround) entry.workaround = v.workaround
  }
  const hit = new Set(Object.keys(foundByPackage))
  const needle = query.trim().toLowerCase()
  const keyOf = (p) => (p.ecosystem || '') + '/' + p.package
  const matching = packages.filter((p) => !needle || (p.package || '').toLowerCase().includes(needle))
  const flagged = matching.filter((p) => hit.has(keyOf(p)))
  // nothing flagged? then the clean list IS the answer, so show it rather than an empty box
  const rows = (showAll || !flagged.length ? matching : flagged)
    .slice()
    .sort((a, b) => (hit.has(keyOf(b)) ? 1 : 0) - (hit.has(keyOf(a)) ? 1 : 0)
                    || String(a.package).localeCompare(String(b.package)))
  const hidden = matching.length - rows.length
  const readEcosystems = Object.entries((libraries && libraries.by_ecosystem) || {})
    .filter(([, count]) => count > 0).map(([eco]) => eco)
  const missingEcosystems = Object.entries((libraries && libraries.outcomes) || {})
    .filter(([, outcome]) => outcome === 'missing').map(([eco]) => eco)

  const fixLines = flagged.map((row) => buildFixCommand(row, foundByPackage[keyOf(row)]))

  return jsxs('section', { style: { marginBottom: '18px' } }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label('libs & runtimes'),
      jsx('span', { style: { flex: 1 } }),
      libraries
        ? jsx('span', { style: { fontFamily: MONO, fontSize: '0.625rem', color: vulnerable.length ? C.danger : C.faint } },
            packages.length + ' package(s) · ' + vulnerable.length + ' finding(s)')
        : null,
      flagged && flagged.length
        ? jsx(Copy, { text: fixLines.join('\n'), label: 'copy fix commands' })
        : null,
      jsx('button', {
        type: 'button',
        onClick: onCheck,
        disabled: busy,
        title: 'Reads the global npm tree and the pip environment on PATH, then asks osv.dev',
        style: {
          fontFamily: MONO, fontSize: '0.625rem', padding: '3px 9px', cursor: busy ? 'default' : 'pointer',
          color: busy ? C.faint : C.accent, background: 'transparent',
          border: '1px solid ' + C.border, borderRadius: '3px'
        }
      }, busy ? 'checking…' : libraries ? 're-check' : 'check')
    ]),
    libraries
      ? jsxs('div', {}, [
          jsx('div', { style: { fontSize: '0.6875rem', color: C.faint, marginBottom: '4px' } },
            (libraries.answer || '')
            + (readEcosystems.length ? ' · read: ' + readEcosystems.join(', ') : '')
            + (missingEcosystems.length
                ? ' · not installed here: ' + missingEcosystems.join(', ') : '')),
          vulnerable.length
            ? jsx('div', { style: { fontSize: '0.6875rem', color: C.dim, marginBottom: '4px', lineHeight: 1.45 } },
                'A finding is a published advisory that names this exact version — one package can carry many, '
                + 'which is why ' + vulnerable.length + ' findings sit on ' + Object.keys(foundByPackage).length +
                ' package(s). The fix column is the first version that closes it.')
            : null,
          !Array.isArray(libraries.packages)
            ? jsx('div', { style: { fontSize: '0.6875rem', color: C.warn, marginBottom: '4px' } },
                'this answer carries no package list — the backend behind this pane is older than the pane. '
                + 'Restart the app so both halves load the same build.')
            : null,
          jsxs('div', { style: { display: 'flex', gap: '6px', marginBottom: '5px' } }, [
            jsx('input', {
              value: query,
              onChange: (event) => setQuery(event.target.value),
              placeholder: 'filter packages',
              style: {
                flex: 1, fontFamily: MONO, fontSize: '0.6875rem', padding: '3px 7px',
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
                    fontFamily: MONO, fontSize: '0.625rem', padding: '3px 9px', cursor: 'pointer',
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
                  fontFamily: MONO, fontSize: '0.625rem'
                }
              }, [
                jsx('span', { style: { color: C.text, wordBreak: 'break-all' } },
                  row.package + '@' + row.version + '  ' + (row.ecosystem || '')),
                jsx('span', { style: { color: found ? C.danger : C.faint, textAlign: 'right' } },
                  found
                    ? found.count + ' advisor' + (found.count === 1 ? 'y' : 'ies')
                      + (found.severity ? ' · ' + found.severity : '')
                      + (fix ? ' · fix ' + fix : ' · no fix listed')
                    : 'clean')
              ]),
              found
                ? jsx('div', {
                    style: {
                      fontFamily: MONO, fontSize: '0.5625rem', color: C.faint,
                      marginTop: '1px', wordBreak: 'break-all'
                    }
                  }, '→ ' + fixCommand(row, found))
                : null,
              found && found.workaround
                ? jsx('div', {
                    style: { fontSize: '0.5625rem', color: C.warn, marginTop: '2px', lineHeight: 1.4 }
                  }, 'workaround, from the advisory: ' + found.workaround.slice(0, 260)
                     + (found.workaround.length > 260 ? '…' : ''))
                : null
            ])
          })),
          !rows.length
            ? jsx('div', { style: { fontSize: '0.6875rem', color: C.faint } },
                needle ? 'nothing matches the filter' : 'nothing was read')
            : null,
          hidden > 0
            ? jsx('div', { style: { fontSize: '0.625rem', color: C.faint, marginTop: '3px' } },
                hidden + ' more package(s) read and clean (no advisory names their version) — '
                + '“show all ' + matching.length + '” lists them')
            : jsx('div', { style: { fontSize: '0.625rem', color: C.faint, marginTop: '3px' } },
                rows.length + ' row(s) in the box above — it scrolls, the filter narrows')
        ])
      : jsx('div', { style: { fontSize: '0.75rem', color: C.faint, padding: '6px 0' } },
          'not read yet — press check. It reads npm\'s global tree and the pip environment on PATH; '
          + 'project lockfiles are not read automatically (see GAPS).')
  ])
}

// --------------------------------------------------------------------------- PENDING

function PendingPanel({ hostLabel, plan, onPlan, limited, planning }) {
  const steps = (plan && plan.steps) || []
  const refusals = (plan && plan.refusals) || []
  return jsxs('section', { style: { marginBottom: '18px' } }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label('plan'),
      jsx('span', { style: { flex: 1 } }),
      jsx('button', {
        type: 'button',
        onClick: () => onPlan(hostLabel),
        disabled: planning || !hostLabel,
        title: planning ? 'measuring the host and turning it into commands'
                        : 'turns this host\'s pending updates into ordered commands, each with a way back',
        style: {
          fontFamily: MONO, fontSize: '0.625rem', padding: '3px 9px',
          cursor: planning || !hostLabel ? 'default' : 'pointer',
          color: planning ? C.accent : C.dim, background: 'transparent',
          border: '1px solid ' + C.border, borderRadius: '3px'
        }
      }, planning ? 'planning…' : steps.length ? 're-plan' : 'plan for ' + (hostLabel || 'this machine'))
    ]),
    steps.length
      ? steps.map((step, index) => jsxs('div', {
          key: index,
          style: {
            border: '1px solid ' + C.border, borderLeft: '2px solid ' + C.accent,
            borderRadius: '3px', padding: '8px 10px', marginBottom: '6px', background: C.panel
          }
        }, [
          jsxs('div', { style: { display: 'flex', gap: '8px', alignItems: 'baseline' } }, [
            jsx('span', { style: { fontFamily: MONO, fontSize: '0.625rem', color: C.accent } }, String(index + 1).padStart(2, '0')),
            jsx('span', { style: { flex: 1, fontSize: '0.8125rem', fontWeight: 600 } }, step.action),
            jsx(Copy, { text: step.command, what: 'the command' })
          ]),
          jsx('div', {
            style: {
              fontFamily: MONO, fontSize: '0.6875rem', color: C.text, marginTop: '4px',
              whiteSpace: 'pre-wrap', wordBreak: 'break-all'
            }
          }, step.command),
          jsx('div', { style: { fontSize: '0.6875rem', color: C.dim, marginTop: '4px' } },
            'risk ' + step.risk + ' · downtime ' + step.downtime),
          jsx('div', { style: { fontSize: '0.6875rem', color: C.faint, marginTop: '3px' } }, step.why),
          jsxs('div', { style: { fontSize: '0.6875rem', color: C.faint, marginTop: '3px' } }, [
            'verify: ', jsx('span', { style: { fontFamily: MONO } }, step.verify || '—'),
            '  ·  reverse: ', jsx('span', { style: { fontFamily: MONO } }, step.reversal || '—')
          ])
        ]))
      : jsx('div', { style: { fontSize: '0.75rem', color: C.faint, padding: '6px 0' } },
          planning ? 'measuring the host — this can take a few seconds over ssh'
          : limited ? 'planning needs a host — pick one in NOW first'
          : plan ? 'the plan came back empty'
          : 'no plan yet — press “plan for …” to turn this host into commands'),
    refusals.length
      ? jsxs('div', {
          style: {
            marginTop: '6px', padding: '7px 9px', borderLeft: '2px solid ' + C.warn,
            background: C.panel, borderRadius: '3px'
          }
        }, [
          jsx('div', { style: { fontSize: '0.6875rem', color: C.warn, fontWeight: 600 } },
            'no steps — ' + refusals.map((r) => r.reason).join(' · ')),
          refusals.some((r) => r.detail)
            ? jsx('div', { style: { fontSize: '0.6875rem', color: C.faint, marginTop: '3px' } },
                refusals.map((r) => r.detail).filter(Boolean).join(' · '))
            : null
        ])
      : null
  ])
}

// --------------------------------------------------------------------------- GAPS

function gapRow(gap, index) {
  const blocked = gap.kind === 'blocked'
  return jsxs('div', {
    key: index,
    style: {
      display: 'grid', gridTemplateColumns: '8px 1fr', gap: '8px', padding: '5px 0',
      borderTop: '1px solid ' + C.border
    }
  }, [
    dot(blocked ? 'red' : 'amber'),
    jsxs('div', {}, [
      jsxs('div', { style: { display: 'flex', gap: '6px', alignItems: 'baseline' } }, [
        jsx('span', { style: { fontSize: '0.75rem', color: C.text } }, gap.gap),
        jsx('span', {
          style: {
            fontSize: '0.5625rem', fontFamily: MONO, padding: '1px 5px', borderRadius: '2px',
            color: blocked ? C.danger : C.faint,
            border: '1px solid ' + (blocked ? C.danger : C.border)
          }
        }, blocked ? 'fixable — do this' : 'cannot be cleared here')
      ]),
      jsx('div', { style: { fontSize: '0.6875rem', color: C.faint, marginTop: '2px' } },
        gap.state + ' — ' + (gap.why || '')),
      gap.next
        ? jsx('div', {
            style: {
              fontSize: '0.6875rem', marginTop: '3px',
              color: blocked ? C.warn : C.dim, fontStyle: blocked ? 'normal' : 'italic'
            }
          }, (blocked ? 'to clear it: ' : 'what you can do: ') + gap.next)
        : null
    ])
  ])
}

/**
 * Gaps are scoped: `hosts` is "every" or the labels it concerns. With a host selected, the panel
 * shows what applies to *that* host — the operator's complaint was a wall of other machines' gaps.
 */
function GapsPanel({ coverage, selected }) {
  const all = (coverage && coverage.gaps) || []
  const appliesTo = (gap) => gap.hosts === 'every' || !Array.isArray(gap.hosts)
    ? true : gap.hosts.includes(selected)
  const mine = all.filter(appliesTo)
  const elsewhere = all.length - mine.length
  const blocked = mine.filter((gap) => gap.kind === 'blocked')
  const limits = mine.filter((gap) => gap.kind !== 'blocked')

  return jsxs('section', {}, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label('gaps'),
      jsx('span', { style: { flex: 1 } }),
      jsx('span', { style: { fontSize: '0.625rem', color: C.faint } },
        selected ? 'what a scan of ' + selected + ' cannot see' : 'what this scan cannot see')
    ]),
    jsx('div', { style: { fontSize: '0.6875rem', color: C.faint, lineHeight: 1.45, marginBottom: '4px' } },
      'A gap is something this scan did not look at — not a fault on the host. None of these can be '
      + 'switched on from this pane; each says what would actually fix it.'),
    blocked.length
      ? jsxs('div', { style: { marginBottom: '4px' } }, [
          jsx('div', { style: { fontSize: '0.625rem', color: C.danger, letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '2px' } },
            'fixable — these are why a row is not green'),
          blocked.map(gapRow)
        ])
      : null,
    limits.map(gapRow),
    elsewhere
      ? jsx('div', { style: { fontSize: '0.625rem', color: C.faint, marginTop: '6px' } },
          elsewhere + ' more gap(s) concern other hosts — switch host at the top to read them')
      : null,
    all.length ? null : jsx('div', { style: { fontSize: '0.6875rem', color: C.warn } },
      'coverage has not been read yet — an empty gap list is not a claim that nothing is missed')
  ])
}

// --------------------------------------------------------------------------- APPLY GATE

function ApplyGate({ hostLabel, entry, onRescan, rescannning }) {
  const [typed, setTyped] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const armed = Boolean(hostLabel) && typed.trim() === hostLabel

  const run = useCallback(async (dryRun) => {
    if (!armed || busy || !entry) return
    setBusy(true)
    setResult(null)
    try {
      const answer = await call('/apply', {
        method: 'POST',
        body: { host: hostLabel, confirm: typed.trim(), dry_run: dryRun }
      })
      setResult(answer)
    } catch (err) {
      setResult({ applied: false, reason: String(err && err.message ? err.message : err) })
    } finally {
      setBusy(false)
    }
  }, [armed, busy, hostLabel, typed])

  const steps = (result && result.steps) || []
  const measured = Boolean(entry)
  const count = measured ? (entry.pending_count || 0) : null
  const nothingToDo = measured && count === 0
  const ready = armed && measured && !nothingToDo
  return jsxs('section', { style: { borderTop: '1px solid ' + C.border, paddingTop: '10px', marginTop: '6px' } }, [
    jsxs('div', { style: { display: 'flex', gap: '8px', alignItems: 'baseline', marginBottom: '6px' } }, [
      label('apply'),
      jsx('span', { style: { flex: 1 } }),
      jsx('span', { style: { fontFamily: MONO, fontSize: '0.625rem', color: nothingToDo ? C.faint : C.warn } },
        !measured ? 'no measurement' : nothingToDo ? 'nothing to apply' : count + ' update(s) to install'),
      onRescan
        ? jsx('button', {
            type: 'button',
            onClick: onRescan,
            disabled: rescannning,
            title: 're-measure every host in the inventory',
            style: {
              fontFamily: MONO, fontSize: '0.625rem', padding: '3px 9px',
              cursor: rescannning ? 'default' : 'pointer',
              color: rescannning ? C.faint : C.accent, background: 'transparent',
              border: '1px solid ' + C.border, borderRadius: '3px'
            }
          }, rescannning ? 'measuring…' : 'rescan')
        : null
    ]),
    jsx('div', { style: { fontSize: '0.75rem', color: C.dim, marginBottom: '4px' } },
      !measured
        ? 'Nothing has been measured for ' + (hostLabel || 'this host') + ' yet — press rescan above, then come back.'
        : nothingToDo
          ? 'The scan found 0 updates on ' + hostLabel + ', so there is nothing to stage and nothing to apply. The buttons are disabled because the work is already done — not because something is broken. Rescan after you change something.'
          : 'This is the step that actually pushes the update list above onto ' + (hostLabel || 'the host') +
            '. “Stage” downloads and prints the command and changes nothing; “Apply” runs it, then re-measures the host and writes a receipt with the versions before and after. It is the same action as asking me in chat.'),
    nothingToDo ? null : jsxs('div', { style: { fontSize: '0.6875rem', color: C.faint, marginBottom: '6px' } }, [
      'Type ',
      jsx('code', {
        style: {
          fontFamily: MONO, color: C.accent, background: C.panel,
          padding: '0 5px', borderRadius: '2px', border: '1px solid ' + C.border
        }
      }, hostLabel || 'the host name'),
      ' exactly — that is the label selected at the top, not the machine\'s hostname. The lock exists so a stray click cannot patch a machine.'
    ]),
    armed ? jsx('div', { style: { fontSize: '0.6875rem', color: C.accent, marginBottom: '6px' } },
      'unlocked — stage first, then apply') : null,
    jsxs('div', { style: { display: 'flex', gap: '6px', alignItems: 'center' } }, [
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
          fontFamily: MONO, fontSize: '0.6875rem', padding: '4px 10px',
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
          fontFamily: MONO, fontSize: '0.6875rem', padding: '4px 12px',
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
              fontFamily: MONO, fontSize: '0.6875rem',
              color: result.applied ? C.ok : (result.dry_run ? C.accent : C.warn)
            }
          }, (result.applied ? 'applied — ' : (result.dry_run ? 'staged, nothing changed — ' : 'refused — ')) + (result.reason || '')),
          result.expected
            ? jsx('div', { style: { fontSize: '0.625rem', color: C.dim, marginTop: '2px' } },
                'the name this gate expects: ' + result.expected)
            : null,
          steps.length
            ? jsx('div', { style: { marginTop: '4px' } }, steps.map((step, index) =>
                jsx('div', {
                  key: index,
                  style: { fontFamily: MONO, fontSize: '0.625rem', color: step.ok ? C.dim : C.danger }
                }, step.action + ' · rc ' + step.rc + ' · ' + step.duration_s + 's' + (step.ok ? '' : ' · ' + (step.output || '').slice(0, 160)))))
            : null,
          result.receipt
            ? jsx('div', { style: { marginTop: '4px', fontSize: '0.625rem', color: C.faint } },
                'receipt written · ' + (result.receipt.outcome || '') + ' · reboot owed: ' + String(Boolean(result.reboot_required)))
            : null
        ])
      : null
  ])
}

// --------------------------------------------------------------------------- root

export { HostsPanel, NowPanel, UpdatesPanel, LanguagesPanel, PendingPanel, GapsPanel, ApplyGate, buildFixCommand }

export function PatchSentinel({ compact }) {
  const [status, setStatus] = useState(null)
  const [coverage, setCoverage] = useState(null)
  const [busy, setBusy] = useState(false)
  const [selected, setSelected] = useState(null)
  const [plan, setPlan] = useState(null)
  const [planning, setPlanning] = useState(false)
  const [health, setHealth] = useState(null)
  const [libraries, setLibraries] = useState(null)
  const [libBusy, setLibBusy] = useState(false)

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

  const rescan = useCallback(async () => {
    setBusy(true)
    try {
      await call('/scan', { method: 'POST', body: {} })
      await load()
    } finally {
      setBusy(false)
    }
  }, [load])

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
  const checkLibraries = useCallback(async () => {
    setLibBusy(true)
    try {
      setLibraries(await call('/libraries'))
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
              fontFamily: MONO, fontSize: '0.6875rem', padding: '2px 4px',
              background: 'Canvas', color: 'CanvasText', border: '1px solid ' + C.border,
              borderRadius: '3px', colorScheme: 'light dark'
            }
          }, labels.map((name) => jsx('option', { key: name, value: name }, name)))
        : null
    ]),
    health && Array.isArray(health.inventory) && health.inventory.length <= 1
      ? jsx('div', { style: { fontSize: '0.6875rem', color: C.warn, marginBottom: '10px' } },
          'the backend loaded an inventory of ' + health.inventory.length + ' host(s)'
          + (health.data_dir ? ' (data dir: ' + health.data_dir + ')' : '')
          + ' — if you declared more, it is running without its settings: restart the app.')
      : null,
    jsxs('div', {
      style: {
        fontSize: '0.6875rem', color: C.faint, lineHeight: 1.5, marginBottom: '14px',
        borderLeft: '2px solid ' + C.border, paddingLeft: '9px'
      }
    }, [
      jsx('div', {}, jsx('b', { style: { color: C.dim } }, 'now'), ' — one row per machine: what the scan measured, and when.'),
      jsx('div', {}, jsx('b', { style: { color: C.dim } }, 'system packages'),
        ' — the distro\'s own update list (apt, dnf, pacman, zypper), every package it would upgrade.'),
      jsx('div', {}, jsx('b', { style: { color: C.dim } }, 'libs & runtimes'),
        ' — what each language toolchain has installed machine-wide, checked against OSV: npm, pip, PHP, Ruby, Rust, .NET, Maven and Go.'),
      jsx('div', {}, jsx('b', { style: { color: C.dim } }, 'plan'),
        ' — the system packages above turned into ordered commands (risk, downtime, how to verify, how to undo).'),
      jsx('div', {}, jsx('b', { style: { color: C.dim } }, 'gaps'), ' — what this scan could not see. Red here is a fact about the scan, not the host.'),
      jsx('div', {}, jsx('b', { style: { color: C.dim } }, 'apply'), ' — the only control that changes a machine, and it needs the host name typed.'),
      jsx('div', {}, jsx('b', { style: { color: C.dim } }, 'servers'),
        ' — the machines this pane answers for (this one included). A server is added only after a probe of it succeeds; addresses only, never a key.')
    ]),
    jsx(HostsPanel, { onChanged: load }),
    jsx(NowPanel, { status, onRefresh: rescan, busy }),
    jsx(UpdatesPanel, { entry: status && status.hosts ? status.hosts[selected] : null,
                        hostLabel: selected, onRescan: rescan, busy }),
    jsx(LanguagesPanel, { libraries, onCheck: checkLibraries, busy: libBusy }),
    jsx(PendingPanel, { hostLabel: selected, plan, onPlan: doPlan, limited: !selected, planning }),
    jsx(GapsPanel, { coverage, selected }),
    jsx(ApplyGate, { hostLabel: selected, onRescan: rescan, rescannning: busy,
                     entry: status && status.hosts ? status.hosts[selected] : null }),
    jsx('div', {
      style: {
        marginTop: '12px', paddingTop: '8px', borderTop: '1px solid ' + C.border,
        fontFamily: MONO, fontSize: '0.5625rem',
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
