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
  if (blind.length) {
    return { level: 'red', why: blind.map(([k, v]) => k + ': ' + v).join(', ') }
  }
  if (pending > 0 || (kernel && kernel !== 'kernel-current' && kernel !== 'kernel-unknown')) {
    return { level: 'amber', why: pending + ' pending, kernel ' + (kernel || '?') }
  }
  if (kernel === 'kernel-unknown') return { level: 'grey', why: 'kernel not measurable here' }
  return { level: 'green', why: 'every check answered, nothing pending' }
}

const LEVEL_COLOUR = { green: C.ok, amber: C.warn, red: C.danger, grey: C.faint }

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
      fontFamily: MONO, fontSize: '0.5625rem', letterSpacing: '0.14em',
      textTransform: 'uppercase', color: C.faint, ...(extra || {})
    }
  }, text)
}

function Copy({ text, what }) {
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
  }, done ? 'copied' : 'copy')
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
          (entry.pending_count || 0) + ' pending · ' + (entry.images || []).length + ' image(s) · ' + level.level),
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
          blind.length + ' check(s) could not look — see GAPS')
      : null
  ])
}

// --------------------------------------------------------------------------- PENDING

function PendingPanel({ hostLabel, plan, onPlan, limited, planning }) {
  const steps = (plan && plan.steps) || []
  const refusals = (plan && plan.refusals) || []
  return jsxs('section', { style: { marginBottom: '18px' } }, [
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' } }, [
      label('pending'),
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
        jsx('span', { style: { fontSize: '0.5625rem', color: blocked ? C.danger : C.faint, fontFamily: MONO } },
          blocked ? 'fixable' : 'by design')
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

function ApplyGate({ hostLabel }) {
  const [typed, setTyped] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const armed = Boolean(hostLabel) && typed.trim() === hostLabel

  const run = useCallback(async (dryRun) => {
    if (!armed || busy) return
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
  return jsxs('section', { style: { borderTop: '1px solid ' + C.border, paddingTop: '10px', marginTop: '6px' } }, [
    label('apply', { marginBottom: '6px' }),
    jsx('div', { style: { fontSize: '0.75rem', color: C.dim, marginBottom: '6px' } },
      'This is the only control that changes a machine. Type ' + (hostLabel || 'the host name') +
      ' exactly to unlock it. “Stage” downloads and prints the command, changes nothing. “Apply” runs it and writes a receipt with the versions before and after.'),
    jsx('div', { style: { fontSize: '0.6875rem', color: C.faint, marginBottom: '6px' } },
      armed ? 'unlocked — stage first, then apply' : 'locked — the two buttons stay dead until the name matches'),
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
        disabled: !armed || busy,
        title: 'Stages the download and prints the command. Changes nothing.',
        style: {
          fontFamily: MONO, fontSize: '0.6875rem', padding: '4px 10px',
          cursor: armed && !busy ? 'pointer' : 'not-allowed',
          color: armed ? C.accent : C.faint, background: 'transparent',
          border: '1px solid ' + (armed ? C.accent : C.border), borderRadius: '3px'
        }
      }, busy ? '…' : 'stage (no change)'),
      jsx('button', {
        type: 'button',
        onClick: () => run(false),
        disabled: !armed || busy,
        title: 'Applies for real. Writes a receipt with the versions before and after.',
        style: {
          fontFamily: MONO, fontSize: '0.6875rem', padding: '4px 12px',
          cursor: armed && !busy ? 'pointer' : 'not-allowed',
          color: armed ? C.danger : C.faint, background: 'transparent',
          border: '1px solid ' + (armed ? C.danger : C.border), borderRadius: '3px'
        }
      }, armed ? 'apply for real' : 'apply — locked')
    ]),
    result
      ? jsxs('div', { style: { marginTop: '8px', borderTop: '1px dashed ' + C.border, paddingTop: '6px' } }, [
          jsx('div', {
            style: {
              fontFamily: MONO, fontSize: '0.6875rem',
              color: result.applied ? C.ok : (result.dry_run ? C.accent : C.warn)
            }
          }, (result.applied ? 'applied — ' : (result.dry_run ? 'staged, nothing changed — ' : 'refused — ')) + (result.reason || '')),
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

export { NowPanel, PendingPanel, GapsPanel, ApplyGate }

export function PatchSentinel({ compact }) {
  const [status, setStatus] = useState(null)
  const [coverage, setCoverage] = useState(null)
  const [busy, setBusy] = useState(false)
  const [selected, setSelected] = useState(null)
  const [plan, setPlan] = useState(null)
  const [planning, setPlanning] = useState(false)

  const load = useCallback(async () => {
    try {
      const [nextStatus, nextCoverage] = await Promise.all([call('/status'), call('/coverage')])
      setStatus(nextStatus)
      setCoverage(nextCoverage)
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

  useEffect(() => {
    load()
  }, [load])

  const labels = useMemo(() => Object.keys((status && status.hosts) || {}), [status])

  return jsxs('div', {
    style: {
      padding: compact ? '10px 12px' : '18px 22px',
      color: C.text, fontSize: '0.8125rem',
      maxWidth: compact ? 'none' : '900px'
    }
  }, [
    jsxs('div', { style: { display: 'flex', gap: '8px', alignItems: 'baseline', marginBottom: '10px' } }, [
      label('patch sentinel', { color: C.accent }),
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
    jsxs('div', {
      style: {
        fontSize: '0.6875rem', color: C.faint, lineHeight: 1.5, marginBottom: '14px',
        borderLeft: '2px solid ' + C.border, paddingLeft: '9px'
      }
    }, [
      jsx('div', {}, jsx('b', { style: { color: C.dim } }, 'now'), ' — one row per machine: what the scan measured, and when.'),
      jsx('div', {}, jsx('b', { style: { color: C.dim } }, 'pending'), ' — this host\'s updates turned into ordered commands, each with a way back.'),
      jsx('div', {}, jsx('b', { style: { color: C.dim } }, 'gaps'), ' — what this scan could not see. Red here is a fact about the scan, not the host.'),
      jsx('div', {}, jsx('b', { style: { color: C.dim } }, 'apply'), ' — the only control that changes a machine, and it needs the host name typed.')
    ]),
    jsx(NowPanel, { status, onRefresh: rescan, busy }),
    jsx(PendingPanel, { hostLabel: selected, plan, onPlan: doPlan, limited: !selected, planning }),
    jsx(GapsPanel, { coverage, selected }),
    jsx(ApplyGate, { hostLabel: selected })
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
