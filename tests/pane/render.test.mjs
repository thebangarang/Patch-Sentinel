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
import { HostsPanel, NowPanel, UpdatesPanel, LanguagesPanel, PendingPanel, GapsPanel, ApplyGate }
  from './pane.mjs'

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

let bytes = 0
for (const [name, element] of panes) {
  const html = renderToStaticMarkup(element)
  if (!html || html.length < 20) throw new Error(name + ' rendered nothing')
  bytes += html.length
  console.log('  ' + name.padEnd(16) + html.length + ' bytes')
}
console.log('rendered ' + panes.length + ' panes, ' + bytes + ' bytes total')
