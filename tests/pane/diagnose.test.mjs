// The message a user reads when adding a server fails.
//
// "the probe failed" is not a diagnosis: DNS, a closed port, a missing key, an unaccepted host key and a
// host without bash each need a different action. These assertions pin the classification and the
// command that unblocks each one, because getting it wrong sends someone editing the wrong thing.
import assert from 'node:assert'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { HostsPanel } from './pane.mjs'

const render = (extra) => renderToStaticMarkup(
  createElement(HostsPanel, Object.assign({ onChanged: () => {} }, extra)))

const failure = {
  ok: false, stage: 'auth',
  reason: 'debian@10.0.0.9: Permission denied (publickey).',
  hint: 'the host answered but rejected the key — append this machine\'s public key to the target\'s authorized_keys',
  fix: 'ssh-copy-id -i ~/.ssh/id_ed25519.pub -p 2223 debian@10.0.0.9'
}

const html = render({ startOpen: true, initialTest: failure })
assert.ok(html.includes('stopped at auth'), 'the failing stage is not shown')
assert.ok(html.includes('rejected the key'), 'the hint is not shown')
assert.ok(html.includes('ssh-copy-id'), 'the unblocking command is not shown')
assert.ok(!html.includes('reached it'), 'a failed test must not read as success')

const ok = render({ startOpen: true, initialTest: { ok: true, adapter: 'apt', pending: 3,
                                                     os: { id: 'debian', codename: '12' },
                                                     kernel: { verdict: 'kernel-current' } } })
assert.ok(ok.includes('reached it'), 'a successful test must say so')
assert.ok(!ok.includes('stopped at'), 'a successful test must not show a failure stage')

console.log('diagnose pane: 6 assertions passed')
