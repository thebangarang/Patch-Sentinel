// The string a user pastes into a shell. Its failure mode is silent: a wrong path installs into the
// wrong environment, or fails with "No module named pip" and no clue why.
import assert from 'node:assert'
import { buildFixCommand } from './pane.mjs'

const pip = { tool: 'pip3', path: '/home/u/.hermes/tools/python/bin/pip3',
              upgrade: '{tool} install -U {spec}' }
const pipx = { tool: 'pipx', path: '/usr/bin/pipx', upgrade: '{tool} upgrade {pkg}' }
const maven = { upgrade: null, why: "a build dependency: the fix belongs in the project's own manifest" }

// 1. the real failure: the interpreter that answered, not whatever python3 means in the user's shell
assert.equal(
  buildFixCommand({ ecosystem: 'PyPI', package: 'filelock', manager: pip }, { fixes: ['3.20.0'] }),
  "/home/u/.hermes/tools/python/bin/pip3 install -U 'filelock>=3.20.0'")

// 2. a pipx tool is not upgradable by pip
assert.equal(buildFixCommand({ ecosystem: 'PyPI', package: 'pycowsay', manager: pipx }, { fixes: [] }),
             '/usr/bin/pipx upgrade pycowsay')

// 3. npm takes an @version, not a PEP 508 spec
assert.equal(buildFixCommand({ ecosystem: 'npm', package: 'lodash',
                               manager: { upgrade: '{tool} install -g {spec}', path: '/usr/bin/npm' } },
                             { fixes: ['4.17.21'] }), '/usr/bin/npm install -g lodash@4.17.21')

// 4. a build dependency gets a sentence, not an invented command
assert.ok(buildFixCommand({ ecosystem: 'Maven', package: 'commons-lang3', manager: maven }, { fixes: [] })
            .startsWith('# commons-lang3: a build dependency'))

// 5. no manager at all is admitted, never guessed
assert.ok(buildFixCommand({ ecosystem: 'RubyGems', package: 'rack' }, { fixes: ['2.2.8'] })
            .includes('this scan did not find the store that owns it'))

// 6. no placeholder survives into the output
const out = buildFixCommand({ ecosystem: 'PyPI', package: 'urllib3', manager: pip }, { fixes: ['1.26.5'] })
assert.ok(!out.includes('{'), 'an unfilled placeholder reached the user: ' + out)

console.log('fix commands: 6 assertions passed')
