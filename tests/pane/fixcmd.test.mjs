// The string a user pastes into a shell. Its failure mode is silent: a wrong path installs into the
// wrong environment, or fails with "No module named pip" and no clue why.
import assert from 'node:assert'
import { buildFixCommand, fixBlock, actionableFixes } from './pane.mjs' 

const pip = { tool: 'pip3', path: '/home/u/.hermes/tools/python/bin/pip3',
              upgrade: '{tool} install -U {spec}' }
const pipx = { tool: 'pipx', path: '/usr/bin/pipx', upgrade: '{tool} upgrade {pkg}' }
const maven = { upgrade: null, why: "a build dependency: the fix belongs in the project's own manifest" }

// 1. the real failure: the interpreter that answered, not whatever python3 means in the user's shell
assert.equal(
  buildFixCommand({ ecosystem: 'PyPI', package: 'filelock', manager: pip }, { fixes: ['3.20.0'] }),
  "/home/u/.hermes/tools/python/bin/pip3 install -U 'filelock==3.20.0'")

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

// 5. no manager at all is admitted, never guessed — and says the actionable half: nothing to run here
assert.ok(buildFixCommand({ ecosystem: 'RubyGems', package: 'rack' }, { fixes: ['2.2.8'] })
            .includes('no store on this machine owns it'))

// 6. a package inside a project virtualenv is upgraded *in that virtualenv*, by its own pip
assert.equal(
  buildFixCommand({ ecosystem: 'PyPI', package: 'pillow', version: '12.3.0',
                    source: 'env:/home/u/projects/api/.venv',
                    manager: { tool: 'pip', path: '/home/u/projects/api/.venv/bin/pip',
                               upgrade: '{tool} install -U {spec}' } },
                  { fixes: ['13.0.0'] }),
  "/home/u/projects/api/.venv/bin/pip install -U 'pillow==13.0.0'")

// 7. a uv-made venv has no pip: the command names its interpreter instead of a pip that is not there
assert.equal(
  buildFixCommand({ ecosystem: 'PyPI', package: 'pyjwt', version: '2.10.1',
                    source: 'env:/home/u/projects/bot/.venv',
                    manager: { tool: 'uv', path: 'uv',
                               upgrade: 'uv pip install --python {python} {spec}' } },
                  { fixes: ['2.15.0'] }),
  "uv pip install --python /home/u/projects/bot/.venv/bin/python 'pyjwt==2.15.0'")

// 9. the copy block is one entry per package, not one per advisory or per environment: the first
// version of it printed `pillow` nine times (three environments × three advisories) and fixed nothing
const envPip = { tool: 'pip', path: '/home/u/projects/a/.venv/bin/pip', upgrade: '{tool} install -U {spec}' }
const block = fixBlock([
  { package: 'pillow', version: '12.3.0', source: 'env:/home/u/projects/a/.venv', fix: '13.0.0', manager: envPip },
  { package: 'pillow', version: '12.3.0', source: 'env:/home/u/projects/b/.venv', fix: '13.0.0',
    manager: { tool: 'uv', path: 'uv', upgrade: 'uv pip install --python {python} {spec}' } },
  { package: 'pytest', version: '8.0.0', source: 'env:/home/u/projects/a/.venv', fix: '9.0.3', manager: envPip }
])
const headers = block.split('\n').filter((line) => line.startsWith('# '))
assert.equal(headers.length, 2, 'one header per package\n' + block)
assert.ok(block.includes("# pillow 12.3.0 → 13.0.0 — 2 places carry it"), block)
assert.ok(block.includes("/home/u/projects/a/.venv/bin/pip install -U 'pillow==13.0.0'"), block)
assert.ok(block.includes("uv pip install --python /home/u/projects/b/.venv/bin/python 'pillow==13.0.0'"), block)

// 10. an advisory whose named fix is *behind* the installed version is not an upgrade. The pane read
// "pytest 9.1.1 → 9.0.3" and a paste of that would have been a downgrade.
const downgrades = actionableFixes([
  { package: 'pytest', version: '9.1.1', fix: '9.0.3' },
  { package: 'pillow', version: '12.3.0', fix: '13.0.0' },
  { package: 'msgpack', version: '1.2.2', fix: null }
])
assert.deepEqual(downgrades.map((row) => row.package), ['pillow'], JSON.stringify(downgrades))

// 11. "no fix published" must not become an install command: the pane printed
// `uv pip install ... 'diskcache==latest'` under a row that said "no fix published"
const noFix = buildFixCommand({ ecosystem: 'PyPI', package: 'diskcache',
                                manager: { tool: 'uv', path: '/u/uv',
                                           upgrade: '{tool} pip install --python {python} {spec}' } },
                              { fixes: [] })
assert.ok(noFix.startsWith('# diskcache: no published fix'), noFix)
assert.ok(!noFix.includes('=='), 'a version was invented for a package with no fix: ' + noFix)

// 8. no placeholder survives into the output, ever
const out = buildFixCommand({ ecosystem: 'PyPI', package: 'urllib3', manager: pip }, { fixes: ['1.26.5'] })
assert.ok(!out.includes('{'), 'an unfilled placeholder reached the user: ' + out)

console.log('fix commands: 8 assertions passed')
