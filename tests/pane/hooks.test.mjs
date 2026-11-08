/**
 * A hook that reads a value must depend on it.
 *
 * The pane had a dead scan button: `rescanAll` was created with `useCallback(..., [busy, loadRest])`
 * and read `selected` inside. The closure kept the first render's `selected` — null — so every press
 * hit "pick a device first" no matter what had been clicked. Nothing in a render test can see that,
 * because it is a stale closure rather than a wrong output.
 *
 * This walks the pane source and fails when a `useCallback` body reads one of the stateful names
 * without listing it in the dependency array. It is deliberately a source check: it is the only place
 * the mistake is visible.
 */
import { readFileSync } from 'node:fs'

const raw = readFileSync(new URL('./pane.mjs', import.meta.url), 'utf8')

// Words inside comments and strings are not reads. Blank them out while keeping every newline, so the
// reported line numbers still point at the source.
const source = raw
  .replace(/\/\*[\s\S]*?\*\//g, (block) => block.replace(/[^\n]/g, ' '))
  .replace(/(^|[^:])\/\/[^\n]*/g, (line, prefix) => prefix + ' '.repeat(line.length - prefix.length))
  .replace(/'(?:[^'\\\n]|\\.)*'/g, (text) => "'" + ' '.repeat(Math.max(0, text.length - 2)) + "'")
  .replace(/"(?:[^"\\\n]|\\.)*"/g, (text) => '"' + ' '.repeat(Math.max(0, text.length - 2)) + '"')
const WATCHED = ['selected', 'devices', 'labels', 'busy', 'stage', 'currentHost', 'inventory',
                 'bundle', 'libProject', 'coverage', 'health', 'scanError']

let checked = 0
const problems = []

// every `useCallback(` call: capture its body up to the closing `}, [...])`
const pattern = /useCallback\(\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z_$][\w$]*)\s*=>\s*\{/g
let match
while ((match = pattern.exec(source)) !== null) {
  const bodyStart = match.index + match[0].length
  // walk braces to find the end of the callback body
  let depth = 1
  let index = bodyStart
  while (index < source.length && depth > 0) {
    const char = source[index]
    if (char === '{') depth += 1
    else if (char === '}') depth -= 1
    index += 1
  }
  const body = source.slice(bodyStart, index - 1)
  const tail = source.slice(index, index + 240)
  const depsMatch = tail.match(/^\s*,\s*\[([^\]]*)\]\s*\)/)
  if (!depsMatch) continue                      // not the shape we can reason about; skip it
  const deps = depsMatch[1]
  checked += 1
  for (const name of WATCHED) {
    const used = new RegExp(`(^|[^\\w$.])${name}([^\\w$]|$)`).test(body)
    if (!used) continue
    // a name the callback declares itself is its own value, not the hook's
    if (new RegExp(`\\b(const|let|var)\\s+${name}\\b`).test(body)) continue
    const declared = new RegExp(`(^|[^\\w$])${name}([^\\w$]|$)`).test(deps)
    if (!declared) {
      const line = source.slice(0, match.index).split('\n').length
      problems.push(`line ${line}: the callback reads "${name}" but its deps are [${deps.trim()}]`)
    }
  }
}

if (!checked) throw new Error('no useCallback calls were found — this check is not looking at the pane')
if (problems.length) {
  throw new Error('a callback closes over a value it does not depend on (a stale closure):\n  '
    + problems.join('\n  '))
}
console.log(`  ${checked} callbacks depend on every state value they read`)
