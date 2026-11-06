# The pane's render checks

Run from a clean checkout with `scripts/pane_check.sh`. It borrows React from the desktop app's own
`node_modules` (the plugin imports `react` and `@hermes/plugin-sdk`, and declares neither as a
dependency), copies the plugin in, stubs the SDK, and runs:

* `fixcmd.test.mjs` — the shell strings the pane hands a user, asserted literally;
* `render.test.mjs` — every panel, including the states only reachable by clicking.

Nothing here is a snapshot test: the assertion is that the code runs and the strings are right. A
pixel diff would make every palette change a chore and catch none of the bugs that matter.
