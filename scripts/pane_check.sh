#!/usr/bin/env bash
# Render the pane and check the commands it produces, without putting node_modules in the tree.
#
# The plugin imports react and @hermes/plugin-sdk and declares neither (the desktop app supplies
# them). So this builds a scratch directory, borrows the app's node_modules through a symlink, and
# runs the checks there — the published tree stays source-only, which is also what the plugin
# validator insists on.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="${HERMES_DESKTOP_APP:-$HOME/.hermes/hermes-agent/apps/desktop}"
[[ -d "$app/node_modules" ]] || { echo "no node_modules under $app (set HERMES_DESKTOP_APP)"; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
ln -s "$app/node_modules" "$work/node_modules"
cp "$root"/tests/pane/*.mjs "$work/"
sed "s|from '@hermes/plugin-sdk'|from './sdk-stub.mjs'|g" \
    "$root/desktop/plugin.js" > "$work/pane.mjs"

node --check "$work/pane.mjs"
cd "$work"
node hooks.test.mjs
# the fixture is committed under tests/, not in tmp/ (which is gitignored): a fresh clone has to be
# able to run these checks, and for a while it could not
DATA="${PANE_DATA:-$root/tests/pane/fixtures/pane-data.json}"
[[ -f "$DATA" ]] || { echo "no pane fixture at $DATA (set PANE_DATA)"; exit 2; }
PANE_DATA="$DATA" node fixcmd.test.mjs
node diagnose.test.mjs
PANE_DATA="$DATA" node render.test.mjs
node page.test.mjs
echo "pane checks passed"
