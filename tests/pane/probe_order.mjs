
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { PatchSentinel } from './pane.mjs'
const html = renderToStaticMarkup(createElement(PatchSentinel, {}))
for (const s of ["the machines this pane answers for","the distro's update list","is this still what we installed?","language packages, against OSV","what this scan could not see","the actions, per device","the commands to paste, in order"]) {
  console.log(JSON.stringify(s), html.indexOf(s))
}
