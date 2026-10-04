// Functional check of the dashboard in a real browser: console errors, the
// charts actually appearing, and the interactive widgets rendering.
//
// Complements measure-dashboard.mjs, which only reports timings. Run against a
// live core:
//
//   node scripts/check-dashboard.mjs [url]

import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const url = process.argv[2] ?? 'http://127.0.0.1:9090/ui#/'
const port = 9223
const edgeCandidates = [
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
]
const edge = edgeCandidates.find(existsSync)
if (!edge) {
  console.error('msedge.exe not found')
  process.exit(2)
}

const profile = mkdtempSync(join(tmpdir(), 'dash-check-'))
const browser = spawn(
  edge,
  ['--headless=new', '--disable-gpu', '--no-first-run', `--user-data-dir=${profile}`, `--remote-debugging-port=${port}`, 'about:blank'],
  { stdio: 'ignore' },
)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function target() {
  for (let i = 0; i < 60; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()
      const page = list.find((t) => t.type === 'page')
      if (page) return page
    } catch {
      /* starting up */
    }
    await sleep(250)
  }
  throw new Error('no debugging target')
}

let socket
let id = 1
const pending = new Map()
const consoleErrors = []

const send = (method, params = {}) => {
  const messageId = id++
  socket.send(JSON.stringify({ id: messageId, method, params }))
  return new Promise((resolve, reject) => pending.set(messageId, { resolve, reject }))
}
const evaluate = (expression) =>
  send('Runtime.evaluate', { expression, returnByValue: true }).then((r) => r.result?.value)

try {
  const page = await target()
  socket = new WebSocket(page.webSocketDebuggerUrl)
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve)
    socket.addEventListener('error', reject)
  })
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(event.data)
    if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') {
      consoleErrors.push(message.params.args.map((a) => a.value ?? a.description).join(' '))
    }
    if (message.method === 'Runtime.exceptionThrown') {
      consoleErrors.push(message.params.exceptionDetails?.exception?.description ?? 'exception')
    }
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id)
      pending.delete(message.id)
      message.error ? reject(new Error(message.error.message)) : resolve(message.result)
    }
  })

  await send('Page.enable')
  await send('Runtime.enable')
  await send('Page.navigate', { url })
  // Long enough for the traffic stream to deliver several samples, so the
  // assertions below see drawn data rather than an empty plot.
  await sleep(9000)

  const report = await evaluate(`(() => {
    const q = (s) => document.querySelector(s)
    return JSON.stringify({
      nav: document.querySelectorAll('.nav__item').length,
      statCards: document.querySelectorAll('.stat-card').length,
      modeSwitcher: !!q('.mode-switcher'),
      trafficChart: !!q('.traffic-chart'),
      memoryChart: !!q('.memory-chart'),
      chartPaths: document.querySelectorAll('.line-chart__svg path').length,
      axisLabels: document.querySelectorAll('.line-chart__axis').length,
      // Each sample contributes one 'C' segment to the smoothed path.
      drawnSegments: Math.max(
        0,
        ...[...document.querySelectorAll('.line-chart__svg path')].map(
          (p) => ((p.getAttribute('d') || '').match(/C/g) || []).length,
        ),
      ),
      // A styled button proves the on-demand Element Plus stylesheets arrived.
      styledButton: (() => {
        const b = q('.el-button')
        if (!b) return 'no button'
        const bg = getComputedStyle(b).borderRadius
        return bg && bg !== '0px' ? 'styled' : 'unstyled'
      })(),
      theme: document.documentElement.className,
      locale: document.documentElement.lang,
    })
  })()`)

  const result = JSON.parse(report)
  // Only the dashboard has charts; the other routes are checked for the shell,
  // the Element Plus styling and a clean console.
  const isDashboard = url.includes('#/') && !url.includes('#/p') && !url.includes('#/c') && !url.includes('#/r') && !url.includes('#/l') && !url.includes('#/s')
  const problems = []
  if (result.nav < 7) problems.push('only ' + result.nav + ' nav items')
  if (isDashboard) {
    if (!result.trafficChart) problems.push('the traffic chart did not render')
    if (!result.memoryChart) problems.push('the memory chart did not render')
    if (result.chartPaths < 2) problems.push('the chart series did not draw (' + result.chartPaths + ' paths)')
    if (result.axisLabels < 4) problems.push('the chart axes have no labels (' + result.axisLabels + ')')
    if (result.drawnSegments < 2) problems.push('the chart lines have no data (' + result.drawnSegments + ' segments)')
  }
  if (result.styledButton !== 'styled') problems.push('Element Plus styling missing (' + result.styledButton + ')')
  if (consoleErrors.length) problems.push(consoleErrors.length + ' console error(s)')

  console.log(JSON.stringify({ url, ...result, consoleErrors, ok: problems.length === 0, problems }, null, 2))
  process.exitCode = problems.length === 0 ? 0 : 1
} finally {
  try {
    socket?.close()
  } catch {
    /* gone */
  }
  browser.kill()
  await sleep(500)
  try {
    rmSync(profile, { recursive: true, force: true })
  } catch {
    /* held by the browser */
  }
}
