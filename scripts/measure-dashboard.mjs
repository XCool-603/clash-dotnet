// Measures the dashboard in a real browser: navigation timing and JS heap.
//
// Drives Edge through the DevTools Protocol over the WebSocket client Node has
// built in, so no dependency is needed. Used to compare a bundle change against
// the previous one instead of guessing that it helped.
//
//   node scripts/measure-dashboard.mjs [url] [runs]

import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const url = process.argv[2] ?? 'http://127.0.0.1:9090/ui#/'
const runs = Number(process.argv[3] ?? 3)
const port = 9222

const edgeCandidates = [
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
]

const { existsSync } = await import('node:fs')
const edge = edgeCandidates.find(existsSync)
if (!edge) {
  console.error('msedge.exe not found')
  process.exit(2)
}

const profile = mkdtempSync(join(tmpdir(), 'dash-measure-'))
const browser = spawn(
  edge,
  [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    `--user-data-dir=${profile}`,
    `--remote-debugging-port=${port}`,
    'about:blank',
  ],
  { stdio: 'ignore' },
)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function targets() {
  for (let i = 0; i < 60; i++) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`)
      const list = await response.json()
      const page = list.find((t) => t.type === 'page')
      if (page) return page
    } catch {
      // the browser is still starting
    }
    await sleep(250)
  }
  throw new Error('the browser never exposed a debugging target')
}

let socket
let nextId = 1
const pending = new Map()

function send(method, params = {}) {
  const id = nextId++
  socket.send(JSON.stringify({ id, method, params }))
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }))
}

function evaluate(expression) {
  return send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }).then(
    (r) => r.result?.value,
  )
}

async function runOnce(index) {
  // A fresh navigation each time, so nothing is cached between runs except what
  // the browser itself keeps (which is what a returning visitor would see).
  await send('Page.navigate', { url })
  await sleep(2500)

  const metrics = await evaluate(`(() => {
    const nav = performance.getEntriesByType('navigation')[0] ?? {}
    const memory = performance.memory ?? {}
    return JSON.stringify({
      domContentLoaded: Math.round(nav.domContentLoadedEventEnd ?? 0),
      loadEvent: Math.round(nav.loadEventEnd ?? 0),
      transferredJs: Math.round(
        performance.getEntriesByType('resource')
          .filter((r) => r.name.endsWith('.js'))
          .reduce((sum, r) => sum + (r.transferSize || 0), 0) / 1024),
      decodedJs: Math.round(
        performance.getEntriesByType('resource')
          .filter((r) => r.name.endsWith('.js'))
          .reduce((sum, r) => sum + (r.decodedBodySize || 0), 0) / 1024),
      scriptCount: performance.getEntriesByType('resource').filter((r) => r.name.endsWith('.js')).length,
      jsHeapMB: memory.usedJSHeapSize ? +(memory.usedJSHeapSize / 1048576).toFixed(1) : null,
      totalHeapMB: memory.totalJSHeapSize ? +(memory.totalJSHeapSize / 1048576).toFixed(1) : null,
      nodes: document.getElementsByTagName('*').length,
      navRendered: !!document.querySelector('.nav__item'),
    })
  })()`)

  return { run: index + 1, ...JSON.parse(metrics) }
}

try {
  const target = await targets()
  socket = new WebSocket(target.webSocketDebuggerUrl)
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve)
    socket.addEventListener('error', reject)
  })
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(event.data)
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id)
      pending.delete(message.id)
      message.error ? reject(new Error(message.error.message)) : resolve(message.result)
    }
  })

  await send('Page.enable')
  await send('Runtime.enable')

  const samples = []
  for (let i = 0; i < runs; i++) samples.push(await runOnce(i))

  // A forced collection makes the heap figure comparable between builds.
  await send('HeapProfiler.enable')
  await send('HeapProfiler.collectGarbage')
  await sleep(500)
  const afterGc = await evaluate(
    'performance.memory ? +(performance.memory.usedJSHeapSize / 1048576).toFixed(1) : null',
  )

  const best = samples.reduce((a, b) => (a.domContentLoaded <= b.domContentLoaded ? a : b))
  console.log(
    JSON.stringify(
      {
        url,
        runs: samples.length,
        bestDomContentLoadedMs: best.domContentLoaded,
        bestLoadMs: best.loadEvent,
        jsDecodedKB: best.decodedJs,
        jsTransferredKB: best.transferredJs,
        scriptCount: best.scriptCount,
        jsHeapMB: best.jsHeapMB,
        jsHeapAfterGcMB: afterGc,
        domNodes: best.nodes,
        navRendered: samples.every((s) => s.navRendered),
        samples,
      },
      null,
      2,
    ),
  )
} finally {
  try {
    socket?.close()
  } catch {
    // already gone
  }
  browser.kill()
  await sleep(500)
  try {
    rmSync(profile, { recursive: true, force: true })
  } catch {
    // the browser may still hold a file
  }
}
