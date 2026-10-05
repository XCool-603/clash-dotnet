// Counts the API traffic the dashboard actually generates.
//
// The core's CPU with a dashboard attached was far above what the documented
// poll intervals predict, so this measures the client side rather than guessing:
// it reports every request the page makes over a window, grouped by path.

import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const url = process.argv[2] ?? 'http://127.0.0.1:9090/ui#/'
const windowMs = Number(process.argv[3] ?? 10000)
const port = 9224
const edge = [
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
].find(existsSync)
if (!edge) {
  console.error('msedge.exe not found')
  process.exit(2)
}

const profile = mkdtempSync(join(tmpdir(), 'dash-count-'))
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
      /* starting */
    }
    await sleep(250)
  }
  throw new Error('no target')
}

let socket
let id = 1
const pending = new Map()
const seen = []

const send = (method, params = {}) => {
  const messageId = id++
  socket.send(JSON.stringify({ id: messageId, method, params }))
  return new Promise((resolve, reject) => pending.set(messageId, { resolve, reject }))
}

try {
  const page = await target()
  socket = new WebSocket(page.webSocketDebuggerUrl)
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve)
    socket.addEventListener('error', reject)
  })
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(event.data)
    if (message.method === 'Network.requestWillBeSent') {
      seen.push(message.params.request.url)
    }
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id)
      pending.delete(message.id)
      message.error ? reject(new Error(message.error.message)) : resolve(message.result)
    }
  })

  await send('Page.enable')
  await send('Runtime.enable')
  await send('Network.enable')
  await send('Page.navigate', { url })

  // Let the first paint and the lazy chunks settle before counting.
  await sleep(4000)
  seen.length = 0
  await sleep(windowMs)

  const counts = new Map()
  for (const request of seen) {
    let path
    try {
      path = new URL(request).pathname
    } catch {
      path = request
    }
    counts.set(path, (counts.get(path) ?? 0) + 1)
  }

  const seconds = windowMs / 1000
  const rows = [...counts.entries()]
    .map(([path, count]) => ({ path, count, perSecond: +(count / seconds).toFixed(2) }))
    .sort((a, b) => b.count - a.count)

  const total = seen.length
  console.log(
    JSON.stringify(
      { url, windowSeconds: seconds, totalRequests: total, perSecond: +(total / seconds).toFixed(2), byPath: rows },
      null,
      2,
    ),
  )

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
    /* held */
  }
}
