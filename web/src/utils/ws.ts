import { useSettingsStore } from '@/stores/settings'
import { messageOf } from '@/utils/async'

export type StreamStatus = 'idle' | 'connecting' | 'open' | 'reconnecting' | 'stopped'

/**
 * Build an absolute `ws://` / `wss://` URL for a Clash streaming endpoint.
 *
 * The secret is passed as `?token=` because browsers cannot set an
 * `Authorization` header on a WebSocket handshake.
 */
export function buildWebSocketUrl(path: string): string {
  const settings = useSettingsStore()
  const raw = settings.apiBase
  const origin = window.location.origin

  let base: string
  if (!raw) {
    base = origin
  } else if (/^https?:\/\//i.test(raw)) {
    base = raw
  } else {
    base = `${origin}${raw.startsWith('/') ? raw : `/${raw}`}`
  }

  base = base.replace(/\/+$/, '')
  if (base.startsWith('https://')) base = `wss://${base.slice('https://'.length)}`
  else if (base.startsWith('http://')) base = `ws://${base.slice('http://'.length)}`
  else if (!base.startsWith('ws://') && !base.startsWith('wss://')) base = `ws://${base}`

  const suffix = path.startsWith('/') ? path : `/${path}`
  const url = new URL(`${base}${suffix}`)

  const secret = settings.secret.trim()
  if (secret) url.searchParams.set('token', secret)
  return url.toString()
}

export interface ReconnectingStreamOptions {
  /** Called on every (re)connect attempt to resolve the current URL. */
  url: () => string
  onMessage: (data: string) => void
  onOpen?: () => void
  onClose?: (code: number) => void
  onStatus?: (status: StreamStatus) => void
  /** First retry delay. Defaults to 500ms. */
  minDelayMs?: number
  /** Retry delay ceiling. Defaults to 15s. */
  maxDelayMs?: number
}

/**
 * A WebSocket that transparently reconnects with exponential backoff
 * (plus jitter) until it is explicitly stopped.
 */
export class ReconnectingStream {
  private socket: WebSocket | null = null
  private timer: ReturnType<typeof setTimeout> | null = null
  private attempt = 0
  private running = false

  private readonly options: ReconnectingStreamOptions
  private readonly minDelay: number
  private readonly maxDelay: number

  status: StreamStatus = 'idle'
  lastError: string | null = null

  constructor(options: ReconnectingStreamOptions) {
    this.options = options
    this.minDelay = options.minDelayMs ?? 500
    this.maxDelay = options.maxDelayMs ?? 15_000
  }

  get isRunning(): boolean {
    return this.running
  }

  start(): void {
    if (this.running) return
    this.running = true
    this.attempt = 0
    this.open()
  }

  /** Tear everything down. Safe to call more than once. */
  stop(): void {
    this.running = false
    this.clearTimer()
    const socket = this.socket
    this.socket = null
    if (socket) {
      socket.onopen = null
      socket.onmessage = null
      socket.onerror = null
      socket.onclose = null
      try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
          socket.close()
        }
      } catch {
        // Ignore — the socket is already gone.
      }
    }
    this.setStatus('stopped')
  }

  private setStatus(status: StreamStatus): void {
    if (this.status === status) return
    this.status = status
    this.options.onStatus?.(status)
  }

  private clearTimer(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer)
      this.timer = null
    }
  }

  private open(): void {
    if (!this.running) return

    if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
      return
    }

    let url: string
    try {
      url = this.options.url()
    } catch (error) {
      this.scheduleReconnect(messageOf(error))
      return
    }

    this.setStatus(this.attempt === 0 ? 'connecting' : 'reconnecting')

    let socket: WebSocket
    try {
      socket = new WebSocket(url)
    } catch (error) {
      this.scheduleReconnect(messageOf(error))
      return
    }
    this.socket = socket

    socket.onopen = (): void => {
      if (!this.running) {
        socket.close()
        return
      }
      this.attempt = 0
      this.lastError = null
      this.setStatus('open')
      this.options.onOpen?.()
    }

    socket.onmessage = (event: MessageEvent): void => {
      if (!this.running) return
      const data = event.data
      if (typeof data === 'string') this.options.onMessage(data)
    }

    socket.onerror = (): void => {
      // A `close` event always follows, which is where we reconnect.
      this.lastError = 'WebSocket error'
    }

    socket.onclose = (event: CloseEvent): void => {
      if (this.socket === socket) this.socket = null
      this.options.onClose?.(event.code)
      if (!this.running) return
      this.scheduleReconnect(`connection closed (${event.code})`)
    }
  }

  private scheduleReconnect(reason: string): void {
    if (!this.running) return
    this.setStatus('reconnecting')
    this.lastError = reason

    const backoff = Math.min(this.maxDelay, this.minDelay * 2 ** this.attempt)
    const jitter = Math.random() * Math.min(this.minDelay, 500)
    this.attempt += 1

    this.clearTimer()
    this.timer = setTimeout(() => {
      this.timer = null
      this.open()
    }, backoff + jitter)
  }
}
