/** Logs page strings. */
export const logs = {
  'logs.subtitleBefore': 'Live core log over ',
  'logs.subtitleAfter': ' · {buffered} buffered · {matching} matching',

  'logs.status.idle': 'Stream idle',
  'logs.status.connecting': 'Connecting…',
  'logs.status.open': 'Streaming',
  'logs.status.reconnecting': 'Reconnecting…',
  'logs.status.stopped': 'Stopped',

  'logs.levelLabel': 'Log level',
  'logs.levelAndAbove': '{level} and above',
  'logs.searchPlaceholder': 'Search payload…',
  'logs.pause': 'Pause',
  'logs.resume': 'Resume',
  'logs.startStream': 'Start stream',
  'logs.stopStream': 'Stop stream',
  'logs.autoScroll': 'Auto-scroll',

  'logs.rendered': '{shown} of {total} line(s) rendered',
  'logs.showingLast': ' · showing the last {count}',
  'logs.buffer': '· buffer {used} / {limit}',
  'logs.dropped': '· {count} oldest line(s) dropped',
  'logs.pausedNote': '· paused, new lines keep buffering',

  'logs.emptyTitle': 'No log lines',
  'logs.emptyPaused': 'Live updates are paused. Resume to follow new lines.',
  'logs.emptyFiltered': 'No buffered line matches the current level and search filter.',
  'logs.emptyWaiting': 'Connected — waiting for the core to emit a log line.',
  'logs.emptyDisconnected': 'The log stream is not connected. Start it, or check the API address in Settings.',
}