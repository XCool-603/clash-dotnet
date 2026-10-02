/**
 * The settings page: the connection target and secret, appearance (theme and
 * language), the JSON configuration editor and the maintenance actions.
 *
 * A few notes are split into prefix/middle/suffix keys because an inline
 * `<code>` element sits in the middle of the sentence; the fragments are
 * concatenated around that element in the template.
 */
export const settings = {
  'settings.subtitle':
    'Connection, appearance and the running configuration · mode {mode} · core {core}',

  'settings.connection.title': 'Connection',
  'settings.connection.syncedAt': 'synced {time}',
  'settings.connection.neverSynced': 'not synced yet',
  'settings.connection.sameOrigin': 'Same origin',
  'settings.connection.sameOriginHint': 'Talk to the origin that served this page.',
  'settings.connection.apiBaseUrl': 'API base URL',
  'settings.connection.secret': 'Secret',
  'settings.connection.secretPlaceholder': 'external-controller secret',
  'settings.connection.target': 'Effective target',
  'settings.connection.reset': 'Reset connection',
  'settings.connection.resetDone': 'Connection settings reset to their defaults',
  'settings.connection.secretNotePrefix': 'The secret is sent as',
  'settings.connection.secretNoteMiddle': 'on REST and as',
  'settings.connection.secretNoteSuffix':
    "on WebSockets. Both values live in this browser's local storage.",

  'settings.appearance.title': 'Appearance',
  'settings.appearance.dark': 'Dark',
  'settings.appearance.light': 'Light',
  'settings.appearance.toggleTheme': 'Toggle theme',
  'settings.appearance.themeNote': 'The theme is stored in this browser only.',
  'settings.appearance.languageNote': 'The interface language is stored in this browser only.',

  'settings.config.title': 'Configuration',
  'settings.config.loaded': 'loaded',
  'settings.config.descriptionPrefix':
    'The editor holds the general configuration object as JSON. Applying sends only the keys you changed to',
  'settings.config.descriptionSuffix':
    ', which the core merges into the running document and applies in place: the reload is hot, so the process keeps running and active connections are not dropped.',
  'settings.config.loadingPlaceholder': 'Loading configuration…',
  'settings.config.apply': 'Apply changes',
  'settings.config.reloadFromCore': 'Reload from core',
  'settings.config.noChanges': 'no changes',
  'settings.config.changedKeys': { one: '{count} key changed', other: '{count} keys changed' },
  'settings.config.reloadFromFile': 'Reload from a file',
  'settings.config.reloadFileNote':
    're-reads the whole document from disk. This is a hot reload too: listeners, rules and providers are rebuilt in place without restarting the core.',
  'settings.config.errorEmpty': 'The editor is empty.',
  'settings.config.errorNotObject': 'The document must be a JSON object.',
  'settings.config.errorInvalid': 'Invalid JSON — {message}',
  'settings.config.nothingToApply':
    'Nothing to apply — the document matches the running configuration.',
  'settings.config.applied': 'Configuration applied — hot reload, the core was not restarted',
  'settings.config.pathRequired': 'A configuration path is required',
  'settings.config.reloaded': 'Configuration reloaded from disk',

  'settings.maintenance.title': 'Maintenance',
  'settings.maintenance.notePrefix':
    'Cache flushes are safe to repeat; restarting the core drops every active connection, so it asks first. An action this core does not implement answers',
  'settings.maintenance.noteSuffix':
    ', which is reported as "not supported" rather than as a failure.',
  'settings.maintenance.flushFakeIp': 'Flush fake-IP cache',
  'settings.maintenance.fakeIpFlushed': 'Fake-IP cache flushed',
  'settings.maintenance.fakeIpUnsupported': 'This core does not expose POST /cache/fakeip/flush',
  'settings.maintenance.flushDns': 'Flush DNS cache',
  'settings.maintenance.dnsFlushed': 'DNS cache flushed',
  'settings.maintenance.dnsUnsupported': 'This core does not expose POST /cache/dns/flush',
  'settings.maintenance.restartCore': 'Restart core',
  'settings.maintenance.restartConfirm':
    'Restart the Clash core process? Active connections will be dropped.',
  'settings.maintenance.restart': 'Restart',
  'settings.maintenance.restartRequested': 'Restart requested',
  'settings.maintenance.restartUnsupported':
    'This core does not expose POST /restart (embed mode omits it)',
  'settings.maintenance.core': 'Core',
  'settings.maintenance.coreNote': 'mode {mode} · log level {logLevel} · DNS {dns} · TUN {tun}',
}
