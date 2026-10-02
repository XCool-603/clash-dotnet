/**
 * The dashboard page: the header, the stat cards, the traffic and memory
 * panels, the quick proxy selector and the core-dependent actions.
 */
export const dashboard = {
  'dashboard.subtitle': 'Live throughput, memory and the current routing mode.',

  'dashboard.upload': 'Upload',
  'dashboard.download': 'Download',
  'dashboard.uploadTotal': 'Upload total',
  'dashboard.downloadTotal': 'Download total',
  'dashboard.activeConnections': 'Active connections',
  'dashboard.memoryInUse': 'Memory in use',

  'dashboard.peak': 'peak {rate}',
  'dashboard.sinceCoreStart': 'since the core started',
  'dashboard.closedThisSession': '{count} closed this session',
  'dashboard.memoryLimit': 'limit {size}',
  'dashboard.sampleCount': { one: '{count} sample', other: '{count} samples' },

  'dashboard.traffic': 'Traffic',
  'dashboard.trafficWindow': '1 Hz · 2.5 min window',
  'dashboard.memory': 'Memory',
  'dashboard.osLimit': 'OS limit',

  'dashboard.quickProxy': 'Quick proxy',
  'dashboard.testGroup': 'Test this group',
  'dashboard.testGroupTitle': 'Test this group against {url}',
  'dashboard.groupLabel': 'Group',
  'dashboard.groupReadOnly': '— read-only, the core picks the member automatically.',
  'dashboard.emptyTitle': 'No proxy groups',
  'dashboard.emptyDescription': 'The core has not reported any proxy groups yet.',
  'dashboard.loadProxies': 'Load proxies',

  'dashboard.actions': 'Actions',
  'dashboard.flushFakeIp': 'Flush fake-IP',
  'dashboard.restartCore': 'Restart core',
  'dashboard.restart': 'Restart',
  'dashboard.restartConfirm': 'Restart the Clash core process? Active connections will be dropped.',
  'dashboard.restartRequested': 'Restart requested',
  'dashboard.restartUnsupported': 'This core does not expose POST /restart (embed mode omits it)',
  'dashboard.fakeIpFlushed': 'Fake-IP cache flushed',
  'dashboard.fakeIpUnsupported': 'This core does not expose POST /cache/fakeip/flush',
  'dashboard.actionsNoteBefore': 'Both actions are core-dependent: a stock build may not mount',
  'dashboard.actionsNoteAfter': ', in which case the dashboard says so instead of failing silently.',
}
