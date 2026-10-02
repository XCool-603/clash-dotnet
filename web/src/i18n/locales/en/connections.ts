/**
 * The connections page: the live/history table, its column headers, the
 * connection detail drawer and the close-all confirmation.
 */
export const connections = {
  'connections.active': { one: '{count} active', other: '{count} active' },
  'connections.history': { one: '{count} in history', other: '{count} in history' },
  'connections.totalTraffic': 'total {down} down / {up} up',

  'connections.tabActive': { one: 'Active ({count})', other: 'Active ({count})' },
  'connections.tabClosed': { one: 'Closed ({count})', other: 'Closed ({count})' },
  'connections.tabAll': 'All',

  'connections.searchPlaceholder': 'Search host, rule, chain, process…',
  'connections.pause': 'Pause',
  'connections.resume': 'Resume',
  'connections.closeAll': 'Close all',
  'connections.closeAllTitle': 'Close all connections',
  'connections.closeAllConfirm': {
    one: 'Close all {count} active connection?',
    other: 'Close all {count} active connections?',
  },
  'connections.closeAllDone': 'All connections closed',
  'connections.closeConnection': 'Close connection',
  'connections.closeConnectionTo': 'Close connection to {host}',
  'connections.detailsFor': 'Details for {host}',

  'connections.showingFirst': 'showing the first {limit}',
  'connections.paused': 'paused',
  'connections.liveAt': 'live @ {interval} ms',
  'connections.clearHistory': 'Clear history',
  'connections.sortBy': 'Sort by {column}',

  'connections.emptyTitle': 'No connections',
  'connections.emptyPaused': 'Live updates are paused. Resume to see new connections.',
  'connections.emptyDescription': 'Nothing is going through the proxy right now.',

  'connections.detailTitle': 'Connection detail',
  'connections.detail.id': 'ID',
  'connections.detail.network': 'Network',
  'connections.detail.rulePayload': 'Rule payload',
  'connections.detail.started': 'Started',
  'connections.detail.destinationPort': 'Destination port',
  'connections.detail.dnsMode': 'DNS mode',
  'connections.detail.sniffHost': 'Sniff host',
  'connections.detail.processPath': 'Process path',
  'connections.detail.remoteDestination': 'Remote destination',
  'connections.detail.specialProxy': 'Special proxy',
  'connections.detail.specialRules': 'Special rules',
  'connections.detail.inbound': 'Inbound',
  'connections.detail.inboundUser': 'Inbound user',

  'connections.column.host': 'Host',
  'connections.column.network': 'Net',
  'connections.column.type': 'Type',
  'connections.column.chains': 'Chains',
  'connections.column.rule': 'Rule',
  'connections.column.upload': 'Upload',
  'connections.column.download': 'Download',
  'connections.column.duration': 'Duration',
  'connections.column.source': 'Source',
  'connections.column.destination': 'Destination',
  'connections.column.process': 'Process',
}
