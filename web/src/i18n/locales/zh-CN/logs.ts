/** 日志页面文案。 */
export const logs = {
  'logs.subtitleBefore': '通过 ',
  'logs.subtitleAfter': ' 实时查看内核日志 · 已缓冲 {buffered} · 匹配 {matching}',

  'logs.status.idle': '日志流未启动',
  'logs.status.connecting': '连接中…',
  'logs.status.open': '接收中',
  'logs.status.reconnecting': '重连中…',
  'logs.status.stopped': '已停止',

  'logs.levelLabel': '日志级别',
  'logs.levelAndAbove': '{level} 及以上',
  'logs.searchPlaceholder': '搜索日志内容…',
  'logs.pause': '暂停',
  'logs.resume': '恢复',
  'logs.startStream': '启动日志流',
  'logs.stopStream': '停止日志流',
  'logs.autoScroll': '自动滚动',

  'logs.rendered': '已渲染 {shown} / {total} 行',
  'logs.showingLast': ' · 仅显示最后 {count} 行',
  'logs.buffer': '· 缓冲 {used} / {limit}',
  'logs.dropped': '· 已丢弃最早的 {count} 行',
  'logs.pausedNote': '· 已暂停，新日志仍在缓冲',

  'logs.emptyTitle': '暂无日志',
  'logs.emptyPaused': '实时更新已暂停。点击恢复以继续跟踪新日志。',
  'logs.emptyFiltered': '当前级别与搜索条件下没有匹配的日志。',
  'logs.emptyWaiting': '已连接——等待内核输出日志。',
  'logs.emptyDisconnected': '日志流未连接。请启动日志流，或到「设置」检查 API 地址。',
}
