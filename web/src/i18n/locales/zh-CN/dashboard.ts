/** 概览页面文案：页头、统计卡片、流量与内存面板、快速切换代理和内核相关操作。 */
export const dashboard = {
  'dashboard.subtitle': '实时速率、内存占用与当前路由模式。',

  'dashboard.upload': '上传',
  'dashboard.download': '下载',
  'dashboard.uploadTotal': '上传总量',
  'dashboard.downloadTotal': '下载总量',
  'dashboard.activeConnections': '活动连接',
  'dashboard.memoryInUse': '内存占用',

  'dashboard.peak': '峰值 {rate}',
  'dashboard.sinceCoreStart': '自内核启动以来',
  'dashboard.closedThisSession': '本会话已关闭 {count} 个',
  'dashboard.memoryLimit': '上限 {size}',
  // 中文不区分单复数，两栏填同样的文本。
  'dashboard.sampleCount': { one: '{count} 个采样', other: '{count} 个采样' },

  'dashboard.traffic': '流量',
  'dashboard.trafficWindow': '1 Hz · 2.5 分钟窗口',
  'dashboard.memory': '内存',
  'dashboard.osLimit': '系统上限',

  'dashboard.quickProxy': '快速切换代理',
  'dashboard.testGroup': '测试该分组',
  'dashboard.testGroupTitle': '使用 {url} 测试该分组',
  'dashboard.groupLabel': '分组',
  'dashboard.groupReadOnly': '——只读，由内核自动选择成员。',
  'dashboard.emptyTitle': '暂无代理分组',
  'dashboard.emptyDescription': '内核尚未返回任何代理分组。',
  'dashboard.loadProxies': '加载代理',

  'dashboard.actions': '操作',
  'dashboard.flushFakeIp': '清除 fake-IP 缓存',
  'dashboard.restartCore': '重启内核',
  'dashboard.restart': '重启',
  'dashboard.restartConfirm': '确定重启 Clash 内核进程？现有连接会被中断。',
  'dashboard.restartRequested': '已请求重启',
  'dashboard.restartUnsupported': '该内核未提供 POST /restart（嵌入式模式已省略）',
  'dashboard.fakeIpFlushed': 'fake-IP 缓存已清除',
  'dashboard.fakeIpUnsupported': '该内核未提供 POST /cache/fakeip/flush',
  'dashboard.actionsNoteBefore': '这两个操作依赖内核支持：原版内核可能未挂载',
  'dashboard.actionsNoteAfter': '，此时面板会明确提示，而不是静默失败。',
}
