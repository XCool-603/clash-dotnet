/**
 * 设置页面：连接目标与密钥、外观（主题与语言）、JSON 配置编辑器以及维护操作。
 *
 * 部分说明文案按前缀/中段/后缀拆成多个键，因为句子中间夹着行内
 * `<code>` 元素，模板会把这几段拼在该元素两侧。
 */
export const settings = {
  'settings.subtitle': '连接、外观与运行中的配置 · 模式 {mode} · 内核 {core}',

  'settings.connection.title': '连接',
  'settings.connection.syncedAt': '已同步 {time}',
  'settings.connection.neverSynced': '尚未同步',
  'settings.connection.sameOrigin': '同源',
  'settings.connection.sameOriginHint': '与提供本页面的同源地址通信。',
  'settings.connection.apiBaseUrl': 'API 地址',
  'settings.connection.secret': '密钥',
  'settings.connection.secretPlaceholder': 'external-controller 密钥',
  'settings.connection.target': '实际目标',
  'settings.connection.reset': '重置连接',
  'settings.connection.resetDone': '连接设置已恢复默认值',
  'settings.connection.secretNotePrefix': '密钥在 REST 请求中通过',
  'settings.connection.secretNoteMiddle': '头发送，在 WebSocket 中通过',
  'settings.connection.secretNoteSuffix': '参数发送。这两项都保存在本浏览器的本地存储中。',

  'settings.appearance.title': '外观',
  'settings.appearance.dark': '深色',
  'settings.appearance.light': '浅色',
  'settings.appearance.toggleTheme': '切换主题',
  'settings.appearance.themeNote': '主题仅保存在本浏览器中。',
  'settings.appearance.languageNote': '界面语言仅保存在本浏览器中。',

  'settings.config.title': '配置',
  'settings.config.loaded': '已加载',
  'settings.config.descriptionPrefix':
    '编辑器以 JSON 形式保存通用配置对象。应用时只会把改动过的键发送到',
  'settings.config.descriptionSuffix':
    '，内核会把它合并进正在运行的配置并就地生效：这是热重载，进程保持运行，活动连接不会中断。',
  'settings.config.loadingPlaceholder': '正在加载配置…',
  'settings.config.apply': '应用更改',
  'settings.config.reloadFromCore': '从内核重载',
  'settings.config.noChanges': '没有改动',
  'settings.config.changedKeys': { one: '{count} 个键已更改', other: '{count} 个键已更改' },
  'settings.config.reloadFromFile': '从文件重载',
  'settings.config.reloadFileNote':
    '会从磁盘重新读取整个配置文档。这同样是热重载：监听器、规则与规则提供者都会就地重建，无需重启内核。',
  'settings.config.errorEmpty': '编辑器内容为空。',
  'settings.config.errorNotObject': '配置文档必须是 JSON 对象。',
  'settings.config.errorInvalid': 'JSON 无效 —— {message}',
  'settings.config.nothingToApply': '无需应用 —— 配置文档与正在运行的配置一致。',
  'settings.config.applied': '配置已应用 —— 热重载完成，内核未重启',
  'settings.config.pathRequired': '请填写配置路径',
  'settings.config.reloaded': '已从磁盘重新加载配置',

  'settings.maintenance.title': '维护',
  'settings.maintenance.notePrefix':
    '清空缓存可以放心重复执行；重启内核会中断所有活动连接，因此会先确认。内核未实现的接口会返回',
  'settings.maintenance.noteSuffix': '，此时会提示“不支持”，而不是失败。',
  'settings.maintenance.flushFakeIp': '清空 fake-IP 缓存',
  'settings.maintenance.fakeIpFlushed': 'fake-IP 缓存已清空',
  'settings.maintenance.fakeIpUnsupported': '该内核未提供 POST /cache/fakeip/flush',
  'settings.maintenance.flushDns': '清空 DNS 缓存',
  'settings.maintenance.dnsFlushed': 'DNS 缓存已清空',
  'settings.maintenance.dnsUnsupported': '该内核未提供 POST /cache/dns/flush',
  'settings.maintenance.restartCore': '重启内核',
  'settings.maintenance.restartConfirm': '要重启 Clash 内核进程吗？活动连接将被中断。',
  'settings.maintenance.restart': '重启',
  'settings.maintenance.restartRequested': '已请求重启',
  'settings.maintenance.restartUnsupported': '该内核未提供 POST /restart（嵌入模式下不提供）',
  'settings.maintenance.core': '内核',
  'settings.maintenance.coreNote': '模式 {mode} · 日志等级 {logLevel} · DNS {dns} · TUN {tun}',
}
