/** 应用外壳：导航、顶栏、连接状态、路由模式与共用的失败/空状态。 */
export const shell = {
  'brand.name': 'Clash',
  'brand.subtitle': '控制面板',

  'nav.dashboard': '概览',
  'nav.proxies': '代理',
  'nav.profiles': '订阅',
  'nav.connections': '连接',
  'nav.rules': '规则',
  'nav.logs': '日志',
  'nav.settings': '设置',

  'topbar.expandSidebar': '展开侧栏',
  'topbar.collapseSidebar': '收起侧栏',
  'topbar.themeToLight': '切换到浅色主题',
  'topbar.themeToDark': '切换到深色主题',
  'topbar.coreVersion': '内核版本：{version}',
  'topbar.metaCore': 'MetaCubeX (mihomo) 内核 —— 支持订阅与单条规则开关',
  'topbar.stockCore': '原版内核 —— 不支持订阅与单条规则开关',
  'topbar.language': '语言',

  'status.connected': '已连接',
  'status.disconnected': '未连接',
  'status.secretRequired': '需要密钥',

  'mode.label': '模式',
  'mode.rule': '规则',
  'mode.global': '全局',
  'mode.direct': '直连',
  'mode.ruleHint': '按规则集分流',
  'mode.globalHint': '所有流量走选中的代理',
  'mode.directHint': '绕过所有代理',

  'error.generic': '出错了',
  'error.unauthorized': '需要身份验证',
  'error.network': '无法连接到后端',
  'error.timeout': '请求超时',
  'error.notFound': '不支持该功能',
  'error.server': '后端错误',
  'error.failed': '请求失败',

  'delay.testing': '测试中…',
  'delay.failed': '失败',
  'delay.inProgress': '正在测速',
  'delay.noMeasurement': '尚未测速',
  'delay.band.good': '快',
  'delay.band.fair': '一般',
  'delay.band.bad': '慢',
  'delay.band.failed': '失败',
  'delay.band.unknown': '未测速',

  'secret.title': '需要 API 密钥',
  'secret.unauthorized': 'API 密钥缺失或不正确',
  'secret.unreachable': '无法连接到 Clash API',
  'secret.description':
    '该 Clash 实例要求密钥。请在下方填写——它只保存在你的浏览器本地，请求时作为 Authorization 头发送（WebSocket 使用 ?token=）。',
  'secret.offlineDescription':
    '控制面板无法连接到 {target}。请确认后端正在运行，且 API 地址填写正确。',
  'secret.placeholder': 'API 密钥',

  'language.english': 'English',
  'language.chinese': '简体中文',
}
