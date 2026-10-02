/** profiles 页面文案。 */
export const profiles = {
  'profiles.subtitle': '本地配置与远程订阅，均由后端保存。',
  'profiles.importUrl': '导入链接',
  'profiles.new': '新建订阅',
  'profiles.activate': '启用',
  'profiles.preview': '预览',
  'profiles.active': '当前',
  'profiles.updated': '更新于 {time}',
  'profiles.expires': '到期 {date}',
  'profiles.usageOf': '已用 {used} / 共 {total}',
  'profiles.usageUsed': '已用 {used}',
  'profiles.loading': '正在加载订阅…',

  'profiles.unavailable.title': '该后端不支持订阅管理',
  'profiles.unavailable.metaCore':
    '内核是 meta 版本，但应用层的 /profiles 接口返回 404。请从 Clash.Server 主机启动控制面板以管理订阅。',
  'profiles.unavailable.stockCore':
    'GET /version 返回 meta: false，该内核不支持订阅。请将控制面板指向 mihomo 内核，或直接编辑配置文件。',
  'profiles.unavailable.hint': '内核：{version} · meta：{meta}',

  'profiles.empty.title': '暂无订阅',
  'profiles.empty.description': '新建一个本地订阅，或从订阅链接导入。',

  'profiles.deleteTitle': '删除订阅',
  'profiles.deleteConfirm': '确定删除订阅“{name}”？',

  'profiles.activatedToast': '已启用 {name}',
  'profiles.updatedToast': '已更新 {name}',
  'profiles.deletedToast': '已删除 {name}',
  'profiles.createdToast': '已创建 {name}',
  'profiles.savedToast': '订阅已保存',
  'profiles.importedToast': '订阅已导入',
  // 中文不区分单复数，两栏填同样的文本。
  'profiles.parsedToast': {
    one: '订阅解析完成：{count} 个节点',
    other: '订阅解析完成：{count} 个节点',
  },
  'profiles.nameRequired': '请填写订阅名称',
  'profiles.urlRequired': '请填写订阅链接',

  'profiles.previewTitle': '预览 — {name}',
  'profiles.editTitle': '编辑 — {name}',

  'profiles.create.title': '新建本地订阅',
  'profiles.create.name': '名称',
  'profiles.create.namePlaceholder': 'my-config',
  'profiles.create.content': 'YAML 内容',
  'profiles.create.submit': '创建',

  'profiles.import.title': '从订阅链接导入',
  'profiles.import.url': '订阅链接',
  'profiles.import.urlPlaceholder': 'https://example.com/sub?token=…',
  'profiles.import.name': '名称（可选）',
  'profiles.import.namePlaceholder': '留空则根据链接生成',
  'profiles.import.parsed': { one: '已解析 {count} 个节点', other: '已解析 {count} 个节点' },
  'profiles.import.check': '检查链接',
}
