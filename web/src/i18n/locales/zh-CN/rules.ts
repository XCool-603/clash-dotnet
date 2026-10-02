/** 规则页面：按匹配顺序排列的规则列表及其筛选、单条规则开关与规则集卡片。 */
export const rules = {
  'rules.totalInOrder': {
    one: '按匹配顺序共 {count} 条规则',
    other: '按匹配顺序共 {count} 条规则',
  },
  'rules.disabledCount': { one: '已禁用 {count} 条', other: '已禁用 {count} 条' },
  'rules.updated': '更新于 {time}',

  'rules.searchPlaceholder': '按类型、内容或目标筛选…',
  'rules.onlyDisabled': '仅看已禁用',

  'rules.emptyTitle': '暂无规则',
  'rules.emptyDescription': '内核返回的规则列表为空。请加载包含规则的订阅，或检查后端连接。',
  'rules.reloadRules': '重新加载规则',

  'rules.showingOf': {
    one: '共 {total} 条规则，显示 {shown} 条',
    other: '共 {total} 条规则，显示 {shown} 条',
  },
  'rules.renderingFirst': '仅渲染前 {limit} 条',
  'rules.filtered': '已筛选',
  'rules.toggleNote': '规则开关只在本次运行内生效：内核会在下次重载后恢复',

  'rules.loading': '正在加载规则…',
  'rules.noMatch': '没有规则符合当前筛选条件。',
  'rules.ruleSetEntries': {
    one: '该规则集包含 {count} 条',
    other: '该规则集包含 {count} 条',
  },
  'rules.toggleRule': '启用或禁用第 {index} 条规则',

  'rules.providersTitle': '规则集',
  'rules.providersUnsupportedPrefix': '该内核未提供 ',
  'rules.providersUnsupportedSuffix': '，因此无法在此列出或刷新规则集。上方的规则列表不受影响。',
  'rules.noProviders': '未配置规则集 —— 所有规则都是内联的。',
  'rules.providerUnknownBehavior': '未知行为',
  'rules.providerFormat': '格式 {format}',
  'rules.providerUpdated': '已更新规则集 {name}',
  'rules.providersUpdated': '规则集已全部更新',
}
