/** proxies 页面文案。 */
export const proxies = {
  // 中文不区分单复数，两栏填同样的文本。
  'proxies.groupCount': { one: '{count} 个分组', other: '{count} 个分组' },
  'proxies.filterPlaceholder': '筛选节点…',
  'proxies.sort.groupOrder': '分组顺序',
  'proxies.sort.fastest': '延迟最低优先',
  'proxies.testAllGroups': '测试全部分组',
  'proxies.testAll': '全部测速',
  'proxies.testGroup': '测试 {name} 中的全部节点',
  'proxies.reload': '重新加载代理',
  'proxies.auto': '自动',
  'proxies.noMatch': '没有匹配“{query}”的节点。',
  'proxies.node.selectTitle': '{name} — 点击选择',
  'proxies.node.staticTitle': '{name} — {type} 分组自动选择成员',
  'proxies.empty.title': '未获取到代理',
  'proxies.empty.description': '内核返回的代理列表为空。请加载订阅，或检查后端连接。',
  'proxies.providers': '代理集合',
  'proxies.providerUpdated': '更新于 {time}',
  'proxies.providerUpdatedToast': '已更新代理集合 {name}',
  'proxies.expires': '到期 {date}',
}
