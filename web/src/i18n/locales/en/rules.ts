/**
 * The rules page: the ordered rule list and its filters, the per-rule toggles
 * and the rule-provider cards.
 */
export const rules = {
  'rules.totalInOrder': {
    one: '{count} rule in evaluation order',
    other: '{count} rules in evaluation order',
  },
  'rules.disabledCount': { one: '{count} disabled', other: '{count} disabled' },
  'rules.updated': 'updated {time}',

  'rules.searchPlaceholder': 'Filter by type, payload or target…',
  'rules.onlyDisabled': 'Only disabled',

  'rules.emptyTitle': 'No rules reported',
  'rules.emptyDescription':
    'The core returned an empty rule list. Load a profile that has rules, or check the backend connection.',
  'rules.reloadRules': 'Reload rules',

  'rules.showingOf': { one: '{shown} of {total} rule', other: '{shown} of {total} rules' },
  'rules.renderingFirst': 'rendering the first {limit}',
  'rules.filtered': 'filtered',
  'rules.toggleNote': 'toggling a rule is process-local: the core keeps it until the next reload',

  'rules.loading': 'Loading rules…',
  'rules.noMatch': 'No rule matches the current filter.',
  'rules.ruleSetEntries': {
    one: '{count} entry in this rule set',
    other: '{count} entries in this rule set',
  },
  'rules.toggleRule': 'Enable or disable rule {index}',

  'rules.providersTitle': 'Rule providers',
  'rules.providersUnsupportedPrefix': 'This core does not expose ',
  'rules.providersUnsupportedSuffix':
    ', so rule providers cannot be listed or refreshed here. The rule list above is unaffected.',
  'rules.noProviders': 'No rule providers are configured — every rule is inline.',
  'rules.providerUnknownBehavior': 'unknown behaviour',
  'rules.providerFormat': 'format {format}',
  'rules.providerUpdated': 'Updated provider {name}',
  'rules.providersUpdated': 'Rule providers updated',
}
