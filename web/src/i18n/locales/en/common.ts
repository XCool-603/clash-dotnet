/**
 * Shared vocabulary. Every view reuses these instead of inventing its own
 * wording for the same button or state.
 *
 * Deliberately not `as const`: the catalogue's *keys* must stay literal (so a
 * typo is a compile error) while the *values* stay `string`, which is what lets
 * the Chinese catalogue assign its own text to the same shape.
 */
export const common = {
  'action.save': 'Save',
  'action.cancel': 'Cancel',
  'action.close': 'Close',
  'action.refresh': 'Refresh',
  'action.reload': 'Reload',
  'action.retry': 'Retry',
  'action.delete': 'Delete',
  'action.edit': 'Edit',
  'action.copy': 'Copy',
  'action.copied': 'Copied',
  'action.confirm': 'Confirm',
  'action.add': 'Add',
  'action.remove': 'Remove',
  'action.apply': 'Apply',
  'action.reset': 'Reset',
  'action.search': 'Search',
  'action.clear': 'Clear',
  'action.update': 'Update',
  'action.updateAll': 'Update all',
  'action.import': 'Import',
  'action.export': 'Export',
  'action.enable': 'Enable',
  'action.disable': 'Disable',
  'action.test': 'Test',
  'action.details': 'Details',
  'action.back': 'Back',

  'state.loading': 'Loading…',
  'state.saving': 'Saving…',
  'state.empty': 'Nothing here yet',
  'state.error': 'Something went wrong',
  'state.unknown': 'Unknown',
  'state.none': 'None',
  'state.yes': 'Yes',
  'state.no': 'No',
  'state.on': 'On',
  'state.off': 'Off',
  'state.enabled': 'Enabled',
  'state.disabled': 'Disabled',
  'state.readonly': 'Read-only',

  'unit.bytes': 'B',
  'unit.kilobytes': 'KB',
  'unit.megabytes': 'MB',
  'unit.gigabytes': 'GB',
  'unit.perSecond': '/s',
  'unit.milliseconds': 'ms',
  'unit.seconds': 's',
  'unit.minutes': 'min',
  'unit.hours': 'h',
  'unit.days': 'd',

  'count.items': { one: '{count} item', other: '{count} items' },
  'count.nodes': { one: '{count} node', other: '{count} nodes' },
  'count.rules': { one: '{count} rule', other: '{count} rules' },
  'count.connections': { one: '{count} connection', other: '{count} connections' },
  'count.lines': { one: '{count} line', other: '{count} lines' },

  // Relative timestamps, produced by utils/format.ts.
  'time.justNow': 'just now',
  'time.minutesAgo': { one: '{count} min ago', other: '{count} min ago' },
  'time.hoursAgo': { one: '{count} h ago', other: '{count} h ago' },
  'time.daysAgo': { one: '{count} d ago', other: '{count} d ago' },
}
