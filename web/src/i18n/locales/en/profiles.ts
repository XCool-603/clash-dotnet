/** profiles page strings. */
export const profiles = {
  'profiles.subtitle': 'Local configurations and remote subscriptions, stored by the backend.',
  'profiles.importUrl': 'Import URL',
  'profiles.new': 'New profile',
  'profiles.activate': 'Activate',
  'profiles.preview': 'Preview',
  'profiles.active': 'active',
  'profiles.updated': 'updated {time}',
  'profiles.expires': 'expires {date}',
  'profiles.usageOf': '{used} of {total}',
  'profiles.usageUsed': '{used} used',
  'profiles.loading': 'Loading profile…',

  'profiles.unavailable.title': 'Profiles are not available on this backend',
  'profiles.unavailable.metaCore':
    'The core is a meta build, but the app-level /profiles endpoints answered 404. Start the dashboard from the Clash.Server host to manage profiles.',
  'profiles.unavailable.stockCore':
    'GET /version reports meta: false, so this core has no profile or subscription support. Point the dashboard at a mihomo build, or edit the configuration file directly.',
  'profiles.unavailable.hint': 'core: {version} · meta: {meta}',

  'profiles.empty.title': 'No profiles yet',
  'profiles.empty.description': 'Create a local profile or import one from a subscription URL.',

  'profiles.deleteTitle': 'Delete profile',
  'profiles.deleteConfirm': 'Delete the profile “{name}”?',

  'profiles.activatedToast': 'Activated {name}',
  'profiles.updatedToast': 'Updated {name}',
  'profiles.deletedToast': 'Deleted {name}',
  'profiles.createdToast': 'Created {name}',
  'profiles.savedToast': 'Profile saved',
  'profiles.importedToast': 'Subscription imported',
  'profiles.parsedToast': {
    one: 'Subscription parsed: {count} node',
    other: 'Subscription parsed: {count} nodes',
  },
  'profiles.nameRequired': 'A profile name is required',
  'profiles.urlRequired': 'A subscription URL is required',

  'profiles.previewTitle': 'Preview — {name}',
  'profiles.editTitle': 'Edit — {name}',

  'profiles.create.title': 'New local profile',
  'profiles.create.name': 'Name',
  'profiles.create.namePlaceholder': 'my-config',
  'profiles.create.content': 'YAML content',
  'profiles.create.submit': 'Create',

  'profiles.import.title': 'Import from subscription URL',
  'profiles.import.url': 'Subscription URL',
  'profiles.import.urlPlaceholder': 'https://example.com/sub?token=…',
  'profiles.import.name': 'Name (optional)',
  'profiles.import.namePlaceholder': 'Derived from the URL when empty',
  'profiles.import.parsed': { one: 'Parsed {count} node', other: 'Parsed {count} nodes' },
  'profiles.import.check': 'Check URL',
}
