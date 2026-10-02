/**
 * The application shell: navigation, top bar, connection status, routing mode
 * and the shared failure/empty states.
 */
export const shell = {
  'brand.name': 'Clash',
  'brand.subtitle': 'dashboard',

  'nav.dashboard': 'Dashboard',
  'nav.proxies': 'Proxies',
  'nav.profiles': 'Profiles',
  'nav.connections': 'Connections',
  'nav.rules': 'Rules',
  'nav.logs': 'Logs',
  'nav.settings': 'Settings',

  'topbar.expandSidebar': 'Expand sidebar',
  'topbar.collapseSidebar': 'Collapse sidebar',
  'topbar.themeToLight': 'Switch to light theme',
  'topbar.themeToDark': 'Switch to dark theme',
  'topbar.coreVersion': 'Core version: {version}',
  'topbar.metaCore': 'MetaCubeX (mihomo) core — profiles and rule toggles are available',
  'topbar.stockCore': 'Stock core — profiles and per-rule toggles are not available',
  'topbar.language': 'Language',

  'status.connected': 'Connected',
  'status.disconnected': 'Disconnected',
  'status.secretRequired': 'Secret required',

  'mode.label': 'Mode',
  'mode.rule': 'Rule',
  'mode.global': 'Global',
  'mode.direct': 'Direct',
  'mode.ruleHint': 'Route traffic by the rule set',
  'mode.globalHint': 'Send everything through the selected proxy',
  'mode.directHint': 'Bypass all proxies',

  'error.generic': 'Something went wrong',
  'error.unauthorized': 'Authentication required',
  'error.network': 'Backend unreachable',
  'error.timeout': 'Request timed out',
  'error.notFound': 'Not available',
  'error.server': 'Backend error',
  'error.failed': 'Request failed',

  'delay.testing': 'testing…',
  'delay.failed': 'failed',
  'delay.inProgress': 'Health check in progress',
  'delay.noMeasurement': 'No measurement yet',
  'delay.band.good': 'fast',
  'delay.band.fair': 'acceptable',
  'delay.band.bad': 'slow',
  'delay.band.failed': 'failed',
  'delay.band.unknown': 'not measured',

  'secret.title': 'API secret required',
  'secret.unauthorized': 'The API secret is missing or incorrect',
  'secret.unreachable': 'Cannot reach the Clash API',
  'secret.description':
    'This Clash instance requires a secret. Enter it below — it is stored locally in your browser and sent as an Authorization header (and as ?token= for WebSockets).',
  'secret.offlineDescription':
    'The dashboard could not connect to {target}. Check that the backend is running and that the API address is right.',
  'secret.placeholder': 'API secret',

  'language.english': 'English',
  'language.chinese': '简体中文',
}
