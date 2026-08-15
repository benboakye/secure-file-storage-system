export type AppPage =
  | 'dashboard'
  | 'files'
  | 'shared'
  | 'trash'
  | 'upload'
  | 'inspection'
  | 'accepted'
  | 'rejected'
  | 'failed'
  | 'details'
  | 'audit'
  | 'admin'
  | 'admin-dashboard'
  | 'admin-resources'
  | 'admin-security'
  | 'admin-monitoring'
  | 'admin-lifecycle'
  | 'admin-audit'
  | 'admin-signin'
  | 'signin'
  | 'register'
  | 'check-email'
  | 'verify-email'
  | 'activate-privileged'

const protectedPages = new Set<AppPage>([
  'dashboard',
  'files',
  'shared',
  'trash',
  'upload',
  'inspection',
  'accepted',
  'rejected',
  'failed',
  'details',
  'audit',
  'admin',
  'admin-dashboard',
  'admin-resources',
  'admin-security',
  'admin-monitoring',
  'admin-lifecycle',
  'admin-audit',
])

const routeAliases: Record<string, AppPage> = {
  '': 'dashboard',
  top: 'dashboard',
  folders: 'dashboard',
  recent: 'dashboard',
  dashboard: 'dashboard',
  files: 'files',
  shared: 'shared',
  trash: 'trash',
  upload: 'upload',
  inspection: 'inspection',
  accepted: 'accepted',
  rejected: 'rejected',
  failed: 'failed',
  details: 'details',
  audit: 'audit',
  admin: 'admin',
  'admin-dashboard': 'admin-dashboard',
  'admin-resources': 'admin-resources',
  'admin-security': 'admin-security',
  'admin-monitoring': 'admin-monitoring',
  'admin-lifecycle': 'admin-lifecycle',
  'admin-audit': 'admin-audit',
  'admin-signin': 'admin-signin',
  signin: 'signin',
  register: 'register',
  'check-email': 'check-email',
  'verify-email': 'verify-email',
  'activate-privileged': 'activate-privileged',
}

export function pageFromHash(hash = window.location.hash): AppPage {
  const route = hash.replace(/^#\/?/, '').split('?')[0].toLowerCase()
  return routeAliases[route] ?? 'dashboard'
}

export function isProtectedPage(page: AppPage) {
  return protectedPages.has(page)
}

export function isAdminPage(page: AppPage) {
  return page === 'admin'
    || page === 'admin-dashboard'
    || page === 'admin-resources'
    || page === 'admin-security'
    || page === 'admin-monitoring'
    || page === 'admin-lifecycle'
    || page === 'admin-audit'
}

export function isStandardProtectedPage(page: AppPage) {
  return isProtectedPage(page) && !isAdminPage(page)
}
