import { handleAuthenticationExpiry } from './authenticationExpiry'

export type ApiUser = {
  id: string
  name: string
  email: string
  role: 'user' | 'auditor' | 'admin'
}

export type AdminUser = {
  id: string
  name: string
  email: string
  role: 'user' | 'auditor' | 'admin'
  verificationStatus: 'pending' | 'verified'
  accountStatus: 'active' | 'suspended' | 'locked'
  emailVerifiedAt?: string
  createdAt: string
}

export type AdminUserPage = {
  users: AdminUser[]
  total: number
  limit: number
  offset: number
}

export type AdminResource = {
  id: string
  ownerId: string
  name: string
  size: number
  declaredMediaType: string
  detectedMediaType: string
  status: UploadStatus
  decisionReason?: string
  correlationId: string
  createdAt: string
}

export type AdminResourcePage = {
  resources: AdminResource[]
  summary: {
    trackedUploads: number
    trackedBytes: number
    quarantineBytes: number
    orphanedObjects: number
    orphanedBytes: number
    pendingProcessing: number
    bytesLast24Hours: number
    bytesLast7Days: number
    ownerUsage: Array<{ ownerId: string; uploads: number; bytes: number; quotaBytes: number }>
    defaultQuotaBytes: number
    quotaAlerts: number
    quotaOverrides: Array<{ ownerId: string; quotaBytes: number }>
    statusCounts: Partial<Record<UploadStatus, number>>
    metadataDurable: boolean
    runtimeOnly: boolean
    protectedStorageConnected: boolean
	storageCapacityBytes: number
	storageReserveBytes: number
	reservedCapacityBytes: number
	activeReservations: number
    protectedCapacity: {
      trackedObjects: number
      trackedCiphertextBytes: number
      orphanedObjects: number
      orphanedBytes: number
      missingObjects: number
      volumeTotalBytes: number
      volumeAvailableBytes: number
      volumeUsedPercent: number
      alerts: Array<{ id: string; severity: string; title: string; detail: string; count: number }>
    }
  }
  total: number
  limit: number
  offset: number
}

export type OrphanPreview = {
  generatedAt: string
  minimumAgeSeconds: number
  candidates: Array<{ token: string; zone: 'quarantine' | 'protected'; size: number; modifiedAt: string; eligible: boolean; reason: string }>
}

export type AdminSecuritySummary = {
  generatedAt: string
  authentication: {
    passwordHashAlgorithm: string
    passwordHashCost: number
    sessionTtlSeconds: number
    verificationTtlSeconds: number
    emailVerificationRequired: boolean
    opaqueServerSessions: boolean
    csrfProtection: boolean
    privilegedBoundary: boolean
    mfaEnforced: boolean
    accountLockoutEnabled: boolean
	loginFailureThreshold: number
	loginFailureWindowSeconds: number
	accountLockSeconds: number
	adminStepUpEnforced: boolean
	stepUpTtlSeconds: number
  }
  accounts: {
    total: number
    verified: number
    unverified: number
    active: number
    suspended: number
    locked: number
    administrators: number
    auditors: number
  }
  ingestion: {
    statusCounts: Partial<Record<UploadStatus, number>>
    scanner: { connected: boolean; productionReady: boolean; failClosed: boolean; signaturesFresh: boolean; adapter: string; policyVersion: string; engineVersion?: string; signatureDatabase?: string; signatureUpdatedAt?: string; signatureAgeSeconds?: number; signatureMaxAgeSeconds?: number; checkedAt?: string; detail: string }
  }
  auditChainConnected: boolean
  auditAnchor: AuditAnchorPosture
  encryptionServiceConnected: boolean
  keyService: { connected: boolean; productionReady: boolean; hardwareBacked: boolean; adapter: string; provider?: string; keyId: string; keyVersion: string; checkedAt?: string; detail: string }
  keyRotation: {
    currentKekId: string
    currentKekVersion: string
    protectedVersions: number
    currentVersions: number
    pendingVersions: number
    completedRewraps: number
    durable: boolean
  }
}

export type AdminMonitoringSummary = {
  generatedAt: string
  startedAt: string
  uptimeSeconds: number
  api: { status: string }
  persistence: {
    authentication: { durable: boolean; driver: string }
    ingestionDurable: boolean
  }
  worker: { mode: string; pendingProcessing: number; failedRecords: number }
  quarantine: { bytes: number; orphanedObjects: number; orphanedBytes: number }
  scanner: { connected: boolean; productionReady: boolean; failClosed: boolean; signaturesFresh: boolean; adapter: string; policyVersion: string; engineVersion?: string; signatureDatabase?: string; signatureUpdatedAt?: string; signatureAgeSeconds?: number; signatureMaxAgeSeconds?: number; checkedAt?: string; detail: string }
  policies: {
    ingestion: { maxUploadBytes: number; defaultOwnerQuotaBytes: number; inspectionTtlSeconds: number; storageCapacityBytes: number; storageReserveBytes: number; reservationTtlSeconds: number }
    sessionTtlSeconds: number
    secureCookies: boolean
    allowedOrigins: number
    deploymentMode: 'development' | 'production'
    httpsRequired: boolean
  }
  externalTelemetryConnected: boolean
	telemetry: { exporterEnabled: boolean; connected: boolean; scrapesTotal: number; lastScrapeAt?: string; staleAfterSeconds: number }
  backupMonitoringConnected: boolean
  encryptionServiceConnected: boolean
  keyService: { connected: boolean; productionReady: boolean; hardwareBacked: boolean; adapter: string; provider?: string; keyId: string; keyVersion: string; checkedAt?: string; detail: string }
  audit: {
    durable: boolean
    integrityValid: boolean
    eventCount: number
    eventsLast24Hours: number
    deniedLast24Hours: number
    highRiskLast24Hours: number
    pendingEvidence: number
    anchor: AuditAnchorPosture
    alerts: AuditAlert[]
  }
}

export type AuditAnchorPosture = {
  connected: boolean
  productionReady: boolean
  adapter: string
  detail: string
  valid: boolean
  anchoredThrough: number
  anchoredAt?: string
  failureCategory?: string
}

export type AdminLifecycleSummary = {
  generatedAt: string
  lifecycle: {
    statusCounts: Partial<Record<UploadStatus, number>>
    pendingProcessing: number
    stuckProcessing: number
    oldestPendingAt?: string
    trackedRecords: number
    metadataDurable: boolean
    quarantineBytes: number
    orphanedObjects: number
    orphanedBytes: number
    recentRecords: AdminResource[]
  }
  capabilities: {
    quarantineWorkflow: boolean
    inspectionDecisions: boolean
    protectedStorage: boolean
    versionHistory: boolean
    retentionPolicy: boolean
    legalHolds: boolean
    deletionGracePeriod: boolean
    cryptographicDeletion: boolean
    backupMonitoring: boolean
    verifiedRecovery: boolean
  }
  protectedFiles: LifecycleSummary
}

export type AuditEvent = {
  sequence: number
  eventId: string
  occurredAt: string
  actorType: string
  actorId: string
  action: string
  resourceType: string
  resourceId: string
  outcome: string
  reasonCode: string
  correlationId: string
  fromState?: string
  toState?: string
  keyVersion: string
  networkSource?: string
}

export type AuditAlert = { id: string; type: string; severity: 'medium' | 'high' | 'critical'; title: string; detail: string; count: number; detectedAt: string }
export type AuditFilters = { search?: string; actorId?: string; action?: string; resourceType?: string; outcome?: string; ipAddress?: string; from?: string; to?: string; limit?: number; offset?: number }

export type AuditPage = {
  events: AuditEvent[]
  total: number
  limit: number
  offset: number
  verification: {
    valid: boolean
    eventCount: number
    verifiedThrough: number
    checkpointAt?: string
    checkpointTrust: string
    failureCategory?: string
    firstInvalidSequence?: number
    anchor: {
      connected: boolean
      productionReady: boolean
      adapter: string
      detail: string
      valid: boolean
      anchoredThrough: number
      anchoredAt?: string
      failureCategory?: string
    }
  }
  summary: { total: number; matching: number; successful: number; denied: number; failed: number; last24Hours: number; distinctActors: number; highRisk: number }
  alerts: AuditAlert[]
}

export type ApiSession = {
  user: ApiUser
  csrfToken: string
}
export type PrivilegedMFAChallenge = { mfaRequired: true; mode: 'enroll' | 'challenge'; challengeToken: string; expiresAt: string; manualEntrySecret?: string; otpAuthUri?: string }
export type PrivilegedMFACompletion = ApiSession & { recoveryCodes?: string[] }

export type ApiMessage = { message: string }

export type UploadStatus = 'quarantined' | 'inspecting' | 'accepted' | 'encrypting' | 'stored' | 'rejected' | 'failed'

export type ApiUpload = {
  id: string
  name: string
  size: number
  declaredMediaType: string
  detectedMediaType: string
  status: UploadStatus
  progress: number
  decisionReason?: string
  correlationId: string
  createdAt: string
}

export type UserFilePage = {
  files: LogicalFile[]
  total: number
}

export type LogicalFile = { fileId: string; ownerId: string; name: string; currentVersionId: string; createdAt: string; updatedAt: string }
export type LifecycleFile = LogicalFile & { deletedAt?: string; purgeAfter?: string; retentionUntil?: string; legalHold: boolean; legalHoldReason?: string; purgedAt?: string }
export type DeletionOperation = { operationId: string; fileId: string; ownerId: string; status: 'pending' | 'completed' | 'failed'; destroyedKeys: number; attempts: number; reasonCode: string; completedAt?: string; updatedAt: string }
export type RecoveryDrill = { drillId: string; fileId: string; versionId: string; requestedBy: string; outcome: 'verified' | 'failed'; reasonCode: string; verifiedAt: string }
export type LifecycleAlert = { id: string; severity: string; title: string; detail: string; count: number }
export type BackupPosture = { connected: boolean; productionReady: boolean; adapter: string; status: string; detail: string; lastSuccessfulAt?: string }
export type LifecycleSummary = { active: number; trashed: number; retained: number; held: number; purged: number; eligibleForPurge: number; files: LifecycleFile[]; deletionOperations: DeletionOperation[]; recoveryDrills: RecoveryDrill[]; alerts: LifecycleAlert[]; backup: BackupPosture }
export type SharedFile = LogicalFile & { ownerName: string; ownerEmail: string; permission: 'read' | 'download' }
export type SharedFilePage = { files: SharedFile[]; total: number }
export type FileVersion = { fileId: string; versionId: string; sourceVersionId?: string; number: number; plaintextSize: number; mediaType: string; reason: 'initial_upload' | 'verified_restore'; current: boolean; createdAt: string }
export type FileDetails = { file: LogicalFile; versions: FileVersion[]; access: 'owner' | 'read' | 'download' }
export type FileGrant = { grantId: string; fileId: string; ownerId: string; recipientId: string; recipientName: string; recipientEmail: string; permission: 'read' | 'download'; expiresAt?: string; createdAt: string }
export type FileGrantPage = { grants: FileGrant[]; total: number }

type ApiErrorBody = {
  code?: string
  message?: string
  correlationId?: string
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly correlationId: string

  constructor(status: number, body: ApiErrorBody = {}) {
    super(body.message || 'The request could not be completed.')
    this.name = 'ApiError'
    this.status = status
    this.code = body.code || 'REQUEST_FAILED'
    this.correlationId = body.correlationId || ''
  }
}

let csrfToken = ''
let stepUpToken = ''
let stepUpExpiresAt = 0

function clearAuthenticatedCredentialState() {
  csrfToken = ''
  stepUpToken = ''
  stepUpExpiresAt = 0
}

async function requestJSON<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...init.headers,
    },
  })

  if (!response.ok) {
    let body: ApiErrorBody = {}
    try {
      body = await response.json() as ApiErrorBody
    } catch {
      // The safe default message is used when an intermediary returns non-JSON.
    }
    handleAuthenticationExpiry(response.status, body.code ?? '', clearAuthenticatedCredentialState)
    throw new ApiError(response.status, body)
  }

  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export async function restoreSession() {
  const session = await requestJSON<ApiSession>('/api/v1/session')
  csrfToken = session.csrfToken
  return session.user
}

export async function register(input: { name: string; email: string; password: string }) {
	return requestJSON<ApiMessage>('/api/v1/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  })
}

export function verifyEmail(token: string) {
  return requestJSON<ApiMessage>('/api/v1/auth/verify-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  })
}

export function resendVerification(email: string) {
  return requestJSON<ApiMessage>('/api/v1/auth/resend-verification', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  })
}

export async function login(input: { email: string; password: string }) {
  const session = await requestJSON<ApiSession>('/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  })
  csrfToken = session.csrfToken
  return session.user
}

export async function loginPrivileged(input: { email: string; password: string }) {
	const result = await requestJSON<ApiSession | PrivilegedMFAChallenge>('/api/v1/admin/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  })
	if ('mfaRequired' in result) return result
	csrfToken = result.csrfToken
	return result.user
}

export async function completePrivilegedMFA(challengeToken: string, code: string) {
	const result = await requestJSON<PrivilegedMFACompletion>('/api/v1/admin/auth/mfa/complete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken, code }) })
	csrfToken = result.csrfToken
	return result
}

export async function logout() {
  try {
    await requestJSON<void>('/api/v1/auth/logout', {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken },
    })
	} finally {
		clearAuthenticatedCredentialState()
  }
}

export function hasValidAdminStepUp() { return Boolean(stepUpToken) && Date.now() < stepUpExpiresAt - 5000 }
export async function authorizeAdminStepUp(password: string, code: string) {
	const proof=await requestJSON<{stepUpToken:string;expiresAt:string}>('/api/v1/admin/auth/step-up',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrfToken},body:JSON.stringify({password,code})})
	stepUpToken=proof.stepUpToken;stepUpExpiresAt=new Date(proof.expiresAt).getTime();return proof
}
export function activatePrivilegedAccount(token: string, password: string) {
  return requestJSON<ApiMessage>('/api/v1/admin/auth/activate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, password }) })
}
function stepUpHeaders(){return {'X-Step-Up-Token':stepUpToken}}

export function uploadFile(file: File, onProgress: (progress: number) => void, signal?: AbortSignal): Promise<ApiUpload> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest()
    const abortRequest = () => request.abort()
    signal?.addEventListener('abort', abortRequest, { once: true })
    const removeAbortListener = () => signal?.removeEventListener('abort', abortRequest)
    request.open('POST', '/api/v1/uploads')
    request.withCredentials = true
    request.responseType = 'json'
    request.setRequestHeader('Accept', 'application/json')
    request.setRequestHeader('X-CSRF-Token', csrfToken)
    request.setRequestHeader('Idempotency-Key', crypto.randomUUID())
	request.setRequestHeader('X-File-Size', String(file.size))
    request.upload.addEventListener('progress', (event) => {
      if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100))
    })
    request.addEventListener('load', () => {
      removeAbortListener()
      if (request.status >= 200 && request.status < 300) {
        resolve(request.response as ApiUpload)
        return
      }
      reject(new ApiError(request.status, (request.response ?? {}) as ApiErrorBody))
    })
    request.addEventListener('error', () => { removeAbortListener(); reject(new ApiError(0, { code: 'NETWORK_ERROR', message: 'The secure upload service is unavailable.' })) })
    request.addEventListener('abort', () => { removeAbortListener(); reject(new ApiError(0, { code: 'UPLOAD_CANCELLED', message: 'The upload was cancelled.' })) })

    const formData = new FormData()
    formData.append('file', file, file.name)
    if (signal?.aborted) {
      removeAbortListener()
      reject(new ApiError(0, { code: 'UPLOAD_CANCELLED', message: 'The upload was cancelled.' }))
      return
    }
    request.send(formData)
  })
}

export function getUpload(uploadID: string) {
  return requestJSON<ApiUpload>(`/api/v1/uploads/${encodeURIComponent(uploadID)}`)
}

export function listUserFiles() {
  return requestJSON<UserFilePage>('/api/v1/files')
}
export function listTrash() { return requestJSON<{ files: LifecycleFile[]; total: number }>('/api/v1/files/trash') }
export function moveFileToTrash(fileID: string) { return requestJSON<LifecycleFile>(`/api/v1/files/${encodeURIComponent(fileID)}/trash`, { method: 'POST', headers: { 'X-CSRF-Token': csrfToken } }) }
export function restoreFileFromTrash(fileID: string) { return requestJSON<LifecycleFile>(`/api/v1/files/${encodeURIComponent(fileID)}/restore`, { method: 'POST', headers: { 'X-CSRF-Token': csrfToken } }) }
export function permanentlyDeleteFile(fileID: string) { return requestJSON<{ fileId: string; destroyedKeys: number; completedAt: string }>(`/api/v1/files/${encodeURIComponent(fileID)}`, { method: 'DELETE', headers: { 'X-CSRF-Token': csrfToken, 'Idempotency-Key': crypto.randomUUID() } }) }
export function listSharedFiles() { return requestJSON<SharedFilePage>('/api/v1/files/shared') }

export function getFileDetails(fileID: string) { return requestJSON<FileDetails>(`/api/v1/files/${encodeURIComponent(fileID)}`) }
export function restoreFileVersion(fileID: string, versionID: string) {
  return requestJSON<FileVersion>(`/api/v1/files/${encodeURIComponent(fileID)}/versions/${encodeURIComponent(versionID)}/restore`, { method: 'POST', headers: { 'X-CSRF-Token': csrfToken, 'Idempotency-Key': crypto.randomUUID() } })
}
export function fileDownloadURL(fileID: string) { return `/api/v1/files/${encodeURIComponent(fileID)}/content` }
export function listFileGrants(fileID: string) { return requestJSON<FileGrantPage>(`/api/v1/files/${encodeURIComponent(fileID)}/grants`) }
export function createFileGrant(fileID: string, input: { recipientEmail: string; permission: 'read' | 'download'; expiresAt?: string }) {
  return requestJSON<FileGrant>(`/api/v1/files/${encodeURIComponent(fileID)}/grants`, { method: 'POST', headers: { 'X-CSRF-Token': csrfToken }, body: JSON.stringify(input) })
}
export function revokeFileGrant(fileID: string, grantID: string) {
  return requestJSON<ApiMessage>(`/api/v1/files/${encodeURIComponent(fileID)}/grants/${encodeURIComponent(grantID)}`, { method: 'DELETE', headers: { 'X-CSRF-Token': csrfToken } })
}

export function protectedDownloadURL(uploadID: string) {
  return `/api/v1/uploads/${encodeURIComponent(uploadID)}/content`
}

export function listAdminUsers(search = '', limit = 50, offset = 0) {
  const query = new URLSearchParams({ search, limit: String(limit), offset: String(offset) })
  return requestJSON<AdminUserPage>(`/api/v1/admin/users?${query}`)
}

export function invitePrivilegedAccount(input: { name: string; email: string; role: 'admin' | 'auditor' }) {
  return requestJSON<ApiMessage>('/api/v1/admin/users/invitations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken, ...stepUpHeaders() },
    body: JSON.stringify(input),
  })
}

export function listAdminResources(search = '', limit = 50, offset = 0) {
  const query = new URLSearchParams({ search, limit: String(limit), offset: String(offset) })
  return requestJSON<AdminResourcePage>(`/api/v1/admin/resources?${query}`)
}

export function listOrphanCandidates() {
  return requestJSON<OrphanPreview>('/api/v1/admin/resources/orphans')
}

export function reconcileOrphanCandidates(tokens: string[]) {
  return requestJSON<{ requested: number; completed: number; failed: number }>('/api/v1/admin/resources/orphans/reconcile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken, ...stepUpHeaders() },
    body: JSON.stringify({ tokens }),
  })
}

export function getAdminSecurity() {
  return requestJSON<AdminSecuritySummary>('/api/v1/admin/security')
}

export function rewrapProtectedDEKs(limit = 25) {
  return requestJSON<{ requested: number; completed: number; skipped: number; failed: number; remaining: number }>('/api/v1/admin/security/keys/rewrap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken, ...stepUpHeaders() },
    body: JSON.stringify({ limit }),
  })
}

export function getAdminMonitoring() {
  return requestJSON<AdminMonitoringSummary>('/api/v1/admin/monitoring')
}

export function getAdminLifecycle() {
  return requestJSON<AdminLifecycleSummary>('/api/v1/admin/lifecycle')
}
export function setFileRetention(fileID: string, retentionUntil: string) { return requestJSON<LifecycleFile>(`/api/v1/admin/lifecycle/files/${encodeURIComponent(fileID)}/retention`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken, ...stepUpHeaders() }, body: JSON.stringify({ retentionUntil }) }) }
export function setFileLegalHold(fileID: string, enabled: boolean, reason: string) { return requestJSON<LifecycleFile>(`/api/v1/admin/lifecycle/files/${encodeURIComponent(fileID)}/legal-hold`, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken, ...stepUpHeaders() }, body: JSON.stringify({ enabled, reason }) }) }
export function processLifecycleDeletions() { return requestJSON<{ examined: number; completed: number; failed: number }>('/api/v1/admin/lifecycle/process', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken, ...stepUpHeaders() } }) }
export function runRecoveryDrill(fileID: string) { return requestJSON<RecoveryDrill>(`/api/v1/admin/lifecycle/files/${encodeURIComponent(fileID)}/recovery-drill`, { method: 'POST', headers: { 'X-CSRF-Token': csrfToken, ...stepUpHeaders() } }) }

export function listAuditEvents(filters: AuditFilters = {}) {
  const query = new URLSearchParams()
  Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') query.set(key, String(value)) })
  if (!query.has('limit')) query.set('limit', '25')
  if (!query.has('offset')) query.set('offset', '0')
  return requestJSON<AuditPage>(`/api/v1/admin/audit?${query}`)
}

export function auditExportURL(filters: AuditFilters = {}) {
  const query = new URLSearchParams()
  Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '' && key !== 'limit' && key !== 'offset') query.set(key, String(value)) })
  return `/api/v1/admin/audit/export?${query}`
}

export function updateOwnerQuota(ownerId: string, quotaBytes: number) {
  return requestJSON<ApiMessage>(`/api/v1/admin/resources/owners/${encodeURIComponent(ownerId)}/quota`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken, ...stepUpHeaders() },
    body: JSON.stringify({ quotaBytes }),
  })
}

export function resetOwnerQuota(ownerId: string) {
  return requestJSON<ApiMessage>(`/api/v1/admin/resources/owners/${encodeURIComponent(ownerId)}/quota`, {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrfToken, ...stepUpHeaders() },
  })
}

export function updateAdminUserStatus(userId: string, status: 'active' | 'suspended') {
  return requestJSON<ApiMessage>(`/api/v1/admin/users/${encodeURIComponent(userId)}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken, ...stepUpHeaders() },
    body: JSON.stringify({ status }),
  })
}

export function revokeAdminUserSessions(userId: string) {
  return requestJSON<ApiMessage>(`/api/v1/admin/users/${encodeURIComponent(userId)}/sessions/revoke`, {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrfToken, ...stepUpHeaders() },
  })
}
