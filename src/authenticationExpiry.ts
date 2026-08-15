export type AuthenticationExpiredHandler = () => void

let authenticationExpiredHandler: AuthenticationExpiredHandler | null = null

/**
 * Registers the application-level owner of authenticated session state.
 *
 * API helpers cannot directly update React state. This narrow subscription
 * lets the API boundary report a server-confirmed expired session without
 * coupling the transport layer to routing or UI components.
 */
export function subscribeToAuthenticationExpiry(handler: AuthenticationExpiredHandler) {
  authenticationExpiredHandler = handler
  return () => {
    if (authenticationExpiredHandler === handler) authenticationExpiredHandler = null
  }
}

/**
 * Handles only the server's explicit expired/missing-session response.
 *
 * Other HTTP 401 responses are expected during login, MFA, recovery-code, or
 * administrator step-up attempts and must remain local form errors. The
 * credential-state callback runs before React is notified so no stale CSRF or
 * step-up proof remains available while the route transition is scheduled.
 */
export function handleAuthenticationExpiry(
  status: number,
  code: string,
  clearCredentialState: () => void,
) {
  if (status !== 401 || code !== 'AUTHENTICATION_REQUIRED') return false
  clearCredentialState()
  authenticationExpiredHandler?.()
  return true
}
