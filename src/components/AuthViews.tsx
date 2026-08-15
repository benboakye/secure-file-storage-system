import { useState, type FormEvent, type ReactNode } from 'react'
import { AlertCircle, CheckCircle2, Eye, EyeOff, MailCheck, RefreshCw, ShieldCheck } from 'lucide-react'
import { activatePrivilegedAccount, resendVerification, verifyEmail, type PrivilegedMFAChallenge } from '../apiClient'

export type AuthSubmission = {
  mode: 'signin' | 'register' | 'admin-signin'
  name: string
  email: string
  password: string
	mfaChallengeToken?: string
	mfaCode?: string
	recoveryCodesAcknowledged?: boolean
}

export type AuthResult = PrivilegedMFAChallenge | { recoveryCodes: string[] } | void

type AuthViewProps = {
  mode: 'signin' | 'register' | 'admin-signin'
  onSwitch: () => void
  onAuthenticated: (submission: AuthSubmission) => Promise<AuthResult>
}

const PASSWORD_PATTERN = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$/
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export function AuthView({ mode, onSwitch, onAuthenticated }: AuthViewProps) {
  const [showPassword, setShowPassword] = useState(false)
  // Registration fields are independently controllable so users can compare
  // both values without exposing the other field unintentionally.
  const [showConfirmation, setShowConfirmation] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
	const [mfaChallenge, setMFAChallenge] = useState<PrivilegedMFAChallenge | null>(null)
	const [recoveryCodes, setRecoveryCodes] = useState<string[]>([])
  const registration = mode === 'register'
  const privileged = mode === 'admin-signin'

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setError('')

    const formData = new FormData(event.currentTarget)
		if (recoveryCodes.length > 0) { setLoading(true); await onAuthenticated({ mode, name: '', email: '', password: '', recoveryCodesAcknowledged: true }); return }
		const name = String(formData.get('name') ?? '').trim()
    const email = String(formData.get('email') ?? '').trim().toLowerCase()
    const password = String(formData.get('password') ?? '')
    const confirmation = String(formData.get('confirmation') ?? '')

    if (!mfaChallenge && (!EMAIL_PATTERN.test(email) || !password)) {
      setError('Enter your email address and password.')
      return
    }

    if (registration && !name) {
      setError('Enter your full name.')
      return
    }

    if (registration && !PASSWORD_PATTERN.test(password)) {
      setError('Use at least 12 characters with upper and lowercase letters, a number, and a symbol.')
      return
    }

    if (registration && password !== confirmation) {
      setError('The password confirmation does not match.')
      return
    }

    setLoading(true)
    try {
		const result = await onAuthenticated({ mode, name, email, password, mfaChallengeToken: mfaChallenge?.challengeToken, mfaCode: String(formData.get('mfaCode') ?? '').trim() })
		setLoading(false)
		if (result && 'mfaRequired' in result) { setMFAChallenge(result); return }
		if (result && 'recoveryCodes' in result) { setRecoveryCodes(result.recoveryCodes); return }
    } catch (requestError) {
      setLoading(false)
      setError(requestError instanceof Error ? requestError.message : 'The request could not be completed.')
    }
  }

  return (
    <main className={privileged ? 'auth-shell auth-shell-privileged' : 'auth-shell'}>
      <section className="auth-brand">
        <div className="auth-brand-lockup"><span><ShieldCheck /></span>SecureStore</div>
        <div className="auth-brand-copy">
          <p className="kicker">{privileged ? 'Privileged access boundary' : 'Protected by design'}</p>
          <h1>{privileged ? 'Administer security without entering user workspaces.' : 'Trust every file only after verification.'}</h1>
          <p>{privileged ? 'Administrator and auditor identities use a dedicated sign-in context. Privileged sessions cannot perform standard-user file operations.' : 'Uploaded files pass through quarantine, static inspection, policy evaluation, encryption, and protected storage before access is allowed.'}</p>
        </div>
        <div className="auth-trust-list">
          <span><CheckCircle2 size={14} />{privileged ? 'Separate credentials' : 'Quarantined first'}</span>
          <span><CheckCircle2 size={14} />{privileged ? 'No impersonation' : 'Encrypted at rest'}</span>
          <span><CheckCircle2 size={14} />{privileged ? 'Server-enforced roles' : 'Auditable access'}</span>
        </div>
      </section>

      <section className="auth-form-panel">
        <form className="auth-form" onSubmit={submit} noValidate>
		  <div className="auth-heading">
            <span>{privileged ? 'Administrator and auditor access' : mode === 'signin' ? 'Welcome back' : 'Standard user registration'}</span>
			<h2>{recoveryCodes.length ? 'Save recovery codes' : mfaChallenge?.mode === 'enroll' ? 'Protect your privileged account' : mfaChallenge ? 'Enter verification code' : privileged ? 'Privileged sign in' : mode === 'signin' ? 'Sign in to SecureStore' : 'Create your account'}</h2>
			<p>{recoveryCodes.length ? 'Store these one-time codes securely. They will not be shown again.' : mfaChallenge?.mode === 'enroll' ? 'Add the secret to an authenticator app, then enter its six-digit code.' : mfaChallenge ? 'Enter the current code from your authenticator app or use one recovery code.' : privileged ? 'Use your dedicated privileged credentials. Standard-user accounts are rejected here.' : mode === 'signin' ? 'Use your standard-user credentials to continue.' : 'Self-registered accounts receive the standard User role.'}</p>
          </div>

		  {recoveryCodes.length ? <div className="mfa-recovery-codes">{recoveryCodes.map((code) => <code key={code}>{code}</code>)}</div> : mfaChallenge ? <>
			{mfaChallenge.mode === 'enroll' ? <div className="mfa-enrollment-secret"><span>Manual setup key</span><code>{mfaChallenge.manualEntrySecret}</code></div> : null}
			<label>Verification code<input required name="mfaCode" inputMode="numeric" autoComplete="one-time-code" maxLength={12} placeholder="123456" autoFocus /></label>
		  </> : <>
		  {registration ? <label>Full name<input required name="name" maxLength={120} placeholder="Jane Student" autoComplete="name" /></label> : null}
		  <label>Email address<input required name="email" type="email" maxLength={254} placeholder="jane@example.edu" autoComplete="email" /></label>
          <label>
            Password
            <div className="password-field">
              <input required name="password" minLength={registration ? 12 : 1} maxLength={128} type={showPassword ? 'text' : 'password'} placeholder="Enter your password" autoComplete={registration ? 'new-password' : 'current-password'} />
              <button type="button" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button>
            </div>
          </label>

          {registration ? <>
            <label>
              Confirm password
              <div className="password-field">
                <input required name="confirmation" type={showConfirmation ? 'text' : 'password'} maxLength={128} placeholder="Confirm your password" autoComplete="new-password" />
                <button type="button" onClick={() => setShowConfirmation((value) => !value)} aria-label={showConfirmation ? 'Hide password confirmation' : 'Show password confirmation'}>{showConfirmation ? <EyeOff size={17} /> : <Eye size={17} />}</button>
              </div>
            </label>
            <div className="password-requirements"><strong>Password requirements</strong><span>At least 12 characters with upper and lowercase letters, a number, and a symbol.</span></div>
		  </> : null}
		  </>}

          {error ? <div className="auth-error" role="alert"><AlertCircle size={16} /><span>{error}</span></div> : null}
		  <button className="primary-button auth-submit" disabled={loading} aria-busy={loading}>{loading ? 'Please wait…' : recoveryCodes.length ? 'I have stored these codes' : mfaChallenge ? 'Verify and continue' : privileged ? 'Continue securely' : mode === 'signin' ? 'Sign in' : 'Create account'}</button>
          <p className="auth-switch">{privileged ? 'Need your personal file account?' : mode === 'signin' ? "Don't have an account?" : 'Already registered?'} <button type="button" onClick={onSwitch}>{privileged ? 'Standard sign in' : mode === 'signin' ? 'Create account' : 'Sign in'}</button></p>
          {!registration && !privileged ? <p className="auth-switch auth-privileged-link">Administrator or auditor? <a href="#admin-signin">Privileged sign in</a></p> : null}
          <div className="auth-notice"><ShieldCheck size={16} /><span>{privileged ? 'This sign-in creates a privileged session that cannot upload, download, or impersonate standard users.' : 'Sessions use an opaque HttpOnly cookie. Passwords are sent only to the local API for secure hashing and are never stored in browser storage.'}</span></div>
        </form>
      </section>
    </main>
  )
}

function AuthShell({ children }: { children: ReactNode }) {
  return (
    <main className="auth-shell">
      <section className="auth-brand">
        <div className="auth-brand-lockup"><span><ShieldCheck /></span>SecureStore</div>
        <div className="auth-brand-copy">
          <p className="kicker">Identity assurance</p>
          <h1>Confirm ownership before access.</h1>
          <p>Email verification establishes control of the registered address. It never creates a session; you still sign in separately.</p>
        </div>
        <div className="auth-trust-list">
          <span><CheckCircle2 size={14} />Single-use link</span>
          <span><CheckCircle2 size={14} />Short expiry</span>
          <span><CheckCircle2 size={14} />Manual sign-in</span>
        </div>
      </section>
      <section className="auth-form-panel">{children}</section>
    </main>
  )
}

export function CheckEmailView({ email, onSignIn }: { email: string; onSignIn: () => void }) {
  const [resending, setResending] = useState(false)
  const [status, setStatus] = useState('')

  const resend = async () => {
    if (!email || resending) return
    setResending(true)
    setStatus('')
    try {
      const response = await resendVerification(email)
      setStatus(response.message)
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'The request could not be completed.')
    } finally {
      setResending(false)
    }
  }

  return <AuthShell><div className="auth-form auth-state">
    <div className="auth-state-icon"><MailCheck size={27} /></div>
    <div className="auth-heading">
      <span>Account created — access pending</span>
      <h2>Check your email</h2>
      <p>We sent a verification link{email ? <> to <strong>{email}</strong></> : ''}. Open it to confirm the address. The link expires in 30 minutes.</p>
    </div>
    <div className="auth-steps" aria-label="Account activation steps">
      <div className="complete"><i>1</i><span><strong>Account created</strong><small>No session was started</small></span></div>
      <div className="current"><i>2</i><span><strong>Verify email</strong><small>Use the single-use link</small></span></div>
      <div><i>3</i><span><strong>Sign in manually</strong><small>Enter your credentials again</small></span></div>
    </div>
    {status ? <div className="auth-status" role="status"><CheckCircle2 size={16} /><span>{status}</span></div> : null}
    <button className="primary-button auth-submit" type="button" onClick={onSignIn}>Return to sign in</button>
    <button className="auth-secondary-action" type="button" onClick={() => void resend()} disabled={!email || resending}><RefreshCw size={15} />{resending ? 'Sending…' : 'Resend verification email'}</button>
    <div className="auth-notice"><ShieldCheck size={16} /><span>Local prototype delivery: verification messages are written privately to <code>.data/mailbox</code>. A production email provider can replace this adapter at deployment.</span></div>
  </div></AuthShell>
}

export function VerifyEmailView({ token, onSignIn }: { token: string; onSignIn: () => void }) {
  const [state, setState] = useState<'ready' | 'loading' | 'success' | 'error'>('ready')
  const [message, setMessage] = useState(token ? '' : 'This verification link is incomplete.')

  const verify = async () => {
    if (!token || state === 'loading') return
    setState('loading')
    setMessage('')
    try {
      const response = await verifyEmail(token)
      setState('success')
      setMessage(response.message)
    } catch (error) {
      setState('error')
      setMessage(error instanceof Error ? error.message : 'This verification link is invalid or has expired.')
    }
  }

  const successful = state === 'success'
  return <AuthShell><div className="auth-form auth-state">
    <div className={`auth-state-icon ${successful ? 'success' : ''}`}>{successful ? <CheckCircle2 size={28} /> : <MailCheck size={27} />}</div>
    <div className="auth-heading">
      <span>{successful ? 'Identity confirmed' : 'Secure email verification'}</span>
      <h2>{successful ? 'Email verified' : 'Verify your email'}</h2>
      <p>{successful ? 'Your address is confirmed. For your security, no session was created.' : 'Confirm this one-time link. We require a separate sign-in after verification.'}</p>
    </div>
    {message ? <div className={state === 'error' || !token ? 'auth-error' : 'auth-status'} role="status">{state === 'error' || !token ? <AlertCircle size={16} /> : <CheckCircle2 size={16} />}<span>{message}</span></div> : null}
    {successful ? <button className="primary-button auth-submit" type="button" onClick={onSignIn}>Continue to sign in</button> : <button className="primary-button auth-submit" type="button" onClick={() => void verify()} disabled={!token || state === 'loading'}>{state === 'loading' ? 'Verifying…' : 'Verify email'}</button>}
    {!successful ? <button className="auth-secondary-action" type="button" onClick={onSignIn}>Return to sign in</button> : null}
    <div className="auth-notice"><ShieldCheck size={16} /><span>Opening this page does not activate the account automatically. Verification occurs only when you press the button above.</span></div>
  </div></AuthShell>
}

export function ActivatePrivilegedView({ token, onSignIn }: { token: string; onSignIn: () => void }) {
  const [state, setState] = useState<'ready' | 'loading' | 'success' | 'error'>('ready')
  const [message, setMessage] = useState(token ? '' : 'This privileged invitation link is incomplete.')
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmation, setShowConfirmation] = useState(false)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const password = String(data.get('password') ?? '')
    const confirmation = String(data.get('confirmation') ?? '')
    if (!PASSWORD_PATTERN.test(password)) { setState('error'); setMessage('Use at least 12 characters with upper and lowercase letters, a number, and a symbol.'); return }
    if (password !== confirmation) { setState('error'); setMessage('The password confirmation does not match.'); return }
    setState('loading'); setMessage('')
    try {
      const response = await activatePrivilegedAccount(token, password)
      setState('success'); setMessage(response.message)
    } catch (error) {
      setState('error'); setMessage(error instanceof Error ? error.message : 'The invitation is invalid or expired.')
    }
  }

  return <AuthShell><form className="auth-form auth-state" onSubmit={submit} noValidate>
    <div className={`auth-state-icon ${state === 'success' ? 'success' : ''}`}>{state === 'success' ? <CheckCircle2 size={28} /> : <ShieldCheck size={27} />}</div>
    <div className="auth-heading"><span>Controlled privileged provisioning</span><h2>{state === 'success' ? 'Account activated' : 'Create privileged credentials'}</h2><p>{state === 'success' ? 'No session was created. Continue to the separate privileged sign-in and enroll your authenticator.' : 'Choose a password known only to you. This invitation is single-use and does not reuse a standard-user account.'}</p></div>
    {state !== 'success' ? <>
      <label>Password<div className="password-field"><input name="password" type={showPassword ? 'text' : 'password'} autoComplete="new-password" minLength={12} maxLength={128} required /><button type="button" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></label>
      <label>Confirm password<div className="password-field"><input name="confirmation" type={showConfirmation ? 'text' : 'password'} autoComplete="new-password" minLength={12} maxLength={128} required /><button type="button" onClick={() => setShowConfirmation((value) => !value)} aria-label={showConfirmation ? 'Hide password confirmation' : 'Show password confirmation'}>{showConfirmation ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></label>
      <div className="password-requirements"><strong>Password requirements</strong><span>At least 12 characters with upper and lowercase letters, a number, and a symbol.</span></div>
    </> : null}
    {message ? <div className={state === 'error' || !token ? 'auth-error' : 'auth-status'} role="status"><span>{message}</span></div> : null}
    {state === 'success' ? <button className="primary-button auth-submit" type="button" onClick={onSignIn}>Privileged sign in</button> : <button className="primary-button auth-submit" disabled={!token || state === 'loading'}>{state === 'loading' ? 'Activating…' : 'Activate account'}</button>}
    <div className="auth-notice"><ShieldCheck size={16} /><span>Activation verifies the invited address but never signs you in automatically. TOTP enrollment is required at first privileged sign-in.</span></div>
  </form></AuthShell>
}
