import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, CheckCircle2, Clock3, Database, KeyRound, Link2, LockKeyhole, ScanSearch, ShieldCheck, Users } from 'lucide-react'
import { getAdminSecurity, rewrapProtectedDEKs, type AdminSecuritySummary } from '../apiClient'

export function SecurityComplianceView({ canManage, requireStepUp }: { canManage: boolean; requireStepUp: () => Promise<void> }) {
  const [summary, setSummary] = useState<AdminSecuritySummary | null>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [rewrapping, setRewrapping] = useState(false)

  const load = () => {
    setError('')
    return getAdminSecurity().then(setSummary).catch((requestError) => setError(requestError instanceof Error ? requestError.message : 'Security posture could not be loaded.'))
  }

  useEffect(() => {
    let cancelled = false
    getAdminSecurity()
      .then((result) => { if (!cancelled) setSummary(result) })
      .catch((requestError) => { if (!cancelled) setError(requestError instanceof Error ? requestError.message : 'Security posture could not be loaded.') })
    return () => { cancelled = true }
  }, [])

  const runRewrap = async () => {
    setRewrapping(true); setError(''); setMessage('')
    try {
      await requireStepUp()
      const result = await rewrapProtectedDEKs(25)
      setMessage(`Key-wrapper batch completed: ${result.completed} updated, ${result.skipped} skipped, ${result.failed} failed, ${result.remaining} remaining.`)
      await load()
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'The key-wrapper batch could not run.')
    } finally { setRewrapping(false) }
  }

  const uploadDecisions = useMemo(() => Object.values(summary?.ingestion.statusCounts ?? {}).reduce((total, count) => total + (count ?? 0), 0), [summary])
  const auth = summary?.authentication
  const rotation = summary?.keyRotation

  return <div className="admin-dashboard-view admin-security-view">
    <header className="admin-dashboard-header">
      <div><p className="kicker">Security &amp; compliance</p><h1>Security posture</h1><p>Review server-confirmed controls and gaps without exposing credentials, tokens, plaintext, or cryptographic key material.</p></div>
      <div className="admin-domain-status"><ShieldCheck size={21} /><span><small>Evidence source</small><strong>{summary ? 'Live server posture' : 'Loading controls'}</strong></span></div>
    </header>

    {error ? <div className="admin-dashboard-error" role="alert">{error}</div> : null}
    {message ? <div className="admin-dashboard-notice" role="status"><CheckCircle2 size={20} /><span><strong>Rotation evidence recorded</strong><p>{message}</p></span></div> : null}

    <section className="admin-resource-stat-grid" aria-label="Security statistics">
      <SecurityStat Icon={Users} label="Organization accounts" value={summary ? String(summary.accounts.total) : '—'} detail="PostgreSQL identity records" />
      <SecurityStat Icon={CheckCircle2} label="Verified identities" value={summary ? String(summary.accounts.verified) : '—'} detail={summary ? `${summary.accounts.unverified} awaiting verification` : 'Loading verification state'} />
      <SecurityStat Icon={LockKeyhole} label="Restricted accounts" value={summary ? String(summary.accounts.suspended + summary.accounts.locked) : '—'} detail={summary ? `${summary.accounts.suspended} suspended · ${summary.accounts.locked} locked` : 'Loading access state'} />
      <SecurityStat Icon={ScanSearch} label="Upload decisions" value={summary ? String(uploadDecisions) : '—'} detail="Durable lifecycle evidence" />
    </section>

    <section className="security-posture-grid">
      <div className="admin-dashboard-panel">
        <div className="admin-dashboard-panel-heading"><div><span>Authentication controls</span><h2>Active policy</h2></div><strong className="posture-state connected">Enforced</strong></div>
        <div className="security-control-list">
          <Control label="Password protection" detail={auth ? `${auth.passwordHashAlgorithm} cost ${auth.passwordHashCost}; SHA-256 password material` : 'Loading'} enabled={Boolean(auth)} />
          <Control label="Email verification" detail={auth ? `${minutes(auth.verificationTtlSeconds)}-minute, single-use verification window` : 'Loading'} enabled={auth?.emailVerificationRequired ?? false} />
          <Control label="Opaque sessions" detail={auth ? `${hours(auth.sessionTtlSeconds)}-hour server-side session lifetime` : 'Loading'} enabled={auth?.opaqueServerSessions ?? false} />
          <Control label="CSRF and origin checks" detail="State-changing requests require the session CSRF token" enabled={auth?.csrfProtection ?? false} />
          <Control label="Privileged session boundary" detail="Admin sessions cannot perform standard-user file operations" enabled={auth?.privilegedBoundary ?? false} />
          <Control label="High-risk action re-authentication" detail={auth ? `Password and fresh TOTP proof; ${minutes(auth.stepUpTtlSeconds)}-minute authorization window` : 'Loading'} enabled={auth?.adminStepUpEnforced ?? false} />
        </div>
      </div>

      <aside className="security-posture-side">
        <section className="admin-dashboard-panel">
          <div className="admin-dashboard-panel-heading"><div><span>Envelope key custody</span><h2>DEK wrapper rotation</h2></div><strong className={`posture-state ${summary?.keyService.productionReady && !rotation?.pendingVersions ? 'connected' : 'partial'}`}>{summary?.keyService.productionReady ? (rotation?.pendingVersions ? 'Rotation needed' : 'Managed') : 'Development custody'}</strong></div>
          <div className="security-service-detail"><KeyRound size={21} /><span><strong>{rotation ? `${rotation.currentKekId} · ${rotation.currentKekVersion}` : 'Loading key posture'}</strong><p>{rotation ? `${rotation.currentVersions} of ${rotation.protectedVersions} protected versions use the current DEK wrapper; ${rotation.pendingVersions} remain.` : 'Reading aggregate wrapper metadata.'}</p><small>{summary?.keyService.detail ?? 'Reading server-confirmed key custody evidence.'}</small></span></div>
          {canManage ? <button className="primary-button" type="button" disabled={rewrapping || !rotation?.pendingVersions} onClick={runRewrap}>{rewrapping ? 'Rotating wrapper keys…' : 'Rotate next 25 wrappers'}</button> : <p className="admin-read-only-note">Auditors can review this posture but cannot rotate keys.</p>}
        </section>
        <section className="admin-dashboard-panel">
          <div className="admin-dashboard-panel-heading"><div><span>Inspection service</span><h2>Upload protection</h2></div><strong className={`posture-state ${summary?.ingestion.scanner.productionReady ? 'connected' : 'partial'}`}>{scannerStatusLabel(summary?.ingestion.scanner)}</strong></div>
          <div className="security-service-detail"><ScanSearch size={21} /><span><strong>{summary?.ingestion.scanner.adapter ?? 'Loading scanner'}</strong><p>{summary?.ingestion.scanner.detail ?? 'Reading adapter posture from the API.'}</p><small>{summary?.ingestion.scanner.engineVersion ? `Engine ${summary.ingestion.scanner.engineVersion} · Signature database ${summary.ingestion.scanner.signatureDatabase}` : `Policy ${summary?.ingestion.scanner.policyVersion || 'not reported'} · Fail-closed ${summary?.ingestion.scanner.failClosed ? 'enabled' : 'not confirmed'}`}</small></span></div>
        </section>
        <section className="admin-dashboard-panel">
          <div className="admin-dashboard-panel-heading"><div><span>Required integrations</span><h2>Open control gaps</h2></div></div>
          <div className="security-gap-list">
            <Gap Icon={KeyRound} label="Multi-factor authentication" pending={!auth?.mfaEnforced} />
            <Gap Icon={Database} label="Tamper-evident audit chain" pending={!summary?.auditChainConnected} />
            <Gap Icon={Link2} label="Independent immutable audit anchor" pending={!summary?.auditAnchor.productionReady || !summary?.auditAnchor.valid} />
            <Gap Icon={LockKeyhole} label="Managed hardware-backed key custody" pending={!summary?.keyService.productionReady} />
			<Gap Icon={AlertTriangle} label={`Automatic lockout · ${auth?.loginFailureThreshold ?? 5} failures / ${Math.round((auth?.loginFailureWindowSeconds ?? 900) / 60)} min`} pending={!auth?.accountLockoutEnabled} />
            <Gap Icon={KeyRound} label="High-risk administrator step-up" pending={!auth?.adminStepUpEnforced} />
          </div>
        </section>
      </aside>
    </section>

    <div className="admin-dashboard-notice"><ShieldCheck size={20} /><span><strong>Evidence, not simulated assurance</strong><p>Privileged TOTP MFA is enforced. The deterministic scanner, local file-backed KEK, local audit anchor, and local MFA encryption-key file remain development adapters; production still requires malware protection and independently managed secret, key, and audit-receipt custody.</p></span></div>
  </div>
}

function scannerStatusLabel(scanner: AdminSecuritySummary['ingestion']['scanner'] | undefined) {
  if (!scanner) return 'Loading'
  if (scanner.productionReady) return 'Production ready'
  if (scanner.connected && scanner.adapter === 'clamd-instream') return 'Signature attention'
  return scanner.connected ? 'Development adapter' : 'Unavailable'
}

function SecurityStat({ Icon, label, value, detail }: { Icon: typeof Users; label: string; value: string; detail: string }) {
  return <article><span><Icon size={20} /></span><small>{label}</small><strong>{value}</strong><p>{detail}</p></article>
}

function Control({ label, detail, enabled }: { label: string; detail: string; enabled: boolean }) {
  return <div><span className={enabled ? 'control-icon enabled' : 'control-icon'}>{enabled ? <CheckCircle2 size={17} /> : <Clock3 size={17} />}</span><span><strong>{label}</strong><small>{detail}</small></span><em>{enabled ? 'Active' : 'Pending'}</em></div>
}

function Gap({ Icon, label, pending }: { Icon: typeof KeyRound; label: string; pending: boolean }) {
  return <div><Icon size={17} /><strong>{label}</strong><span className={`posture-state ${pending ? 'pending' : 'connected'}`}>{pending ? 'Not connected' : 'Connected'}</span></div>
}

function minutes(seconds: number) { return Math.round(seconds / 60) }
function hours(seconds: number) { return Math.round(seconds / 3600) }
