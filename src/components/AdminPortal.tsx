import { useEffect, useMemo, useRef, useState, type ComponentType, type FormEvent } from 'react'
import {
  Activity,
  ArchiveRestore,
  ArrowRight,
  CheckCircle2,
  Database,
  FileSearch,
  HardDrive,
  LayoutDashboard,
  LogOut,
  Server,
  ShieldCheck,
  ScrollText,
  UserCheck,
  Users,
} from 'lucide-react'
import { authorizeAdminStepUp, hasValidAdminStepUp, listAdminUsers, type AdminUserPage, type ApiUser } from '../apiClient'
import type { AppPage } from '../appSession'
import { IdentityAccessView } from './IdentityAccessView'
import { AdminResourcesView } from './AdminResourcesView'
import { SecurityComplianceView } from './SecurityComplianceView'
import { SystemMonitoringView } from './SystemMonitoringView'
import { DataLifecycleView } from './DataLifecycleView'
import { AdminAuditView } from './AdminAuditView'

type AdminPortalProps = {
  page: AppPage
  user: ApiUser
  onNavigate: (page: AppPage) => void
  onLogout: () => void
}

type DomainDefinition = {
  eyebrow: string
  title: string
  summary: string
  status: string
  implemented: string[]
  pending: string[]
  Icon: ComponentType<{ size?: number }>
}

const domainDefinitions: Partial<Record<AppPage, DomainDefinition>> = {}

export function AdminPortal({ page, user, onNavigate, onLogout }: AdminPortalProps) {
  const administrator = user.role === 'admin'
  const [stepUpOpen, setStepUpOpen] = useState(false)
  const [stepUpError, setStepUpError] = useState('')
  const [stepUpBusy, setStepUpBusy] = useState(false)
  const stepUpPromise = useRef<{ resolve: () => void; reject: (error: Error) => void } | null>(null)

  // Sensitive actions share this gate so a proof is requested once and reused
  // only for its short server-defined lifetime. It remains in memory and is
  // never written to localStorage or exposed through the URL.
  const requireStepUp = () => {
    if (hasValidAdminStepUp()) return Promise.resolve()
    setStepUpOpen(true)
    setStepUpError('')
    return new Promise<void>((resolve, reject) => {
      stepUpPromise.current = { resolve, reject }
    })
  }

  const submitStepUp = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setStepUpBusy(true)
    setStepUpError('')
    try {
      await authorizeAdminStepUp(String(data.get('password') ?? ''), String(data.get('code') ?? ''))
      setStepUpOpen(false)
      stepUpPromise.current?.resolve()
      stepUpPromise.current = null
    } catch (error) {
      setStepUpError(error instanceof Error ? error.message : 'Re-authentication failed.')
    } finally {
      setStepUpBusy(false)
    }
  }

  const cancelStepUp = () => {
    setStepUpOpen(false)
    stepUpPromise.current?.reject(new Error('Administrator re-authentication was cancelled.'))
    stepUpPromise.current = null
  }
  const navigation = [
    { page: 'admin-dashboard' as const, label: 'Overview', Icon: LayoutDashboard },
    ...(administrator ? [{ page: 'admin' as const, label: 'Identity & access', Icon: Users }] : []),
    { page: 'admin-resources' as const, label: 'Resource metadata', Icon: HardDrive },
    { page: 'admin-security' as const, label: 'Security & compliance', Icon: ShieldCheck },
    { page: 'admin-monitoring' as const, label: 'System monitoring', Icon: Activity },
    { page: 'admin-lifecycle' as const, label: 'Data lifecycle', Icon: ArchiveRestore },
    { page: 'admin-audit' as const, label: 'Audit trail', Icon: ScrollText },
  ]

  return (
    <main className="admin-portal-shell">
      <aside className="admin-portal-sidebar">
        <div className="admin-portal-brand"><span><ShieldCheck size={21} /></span><div><strong>SecureStore</strong><small>Privileged console</small></div></div>
        <nav aria-label="Privileged navigation">
          {navigation.map(({ page: destination, label, Icon }) => (
            <button className={page === destination ? 'active' : ''} key={destination} onClick={() => onNavigate(destination)}><Icon size={18} />{label}</button>
          ))}
        </nav>
        <div className="admin-portal-identity">
          <div className="admin-avatar">{initials(user.name)}</div>
          <div><strong>{user.name}</strong><small>{user.email}</small><span>{user.role}</span></div>
        </div>
        <button className="admin-logout" onClick={onLogout}><LogOut size={17} />Log out</button>
      </aside>
      <section className="admin-portal-main">
        {page === 'admin-dashboard' ? <AdminDashboard user={user} onUsers={() => onNavigate('admin')} /> : null}
		{page === 'admin' && administrator ? <IdentityAccessView actorId={user.id} requireStepUp={requireStepUp} /> : null}
		{page === 'admin-resources' ? <AdminResourcesView canManage={administrator} requireStepUp={requireStepUp} /> : null}
        {page === 'admin-security' ? <SecurityComplianceView canManage={administrator} requireStepUp={requireStepUp} /> : null}
        {page === 'admin-monitoring' ? <SystemMonitoringView /> : null}
		{page === 'admin-lifecycle' ? <DataLifecycleView canManage={administrator} requireStepUp={requireStepUp} /> : null}
        {page === 'admin-audit' ? <AdminAuditView /> : null}
        {domainDefinitions[page] ? <AdminDomainView definition={domainDefinitions[page]!} /> : null}
      </section>
      {stepUpOpen ? <div className="admin-modal-backdrop" role="presentation">
        <section className="admin-modal" role="dialog" aria-modal="true" aria-labelledby="step-up-title">
          <header>
            <span>High-risk administrator action</span>
            <h2 id="step-up-title">Confirm it is you</h2>
            <p>Re-enter your password and a fresh authenticator code. Authorization lasts five minutes and is bound to this session.</p>
          </header>
          <form onSubmit={submitStepUp}>
            <label htmlFor="step-up-password">Password</label>
            <input id="step-up-password" name="password" type="password" autoComplete="current-password" required autoFocus />
            <label htmlFor="step-up-code">Fresh authenticator code</label>
            <input id="step-up-code" name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" required maxLength={6} placeholder="123456" />
            {stepUpError ? <small className="admin-step-up-error" role="alert">{stepUpError}</small> : null}
            <div>
              <button type="button" className="secondary-button" onClick={cancelStepUp} disabled={stepUpBusy}>Cancel</button>
              <button className="primary-button" disabled={stepUpBusy}>{stepUpBusy ? 'Verifying…' : 'Authorize action'}</button>
            </div>
          </form>
        </section>
      </div> : null}
    </main>
  )
}

function AdminDashboard({ user, onUsers }: { user: ApiUser; onUsers: () => void }) {
  const [directory, setDirectory] = useState<AdminUserPage | null>(null)
  const [error, setError] = useState('')
  const administrator = user.role === 'admin'

  useEffect(() => {
    if (!administrator) return
    let cancelled = false
    listAdminUsers('', 50, 0)
      .then((result) => { if (!cancelled) setDirectory(result) })
      .catch((requestError) => { if (!cancelled) setError(requestError instanceof Error ? requestError.message : 'The administrator summary could not be loaded.') })
    return () => { cancelled = true }
  }, [administrator])

  const summary = useMemo(() => ({
    pending: directory?.users.filter((record) => record.verificationStatus === 'pending').length ?? 0,
    administrators: directory?.users.filter((record) => record.role === 'admin').length ?? 0,
    auditors: directory?.users.filter((record) => record.role === 'auditor').length ?? 0,
  }), [directory])

  const value = (number: number) => directory ? number : '—'

  return <div className="admin-dashboard-view">
    <header className="admin-dashboard-header">
      <div><p className="kicker">Privileged operations</p><h1>{administrator ? 'Administration overview' : 'Compliance overview'}</h1><p>Monitor governance boundaries and system readiness without entering standard-user workspaces.</p></div>
      <div className="admin-session-state"><ShieldCheck size={20} /><span><strong>Privileged session</strong><small>{user.email}</small></span></div>
    </header>

    {error ? <div className="admin-dashboard-error" role="alert">{error}</div> : null}

    {administrator ? <section className="admin-stat-grid" aria-label="Identity and access statistics">
      <article><span><Database size={20} /></span><small>Total accounts</small><strong>{directory?.total ?? '—'}</strong><p>PostgreSQL identity records</p></article>
      <article><span><ShieldCheck size={20} /></span><small>Administrators</small><strong>{value(summary.administrators)}</strong><p>Privileged administrative identities</p></article>
      <article><span><FileSearch size={20} /></span><small>Auditors</small><strong>{value(summary.auditors)}</strong><p>Read-only compliance identities</p></article>
      <article><span><UserCheck size={20} /></span><small>Pending verification</small><strong>{value(summary.pending)}</strong><p>Accounts without activated access</p></article>
    </section> : <div className="admin-dashboard-notice"><ShieldCheck size={20} /><span><strong>Auditor scope</strong><p>Identity management remains restricted to administrators. Audit and compliance data will be read-only.</p></span></div>}

    <section className="admin-domain-grid" aria-label="Administrator control domains">
      <DomainCard title="Identity & access governance" status={administrator ? 'Connected' : 'Restricted'} description="Roles, verification, privileged identities, and session governance." Icon={Users} />
      <DomainCard title="Resource & capacity" status="Connected" description="Durable file metadata, quarantine usage, global policy, and owner quota overrides are connected." Icon={HardDrive} />
      <DomainCard title="Security & compliance" status="Partial" description="Authentication, privileged TOTP MFA, protected encryption, and the durable HMAC audit chain are active; managed key custody remains pending." Icon={ShieldCheck} />
      <DomainCard title="System monitoring" status="Connected" description="Runtime health, persistence, processing queues, scanner capability, and quota policy are live." Icon={Server} />
      <DomainCard title="Data lifecycle" status="Partial" description="Retention, legal holds, scheduled cryptographic deletion, and verified recovery are active; deployment backup integration remains pending." Icon={ArchiveRestore} />
    </section>

    {administrator ? <section className="admin-dashboard-panel admin-identity-preview">
      <div className="admin-dashboard-panel-heading"><div><span>Identity governance</span><h2>Recent accounts</h2></div><button onClick={onUsers}>View identity directory <ArrowRight size={16} /></button></div>
      <div className="admin-recent-users">
        {directory?.users.slice(0, 5).map((record) => <div key={record.id}><div className="admin-avatar small">{initials(record.name)}</div><span><strong>{record.name}</strong><small>{record.email}</small></span><em>{record.role}</em><b className={record.verificationStatus === 'verified' ? 'verified' : ''}>{record.verificationStatus === 'verified' ? <CheckCircle2 size={15} /> : null}{record.verificationStatus}</b></div>)}
        {!directory ? <p>Loading account records…</p> : null}
        {directory && directory.users.length === 0 ? <p>No account records found.</p> : null}
      </div>
    </section> : null}
  </div>
}

function DomainCard({ title, status, description, Icon }: { title: string; status: string; description: string; Icon: ComponentType<{ size?: number }> }) {
  return <article className="admin-domain-card"><span className="admin-domain-icon"><Icon size={21} /></span><div><h2>{title}</h2><p>{description}</p></div><strong>{status}</strong></article>
}

function AdminDomainView({ definition }: { definition: DomainDefinition }) {
  const { eyebrow, title, summary, status, implemented, pending, Icon } = definition
  return <div className="admin-dashboard-view admin-domain-view">
    <header className="admin-dashboard-header"><div><p className="kicker">{eyebrow}</p><h1>{title}</h1><p>{summary}</p></div><div className="admin-domain-status"><Icon size={21} /><span><small>Current status</small><strong>{status}</strong></span></div></header>
    <div className="admin-domain-detail-grid">
      <section className="admin-dashboard-panel"><div className="admin-dashboard-panel-heading"><div><span>Available now</span><h2>Implemented controls</h2></div></div><ul className="admin-control-list implemented">{implemented.map((item) => <li key={item}><CheckCircle2 size={18} />{item}</li>)}</ul></section>
      <section className="admin-dashboard-panel"><div className="admin-dashboard-panel-heading"><div><span>Planned integration</span><h2>Required next capabilities</h2></div></div><ul className="admin-control-list">{pending.map((item) => <li key={item}><span />{item}</li>)}</ul></section>
    </div>
    <div className="admin-dashboard-notice"><ShieldCheck size={20} /><span><strong>No simulated production data</strong><p>Unavailable controls are labelled clearly until a real backend measurement or policy service exists.</p></span></div>
  </div>
}

function initials(name: string) {
  return name.split(/\s+/).map((part) => part[0]).join('').slice(0, 2).toUpperCase()
}
