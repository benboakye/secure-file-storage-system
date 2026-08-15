import { useEffect, useMemo, useState, type FormEvent } from 'react'
import {
  Activity,
  CheckCircle2,
  Clock3,
  Download,
  FileCheck2,
  FileText,
  KeyRound,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  UserRoundCheck,
  Users,
} from 'lucide-react'
import { listAdminUsers, type AdminUserPage } from '../apiClient'

type FileTab = 'Overview' | 'Access' | 'Versions' | 'Activity'

export function FileDetailsView({ onBack }: { onBack: () => void }) {
  const [tab, setTab] = useState<FileTab>('Overview')

  return (
    <div className="product-view details-view">
      <button className="back-button" onClick={onBack}>← Back to Files</button>
      <header className="view-header details-header">
        <div className="details-file-title"><span className="document-icon"><FileText size={21} /></span><div><p className="kicker">Stored and protected</p><h1>security-training.pdf</h1><p>PDF document · 2.4 MB · Current version v1</p></div></div>
        <button className="primary-button"><Download size={17} />Download</button>
      </header>
      <nav className="detail-tabs" aria-label="File details sections">
        {(['Overview', 'Access', 'Versions', 'Activity'] as FileTab[]).map((item) => <button className={tab === item ? 'active' : ''} onClick={() => setTab(item)} key={item}>{item}</button>)}
      </nav>
      {tab === 'Overview' ? <OverviewTab /> : tab === 'Access' ? <AccessTab /> : tab === 'Versions' ? <VersionsTab /> : <ActivityTab />}
    </div>
  )
}

function OverviewTab() {
  return (
    <div className="details-grid">
      <section className="view-card detail-panel"><h2>File information</h2><dl className="detail-list"><div><dt>Owner</dt><dd>Jane Student</dd></div><div><dt>Created</dt><dd>Aug 10, 2026 · 10:18</dd></div><div><dt>Last updated</dt><dd>Aug 10, 2026 · 10:24</dd></div><div><dt>Classification</dt><dd>PDF document</dd></div><div><dt>Content digest</dt><dd><code>7f3a…91c2</code></dd></div></dl></section>
      <section className="view-card detail-panel"><h2>Security summary</h2><div className="security-summary-list"><div><CheckCircle2 /><span><strong>Inspection passed</strong><small>Policy v1.4 · Aug 10, 10:22</small></span></div><div><KeyRound /><span><strong>Encrypted</strong><small>AES-256-GCM envelope encryption</small></span></div><div><ShieldCheck /><span><strong>Authorized</strong><small>Owner access is active</small></span></div></div></section>
      <section className="view-card detail-panel wide"><h2>Authorization summary</h2><p>Download is available because this file is stored and the current user is authorized. Administrators do not automatically receive plaintext access.</p><div className="authorization-strip"><UserRoundCheck size={20} /><div><strong>Owner access</strong><span>Jane Student · Read and download</span></div><span className="status-badge stored"><CheckCircle2 size={13} />Active</span></div></section>
    </div>
  )
}

function AccessTab() {
  return (
    <section className="view-card governance-card"><div className="panel-heading"><div><h2>Active access grants</h2><p>Public links and wildcard grants are not supported.</p></div><button className="primary-button"><Plus size={16} />Add access</button></div>
      <div className="governance-table"><div className="governance-head"><span>User</span><span>Permission</span><span>Created</span><span>Expires</span><span /></div>{[['Jane Student','Owner','Aug 10, 2026','Never'],['Alex Morgan','Read','Aug 10, 2026','Sep 10, 2026']].map((row) => <div className="governance-row" key={row[0]}><strong>{row[0]}</strong><span>{row[1]}</span><span>{row[2]}</span><span>{row[3]}</span><button className="danger-link">Revoke</button></div>)}</div>
      <div className="safe-note"><ShieldCheck size={18} /><span>Revocation blocks new access requests but cannot recall plaintext already downloaded.</span></div>
    </section>
  )
}

function VersionsTab() {
  return (
    <section className="view-card governance-card"><div className="panel-heading"><div><h2>Immutable version history</h2><p>Older versions must be verified and rescanned before becoming current.</p></div></div>
      <div className="version-list"><div className="version-item current"><span className="version-marker"><FileCheck2 /></span><div><strong>Version 1</strong><small>Current · Uploaded by Jane Student</small></div><span>Aug 10, 2026 · 10:18</span><span className="status-badge stored"><CheckCircle2 size={13} />Verified</span></div><div className="version-item"><span className="version-marker"><RefreshCw /></span><div><strong>Recovery candidate</strong><small>Source: backup checkpoint</small></div><span>Aug 9, 2026 · 18:40</span><button className="secondary-button">Restore</button></div></div>
    </section>
  )
}

function ActivityTab() {
  const events = [['Downloaded','Jane Student','Success','Today, 11:06'],['Access granted','Jane Student','Success','Today, 10:44'],['Stored and protected','System','Success','Today, 10:24'],['Static inspection','Inspection service','Passed','Today, 10:22']]
  return <section className="view-card governance-card"><div className="panel-heading"><div><h2>Recent file activity</h2><p>Security-relevant events for this file.</p></div></div><div className="activity-list">{events.map((event) => <div key={event[0]}><span className="event-icon"><Activity size={16} /></span><div><strong>{event[0]}</strong><small>{event[1]}</small></div><span className="status-badge stored"><CheckCircle2 size={13} />{event[2]}</span><time>{event[3]}</time></div>)}</div></section>
}

export function AuditView() {
  return <div className="product-view"><header className="view-header"><div><p className="kicker">Standard-user scope</p><h1>Audit activity</h1><p>Personal audit visibility is not connected yet. The authoritative organization chain is restricted to administrator and auditor accounts.</p></div></header><section className="view-card governance-card"><div className="safe-note"><ShieldCheck size={18} /><span>No demonstration events are shown. A future owner-scoped API must enforce resource authorization before standard users can view their own event history.</span></div></section></div>
}

export function AdministrationView() {
  const [query, setQuery] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState<AdminUserPage | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    setError('')
    listAdminUsers(search)
      .then((result) => { if (!cancelled) setPage(result) })
      .catch((requestError) => { if (!cancelled) setError(requestError instanceof Error ? requestError.message : 'The user directory could not be loaded.') })
    return () => { cancelled = true }
  }, [search])

  const summary = useMemo(() => ({
    verified: page?.users.filter((user) => user.verificationStatus === 'verified').length ?? 0,
    administrators: page?.users.filter((user) => user.role === 'admin').length ?? 0,
  }), [page])

  const submitSearch = (event: FormEvent) => {
    event.preventDefault()
    setSearch(query.trim())
  }

  const formatDate = (value: string) => new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' }).format(new Date(value))

  return <div className="product-view"><header className="view-header"><div><p className="kicker">Administrator only</p><h1>Administration</h1><p>Review real account records without exposing credentials or authentication tokens.</p></div><span className="integrity-pill"><ShieldCheck size={16} />Server-authorized</span></header><div className="admin-grid"><section className="view-card governance-card admin-users"><div className="panel-heading"><div><h2>Organization users</h2><p>{page ? `${page.total} database record${page.total === 1 ? '' : 's'}` : 'Loading the protected directory…'}</p></div><form className="admin-search" onSubmit={submitSearch}><label className="compact-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search users" placeholder="Search name or email" /></label><button className="secondary-button" type="submit">Search</button></form></div>{error ? <div className="admin-directory-message error" role="alert">{error}</div> : <div className="governance-table"><div className="governance-head admin"><span>User</span><span>Role</span><span>Verification</span><span>Created</span></div>{page?.users.map((user) => <div className="governance-row admin" key={user.id}><strong>{user.name}<small>{user.email}</small></strong><span className="role-label">{user.role}</span><span className={user.verificationStatus === 'verified' ? 'status-badge stored' : 'status-badge ready'}>{user.verificationStatus === 'verified' ? <CheckCircle2 size={13} /> : <Clock3 size={13} />}{user.verificationStatus}</span><span>{formatDate(user.createdAt)}</span></div>)}{page && page.users.length === 0 ? <div className="admin-directory-message">No matching user records.</div> : null}{!page ? <div className="admin-directory-message">Loading user records…</div> : null}</div>}</section><aside className="admin-status"><section className="view-card service-status"><h2>Directory summary</h2>{[["Total accounts", String(page?.total ?? 0), "PostgreSQL"],["Verified in view", String(summary.verified), "Confirmed"],["Administrators in view", String(summary.administrators), "Privileged"]].map((item) => <div key={item[0]}><span className="service-icon"><Users size={16} /></span><span><strong>{item[0]}</strong><small>{item[2]}</small></span><em>{item[1]}</em></div>)}</section><div className="safe-note admin-note"><ShieldCheck size={18} /><span>Administrator access is enforced by the API. It does not grant access to password hashes, session tokens, or file plaintext.</span></div></aside></div></div>
}
