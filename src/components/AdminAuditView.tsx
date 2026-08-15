import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { AlertTriangle, CheckCircle2, Database, Download, Filter, Link2, Search, ShieldAlert, ShieldCheck, Users } from 'lucide-react'
import { auditExportURL, listAuditEvents, type AuditFilters, type AuditPage } from '../apiClient'

const pageSize = 25
const emptyDraft = { search: '', actorId: '', action: '', resourceType: '', outcome: '', ipAddress: '', from: '', to: '' }

export function AdminAuditView() {
  const [draft, setDraft] = useState(emptyDraft)
  const [filters, setFilters] = useState<AuditFilters>({ limit: pageSize, offset: 0 })
  const [page, setPage] = useState<AuditPage | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    setError('')
    setLoading(true)
    listAuditEvents(filters)
      .then((result) => { if (!cancelled) setPage(result) })
      .catch((requestError) => { if (!cancelled) setError(requestError instanceof Error ? requestError.message : 'Audit events could not be loaded.') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [filters])

  const submit = (event: FormEvent) => {
    event.preventDefault()
    setFilters({
      search: draft.search.trim(), actorId: draft.actorId.trim(), action: draft.action,
      resourceType: draft.resourceType, outcome: draft.outcome, ipAddress: draft.ipAddress.trim(),
      from: toISO(draft.from), to: toISO(draft.to), limit: pageSize, offset: 0,
    })
  }
  const clear = () => { setDraft(emptyDraft); setFilters({ limit: pageSize, offset: 0 }) }
  const verification = page?.verification
  const assuranceValid = verification?.valid && (!verification.anchor.connected || verification.anchor.valid)
  const summary = page?.summary
  const offset = filters.offset ?? 0
  const exportURL = useMemo(() => auditExportURL(filters), [filters])

  return <div className="admin-dashboard-view admin-audit-view">
    <header className="admin-dashboard-header">
      <div><p className="kicker">Audit &amp; accountability</p><h1>Audit activity</h1><p>Investigate security-relevant activity through a safe projection of the durable, ordered audit chain.</p></div>
      <div className={`admin-domain-status ${assuranceValid === false ? 'integrity-failed' : ''}`}><ShieldCheck size={21} /><span><small>Chain and checkpoint</small><strong>{verification ? (assuranceValid ? 'Verified and anchored' : 'Integrity failure') : 'Verifying evidence'}</strong></span></div>
    </header>

    {error ? <div className="admin-dashboard-error" role="alert">{error}</div> : null}
    {page?.alerts.length ? <section className="audit-alert-stack" aria-label="Active security alerts">{page.alerts.map((alert) => <article key={alert.id} className={`audit-alert ${alert.severity}`}><ShieldAlert size={20} /><span><strong>{alert.title}</strong><p>{alert.detail}</p></span><b>{alert.count}</b></article>)}</section> : null}

    <section className="admin-resource-stat-grid" aria-label="Audit statistics">
      <AuditStat Icon={Database} label="Matching events" value={summary ? String(summary.matching) : '—'} detail={`${summary?.total ?? 0} events in the durable chain`} />
      <AuditStat Icon={Link2} label="Anchored through" value={verification?.anchor.valid ? `#${verification.anchor.anchoredThrough}` : '—'} detail={verification?.anchor.productionReady ? 'Independent checkpoint evidence' : 'Local development evidence'} />
      <AuditStat Icon={Users} label="Distinct actors" value={summary ? String(summary.distinctActors) : '—'} detail="Within the current filtered view" />
      <AuditStat Icon={summary?.highRisk ? AlertTriangle : CheckCircle2} label="High-risk events" value={summary ? String(summary.highRisk) : '—'} detail={summary?.highRisk ? 'Denied, failed, or privileged changes' : 'No elevated activity in this view'} />
    </section>

    <section className="admin-dashboard-panel audit-filter-panel">
      <div className="admin-dashboard-panel-heading"><div><span>Investigation controls</span><h2>Filter events</h2></div><a className="secondary-button audit-export" href={exportURL} download><Download size={16} />Export filtered CSV</a></div>
      <form className="audit-filter-form" onSubmit={submit}>
        <label className="audit-search-field"><span>Search</span><div><Search size={16} /><input value={draft.search} onChange={(event) => setDraft({ ...draft, search: event.target.value })} placeholder="Resource, reason, or correlation ID" /></div></label>
        <Field label="Actor ID" value={draft.actorId} onChange={(value) => setDraft({ ...draft, actorId: value })} placeholder="usr_…" />
        <Select label="Event" value={draft.action} onChange={(value) => setDraft({ ...draft, action: value })} options={['AUTHENTICATION','SESSION_LOGOUT','FILE_METADATA_READ','FILE_DOWNLOAD','UPLOAD_QUARANTINED','FILE_GRANT_CREATED','FILE_GRANT_REVOKED','FILE_VERSION_RESTORE_COMPLETED','ACCOUNT_STATUS_UPDATED','USER_SESSIONS_REVOKED','OWNER_QUOTA_UPDATED','AUDIT_READ','AUDIT_EXPORT','MONITORING_READ']} />
        <Select label="Outcome" value={draft.outcome} onChange={(value) => setDraft({ ...draft, outcome: value })} options={['success','denied','failed']} />
        <Select label="Resource" value={draft.resourceType} onChange={(value) => setDraft({ ...draft, resourceType: value })} options={['session','file','upload','user','audit_chain','system']} />
        <Field label="IP address" value={draft.ipAddress} onChange={(value) => setDraft({ ...draft, ipAddress: value })} placeholder="Filtered as a secure fingerprint" />
        <Field label="From" value={draft.from} onChange={(value) => setDraft({ ...draft, from: value })} type="datetime-local" />
        <Field label="To" value={draft.to} onChange={(value) => setDraft({ ...draft, to: value })} type="datetime-local" />
        <div className="audit-filter-actions"><button className="secondary-button" type="button" onClick={clear}>Clear</button><button className="primary-button" type="submit"><Filter size={16} />Apply filters</button></div>
      </form>
      <p className="audit-privacy-note"><ShieldCheck size={15} />IP addresses are converted to keyed fingerprints by the API. Raw addresses are never stored in audit records or returned to this interface.</p>
    </section>

    <section className="admin-dashboard-panel admin-audit-panel">
      <div className="admin-dashboard-panel-heading"><div><span>Safe event projection</span><h2>Security events</h2></div><strong className="audit-result-count">{loading ? 'Loading…' : `${page?.total ?? 0} results`}</strong></div>
      <div className="admin-audit-table">
        <div className="admin-audit-head"><span>Sequence</span><span>Time</span><span>Actor</span><span>Action</span><span>Resource</span><span>Outcome</span><span>Correlation</span></div>
        {page?.events.map((event) => <div className="admin-audit-row" key={event.eventId}>
          <strong>#{event.sequence}</strong><time>{formatDate(event.occurredAt)}</time><code title={event.actorId}>{event.actorId || event.actorType}<small>{event.networkSource || 'No network fingerprint'}</small></code><span><b>{humanize(event.action)}</b><small>{humanize(event.reasonCode)}</small></span><code title={event.resourceId}>{event.resourceType}{event.resourceId ? ` · ${shortID(event.resourceId)}` : ''}</code><em className={event.outcome === 'success' ? 'success' : 'denied'}>{event.outcome}</em><code title={event.correlationId}>{shortID(event.correlationId)}</code>
        </div>)}
        {!loading && page && page.events.length === 0 ? <p>No audit events match these filters.</p> : null}
      </div>
      <div className="audit-pagination"><p>Showing {page?.events.length ? offset + 1 : 0}–{Math.min(offset + (page?.events.length ?? 0), page?.total ?? 0)} of {page?.total ?? 0}</p><div><button className="secondary-button" disabled={offset === 0 || loading} onClick={() => setFilters({ ...filters, offset: Math.max(0, offset - pageSize) })}>Previous</button><button className="secondary-button" disabled={loading || offset + pageSize >= (page?.total ?? 0)} onClick={() => setFilters({ ...filters, offset: offset + pageSize })}>Next</button></div></div>
    </section>

    <div className="admin-dashboard-notice"><ShieldCheck size={20} /><span><strong>{verification?.anchor.productionReady ? 'Independently anchored checkpoint' : 'Signed anchor protocol connected'}</strong><p>{verification?.anchor.detail ?? 'Loading checkpoint-anchor posture.'} {verification?.anchor.valid ? `Latest evidence matches sequence #${verification.anchor.anchoredThrough}.` : 'The latest anchor does not currently verify.'}</p></span></div>
  </div>
}

function AuditStat({ Icon, label, value, detail }: { Icon: typeof Database; label: string; value: string; detail: string }) { return <article><span><Icon size={20} /></span><small>{label}</small><strong>{value}</strong><p>{detail}</p></article> }
function Field({ label, value, onChange, placeholder, type = 'text' }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string; type?: string }) { return <label><span>{label}</span><input type={type} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} /></label> }
function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: string[] }) { return <label><span>{label}</span><select value={value} onChange={(event) => onChange(event.target.value)}><option value="">All</option>{options.map((option) => <option value={option} key={option}>{humanize(option)}</option>)}</select></label> }
function toISO(value: string) { return value ? new Date(value).toISOString() : '' }
function formatDate(value: string) { return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' }).format(new Date(value)) }
function shortID(value: string) { return value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-5)}` : value }
function humanize(value: string) { return value.toLowerCase().replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase()) }
