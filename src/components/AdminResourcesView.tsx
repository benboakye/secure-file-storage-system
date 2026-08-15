import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { AlertTriangle, Archive, Clock3, Database, FileSearch, Gauge, HardDrive, Search, ShieldCheck, Trash2, Users } from 'lucide-react'
import { listAdminResources, listAdminUsers, listOrphanCandidates, reconcileOrphanCandidates, resetOwnerQuota, updateOwnerQuota, type AdminResourcePage, type AdminUserPage, type OrphanPreview, type UploadStatus } from '../apiClient'

const statusOrder: UploadStatus[] = ['quarantined', 'inspecting', 'accepted', 'encrypting', 'stored', 'rejected', 'failed']

export function AdminResourcesView({ canManage, requireStepUp }: { canManage: boolean; requireStepUp:()=>Promise<void> }) {
  const [query, setQuery] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState<AdminResourcePage | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [directory, setDirectory] = useState<AdminUserPage | null>(null)
  const [revision, setRevision] = useState(0)
  const [quotaEditor, setQuotaEditor] = useState<{ ownerId: string; name: string; megabytes: string } | null>(null)
  const [orphans, setOrphans] = useState<OrphanPreview | null>(null)
  const [selectedOrphans, setSelectedOrphans] = useState<string[]>([])
  const [reconciling, setReconciling] = useState(false)

  useEffect(() => {
    let cancelled = false
    setError('')
    listAdminResources(search)
      .then((result) => { if (!cancelled) setPage(result) })
      .catch((requestError) => {
        if (!cancelled) setError(requestError instanceof Error ? requestError.message : 'Resource metadata could not be loaded.')
      })
    return () => { cancelled = true }
  }, [search, revision])

  useEffect(() => {
    let cancelled = false
    listOrphanCandidates()
      .then((result) => { if (!cancelled) { setOrphans(result); setSelectedOrphans((selected) => selected.filter((token) => result.candidates.some((candidate) => candidate.token === token && candidate.eligible))) } })
      .catch((requestError) => { if (!cancelled) setError(requestError instanceof Error ? requestError.message : 'Orphan preview could not be loaded.') })
    return () => { cancelled = true }
  }, [revision])

  useEffect(() => {
    if (!canManage) return
    let cancelled = false
    listAdminUsers('', 100, 0)
      .then((result) => { if (!cancelled) setDirectory(result) })
      .catch((requestError) => { if (!cancelled) setError(requestError instanceof Error ? requestError.message : 'The account directory could not be loaded.') })
    return () => { cancelled = true }
  }, [canManage])

  const decisions = useMemo(() => statusOrder.reduce((total, status) => total + (page?.summary.statusCounts[status] ?? 0), 0), [page])
  const submitSearch = (event: FormEvent) => {
    event.preventDefault()
    setSearch(query.trim())
  }

  const saveQuota = async (event: FormEvent) => {
    event.preventDefault()
    if (!quotaEditor) return
    const quotaMB = Number(quotaEditor.megabytes)
    if (!Number.isInteger(quotaMB) || quotaMB < 1 || quotaMB > 10 * 1024 * 1024) {
      setError('Enter a whole number between 1 MB and 10,485,760 MB.')
      return
    }
    setError('')
    setNotice('')
    try {
	  await requireStepUp()
      const result = await updateOwnerQuota(quotaEditor.ownerId, quotaMB * 1024 * 1024)
      setNotice(result.message)
      setQuotaEditor(null)
      setRevision((value) => value + 1)
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'The quota could not be updated.')
    }
  }

  const restoreDefaultQuota = async (ownerId: string) => {
    setError('')
    setNotice('')
    try {
      await requireStepUp()
      const result = await resetOwnerQuota(ownerId)
      setNotice(result.message)
      setRevision((value) => value + 1)
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'The organization default quota could not be restored.')
    }
  }

  const reconcileSelected = async () => {
    if (!selectedOrphans.length) return
    setReconciling(true); setError(''); setNotice('')
    try {
      await requireStepUp()
      const result = await reconcileOrphanCandidates(selectedOrphans)
      setNotice(`Reconciliation completed: ${result.completed} deleted and ${result.failed} retained after revalidation.`)
      setSelectedOrphans([])
      setRevision((value) => value + 1)
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Selected orphan objects could not be reconciled.')
    } finally { setReconciling(false) }
  }

  return (
    <div className="admin-dashboard-view admin-resources-view">
      <header className="admin-dashboard-header">
        <div><p className="kicker">Resource &amp; capacity management</p><h1>Resource metadata</h1><p>Monitor durable ingestion, encrypted-object usage, and storage capacity without opening, downloading, or decrypting user files.</p></div>
        <div className="admin-domain-status"><Database size={21} /><span><small>Metadata source</small><strong>{page?.summary.metadataDurable ? 'PostgreSQL connected' : 'Runtime only'}</strong></span></div>
      </header>

      {error ? <div className="admin-dashboard-error" role="alert">{error}</div> : null}
      {notice ? <div className="admin-directory-message success" role="status">{notice}</div> : null}

      <section className="admin-resource-stat-grid" aria-label="Resource statistics">
        <ResourceStat Icon={FileSearch} label="Tracked uploads" value={page ? String(page.summary.trackedUploads) : '—'} detail={page?.summary.metadataDurable ? 'Durable lifecycle records' : 'Current API process'} />
        <ResourceStat Icon={HardDrive} label="Protected ciphertext" value={page ? formatBytes(page.summary.protectedCapacity.trackedCiphertextBytes) : '—'} detail={page ? `${page.summary.protectedCapacity.trackedObjects} encrypted object${page.summary.protectedCapacity.trackedObjects === 1 ? '' : 's'}` : 'Reconciliation pending'} />
        <ResourceStat Icon={Archive} label="Quarantine usage" value={page ? formatBytes(page.summary.quarantineBytes) : '—'} detail="Measured from disk" />
        <ResourceStat Icon={AlertTriangle} label="Protected discrepancies" value={page ? String(page.summary.protectedCapacity.orphanedObjects + page.summary.protectedCapacity.missingObjects) : '—'} detail={page ? `${page.summary.protectedCapacity.orphanedObjects} orphaned · ${page.summary.protectedCapacity.missingObjects} missing` : 'Reconciliation pending'} />
      </section>

      <section className="admin-resource-layout">
        <div className="admin-dashboard-panel admin-resource-inventory">
          <div className="admin-dashboard-panel-heading resource-heading">
            <div><span>Safe metadata only</span><h2>Runtime inventory</h2></div>
            <form className="admin-search" onSubmit={submitSearch}><label className="compact-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search resource metadata" placeholder="Search file, owner ID, or status" /></label><button className="secondary-button" type="submit">Search</button></form>
          </div>
          <div className="resource-table">
            <div className="resource-table-head"><span>File</span><span>Owner</span><span>Status</span><span>Size</span><span>Created</span></div>
            {page?.resources.map((resource) => <div className="resource-table-row" key={resource.id}>
              <strong>{resource.name}<small>{resource.detectedMediaType}</small></strong>
              <code title={resource.ownerId}>{shortID(resource.ownerId)}</code>
              <span className={`status-badge ${resource.status}`}>{resource.status}</span>
              <span>{formatBytes(resource.size)}</span>
              <time>{formatDate(resource.createdAt)}</time>
            </div>)}
            {!page ? <div className="admin-directory-message">Loading resource metadata…</div> : null}
            {page && page.resources.length === 0 ? <div className="admin-directory-message">No runtime resource records match this view.</div> : null}
          </div>
        </div>

        <aside className="admin-resource-side">
          <section className="admin-dashboard-panel">
            <div className="admin-dashboard-panel-heading"><div><span>Lifecycle evidence</span><h2>Processing states</h2></div></div>
            <div className="resource-status-list">{statusOrder.map((status) => <div key={status}><span className={`resource-status-dot ${status}`} /><strong>{status}</strong><em>{page?.summary.statusCounts[status] ?? 0}</em></div>)}</div>
            <div className="resource-inline-note"><ShieldCheck size={18} /><span><strong>{page?.summary.protectedStorageConnected ? 'Protected storage connected' : 'Protected storage not connected'}</strong><p>{decisions} durable lifecycle record{decisions === 1 ? '' : 's'} confirmed. {page?.summary.protectedStorageConnected ? 'Ciphertext accounting and database-to-disk reconciliation are active.' : 'Encryption and protected-storage capacity remain unavailable.'}</p></span></div>
          </section>
          <section className="admin-dashboard-panel capacity-signals-panel">
            <div className="admin-dashboard-panel-heading"><div><span>Capacity signals</span><h2>Current workload</h2></div></div>
            <dl className="capacity-signal-list">
              <div><dt><HardDrive size={16} />Default user quota</dt><dd>{formatBytes(page?.summary.defaultQuotaBytes ?? 0)}</dd></div>
			  <div><dt><Database size={16} />Enforced storage pool</dt><dd>{formatBytes(page?.summary.storageCapacityBytes ?? 0)}</dd></div>
			  <div><dt><ShieldCheck size={16} />Safety reserve</dt><dd>{formatBytes(page?.summary.storageReserveBytes ?? 0)}</dd></div>
			  <div><dt><Clock3 size={16} />Active reservations</dt><dd>{page ? `${page.summary.activeReservations} · ${formatBytes(page.summary.reservedCapacityBytes)}` : '—'}</dd></div>
              <div><dt><Database size={16} />Protected ciphertext</dt><dd>{formatBytes(page?.summary.protectedCapacity.trackedCiphertextBytes ?? 0)}</dd></div>
              <div><dt><Gauge size={16} />Hosting volume used</dt><dd>{page ? `${page.summary.protectedCapacity.volumeUsedPercent.toFixed(1)}%` : '—'}</dd></div>
              <div><dt><HardDrive size={16} />Volume available</dt><dd>{formatBytes(page?.summary.protectedCapacity.volumeAvailableBytes ?? 0)}</dd></div>
              <div><dt><Gauge size={16} />Pending processing</dt><dd>{page?.summary.pendingProcessing ?? 0}</dd></div>
              <div><dt><AlertTriangle size={16} />Quota alerts</dt><dd>{page?.summary.quotaAlerts ?? 0}</dd></div>
              <div><dt><Clock3 size={16} />Added in 24 hours</dt><dd>{formatBytes(page?.summary.bytesLast24Hours ?? 0)}</dd></div>
              <div><dt><Archive size={16} />Added in 7 days</dt><dd>{formatBytes(page?.summary.bytesLast7Days ?? 0)}</dd></div>
            </dl>
            {(page?.summary.protectedCapacity.alerts ?? []).map((alert) => <div className="resource-inline-note capacity-alert" key={alert.id}><AlertTriangle size={16} /><span><strong>{alert.title}</strong><p>{alert.detail} ({alert.count})</p></span></div>)}
            <div className="capacity-owner-heading"><Users size={16} /><strong>Top owners by tracked bytes</strong></div>
            <div className="capacity-owner-list">
              {(page?.summary.ownerUsage ?? []).map((owner) => <div key={owner.ownerId}><code title={owner.ownerId}>{shortID(owner.ownerId)}</code><span>{owner.uploads} upload{owner.uploads === 1 ? '' : 's'} · {quotaPercent(owner.bytes, owner.quotaBytes)}% of {formatBytes(owner.quotaBytes)}</span><strong>{formatBytes(owner.bytes)}</strong></div>)}
              {page && (page.summary.ownerUsage ?? []).length === 0 ? <p>No owner usage records yet.</p> : null}
            </div>
          </section>
          <section className="admin-dashboard-panel orphan-reconciliation-panel">
            <div className="admin-dashboard-panel-heading"><div><span>Administrator-reviewed cleanup</span><h2>Orphan reconciliation</h2></div><strong className={`posture-state ${orphans?.candidates.some((candidate) => candidate.eligible) ? 'partial' : 'connected'}`}>{orphans?.candidates.length ?? 0} found</strong></div>
            <p className="orphan-reconciliation-copy">Only opaque, untracked regular objects are shown. Objects newer than {Math.round((orphans?.minimumAgeSeconds ?? 3600) / 60)} minutes remain protected by the safety window.</p>
            <div className="orphan-candidate-list">
              {(orphans?.candidates ?? []).map((candidate) => <label key={candidate.token} className={!candidate.eligible ? 'ineligible' : ''}>
                <input type="checkbox" disabled={!canManage || !candidate.eligible || reconciling} checked={selectedOrphans.includes(candidate.token)} onChange={(event) => setSelectedOrphans((selected) => event.target.checked ? [...selected, candidate.token] : selected.filter((token) => token !== candidate.token))} />
                <span><strong>{candidate.zone === 'protected' ? 'Protected object' : 'Quarantine object'}</strong><small>{shortID(candidate.token)} · {formatBytes(candidate.size)} · {candidate.eligible ? 'Eligible after revalidation' : 'Safety window active'}</small></span>
              </label>)}
              {orphans && orphans.candidates.length === 0 ? <p>No orphan objects require review.</p> : null}
              {!orphans ? <p>Loading reconciliation preview…</p> : null}
            </div>
            {canManage ? <button className="primary-button" type="button" disabled={!selectedOrphans.length || reconciling} onClick={reconcileSelected}><Trash2 size={16} />{reconciling ? 'Revalidating objects…' : `Delete selected (${selectedOrphans.length})`}</button> : <p className="admin-read-only-note">Auditors can review discrepancies but cannot delete storage objects.</p>}
          </section>
          {canManage ? <section className="admin-dashboard-panel account-quota-panel">
            <div className="admin-dashboard-panel-heading"><div><span>Administrator policy</span><h2>Account quotas</h2></div></div>
            <div className="account-quota-list">
              {directory?.users.filter((user) => user.role === 'user').map((user) => {
                const override = (page?.summary.quotaOverrides ?? []).find((item) => item.ownerId === user.id)
                const quota = override?.quotaBytes ?? page?.summary.defaultQuotaBytes ?? 0
                return <div key={user.id}><span><strong>{user.name}</strong><small>{user.email}</small></span><em>{formatBytes(quota)}{override ? ' override' : ' default'}</em><div className="quota-actions"><button onClick={() => setQuotaEditor({ ownerId: user.id, name: user.name, megabytes: String(Math.round(quota / (1024 * 1024))) })}>Set quota</button>{override ? <button onClick={() => void restoreDefaultQuota(user.id)}>Use default</button> : null}</div></div>
              })}
              {directory && directory.users.every((user) => user.role !== 'user') ? <p>No standard-user accounts are available for quota assignment.</p> : null}
              {!directory ? <p>Loading standard-user accounts…</p> : null}
            </div>
          </section> : null}
        </aside>
      </section>

      {quotaEditor ? <div className="admin-modal-backdrop" role="presentation" onMouseDown={() => setQuotaEditor(null)}>
        <section className="admin-modal" role="dialog" aria-modal="true" aria-labelledby="quota-dialog-title" onMouseDown={(event) => event.stopPropagation()}>
          <header><span>Storage policy</span><h2 id="quota-dialog-title">Set account quota</h2><p>Change the enforced ingestion limit for <strong>{quotaEditor.name}</strong>.</p></header>
          <form onSubmit={saveQuota}>
            <label htmlFor="quota-megabytes">Quota in megabytes</label>
            <input id="quota-megabytes" type="number" min="1" max={10 * 1024 * 1024} step="1" required autoFocus value={quotaEditor.megabytes} onChange={(event) => setQuotaEditor({ ...quotaEditor, megabytes: event.target.value })} />
            <small>Allowed range: 1 MB to 10 TB. Lowering a quota below current usage blocks new uploads.</small>
            <div><button className="secondary-button" type="button" onClick={() => setQuotaEditor(null)}>Cancel</button><button className="primary-button" type="submit">Save quota</button></div>
          </form>
        </section>
      </div> : null}
    </div>
  )
}

function ResourceStat({ Icon, label, value, detail }: { Icon: typeof FileSearch; label: string; value: string; detail: string }) {
  return <article><span><Icon size={20} /></span><small>{label}</small><strong>{value}</strong><p>{detail}</p></article>
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1 }
  return `${value >= 10 ? value.toFixed(1) : value.toFixed(2)} ${units[unit]}`
}

function shortID(value: string) {
  return value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-5)}` : value
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(new Date(value))
}

function quotaPercent(bytes: number, quotaBytes: number) {
  if (quotaBytes <= 0) return 0
  return Math.min(100, Math.round((bytes / quotaBytes) * 100))
}
