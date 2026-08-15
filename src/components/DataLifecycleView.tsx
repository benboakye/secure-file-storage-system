import { useEffect, useState, type FormEvent } from 'react'
import { AlertTriangle, Archive, ArchiveRestore, CheckCircle2, Database, HardDrive, History, LockKeyhole, Play, RotateCcw, Scale, ShieldCheck, Trash2 } from 'lucide-react'
import { getAdminLifecycle, processLifecycleDeletions, runRecoveryDrill, setFileLegalHold, setFileRetention, type AdminLifecycleSummary } from '../apiClient'

export function DataLifecycleView({ canManage, requireStepUp }: { canManage: boolean; requireStepUp:()=>Promise<void> }) {
  const [summary, setSummary] = useState<AdminLifecycleSummary | null>(null)
  const [error, setError] = useState('')
  const [selectedFileID, setSelectedFileID] = useState('')
  const [retentionUntil, setRetentionUntil] = useState('')
  const [holdReason, setHoldReason] = useState('')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const load = () => getAdminLifecycle().then(setSummary)

  useEffect(() => { let cancelled = false; getAdminLifecycle().then((result) => { if (!cancelled) setSummary(result) }).catch((requestError) => { if (!cancelled) setError(requestError instanceof Error ? requestError.message : 'Lifecycle evidence could not be loaded.') }); return () => { cancelled = true } }, [])

  const lifecycle = summary?.lifecycle
  const protectedFiles = summary?.protectedFiles
  const selected = protectedFiles?.files.find((file) => file.fileId === selectedFileID)
  const updateRetention = async (event: FormEvent) => { event.preventDefault(); if (!selectedFileID || !retentionUntil) return; setSaving(true); setError(''); try { await requireStepUp(); await setFileRetention(selectedFileID, new Date(retentionUntil).toISOString()); await load() } catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'Retention could not be updated.') } finally { setSaving(false) } }
  const updateHold = async (enabled: boolean) => { if (!selectedFileID) return; setSaving(true); setError(''); try { await requireStepUp(); await setFileLegalHold(selectedFileID, enabled, enabled ? holdReason : ''); await load(); if (!enabled) setHoldReason('') } catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'The legal hold could not be updated.') } finally { setSaving(false) } }
  const processDue = async () => { setSaving(true); setError(''); setMessage(''); try { await requireStepUp(); const result = await processLifecycleDeletions(); setMessage(`Deletion run complete: ${result.completed} completed, ${result.failed} failed.`); await load() } catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'Deletion processing could not run.') } finally { setSaving(false) } }
  const verifyRecovery = async () => { if (!selectedFileID) return; setSaving(true); setError(''); setMessage(''); try { await requireStepUp(); await runRecoveryDrill(selectedFileID); setMessage('Recovery drill verified the encrypted version. No file content was returned to the administrator.'); await load() } catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'Recovery verification failed.') } finally { setSaving(false) } }

  return <div className="admin-dashboard-view admin-lifecycle-view">
    <header className="admin-dashboard-header">
      <div><p className="kicker">Data protection &amp; lifecycle management</p><h1>Lifecycle operations</h1><p>Govern recovery, retention, legal holds, and cryptographic deletion through metadata-only administrative controls.</p></div>
      <div className="admin-domain-status"><Database size={21} /><span><small>Lifecycle evidence</small><strong>{lifecycle?.metadataDurable ? 'PostgreSQL durable' : 'Loading records'}</strong></span></div>
    </header>
    {error ? <div className="admin-dashboard-error" role="alert">{error}</div> : null}
    {message ? <div className="admin-dashboard-notice lifecycle-success" role="status"><CheckCircle2 size={20} /><span><strong>Operation complete</strong><p>{message}</p></span></div> : null}
    {protectedFiles?.alerts.map((alert) => <div className="admin-dashboard-error" role="alert" key={alert.id}><AlertTriangle size={18} /> {alert.title}: {alert.detail} ({alert.count})</div>)}

    <section className="admin-resource-stat-grid" aria-label="Lifecycle statistics">
      <LifecycleStat Icon={CheckCircle2} label="Active files" value={protectedFiles ? String(protectedFiles.active) : '—'} detail="Accessible protected files" />
      <LifecycleStat Icon={Trash2} label="In Trash" value={protectedFiles ? String(protectedFiles.trashed) : '—'} detail={`${protectedFiles?.eligibleForPurge ?? 0} eligible for deletion`} />
      <LifecycleStat Icon={ArchiveRestore} label="Under retention" value={protectedFiles ? String(protectedFiles.retained) : '—'} detail="Deletion prohibited by policy" />
      <LifecycleStat Icon={Scale} label="Legal holds" value={protectedFiles ? String(protectedFiles.held) : '—'} detail={`${protectedFiles?.purged ?? 0} deletion tombstones`} />
    </section>

    <section className="lifecycle-layout">
      <div className="lifecycle-primary">
        {canManage ? <section className="admin-dashboard-panel">
          <div className="admin-dashboard-panel-heading"><div><span>Global controls</span><h2>Retention and legal hold</h2></div><strong className="posture-state connected">Administrator only</strong></div>
          <form className="lifecycle-policy-form" onSubmit={updateRetention}>
            <label><span>Protected file</span><select value={selectedFileID} onChange={(event) => setSelectedFileID(event.target.value)}><option value="">Select a metadata record</option>{protectedFiles?.files.filter((file) => !file.purgedAt).map((file) => <option value={file.fileId} key={file.fileId}>{file.name} · {shortID(file.ownerId)}</option>)}</select></label>
            <label><span>Retain until</span><input type="datetime-local" value={retentionUntil} onChange={(event) => setRetentionUntil(event.target.value)} /></label>
            <button className="secondary-button" disabled={saving || !selectedFileID || !retentionUntil}>Extend retention</button>
            <label className="hold-reason"><span>Legal-hold reason</span><input value={holdReason} onChange={(event) => setHoldReason(event.target.value)} placeholder="Case or preservation reason" /></label>
            <button className="secondary-button" type="button" disabled={saving || !selectedFileID || holdReason.trim().length < 4} onClick={() => void updateHold(true)}>Apply hold</button>
            <button className="secondary-button" type="button" disabled={saving || !selected?.legalHold} onClick={() => void updateHold(false)}>Release hold</button>
          </form>
          <div className="resource-inline-note"><ShieldCheck size={16} /><span><strong>Forward-only retention</strong><p>An active retention deadline cannot be shortened or removed. Legal-hold changes require a separate administrator action and are written to the audit chain.</p></span></div>
          <div className="lifecycle-action-row"><button className="secondary-button" type="button" disabled={saving} onClick={() => void processDue()}><Play size={16} />Run eligible deletions</button><button className="secondary-button" type="button" disabled={saving || !selectedFileID} onClick={() => void verifyRecovery()}><RotateCcw size={16} />Verify recovery</button></div>
        </section> : <div className="admin-dashboard-notice"><ShieldCheck size={20} /><span><strong>Auditor read-only scope</strong><p>Auditors may review lifecycle metadata and controls, but only administrators can change retention or legal holds.</p></span></div>}

        <section className="admin-dashboard-panel">
          <div className="admin-dashboard-panel-heading"><div><span>Protected catalog</span><h2>File lifecycle records</h2></div></div>
          <div className="lifecycle-file-list">{protectedFiles?.files.map((file) => <div key={file.fileId}><span className="lifecycle-file-icon"><Archive size={17} /></span><span><strong>{file.name}</strong><small>{shortID(file.ownerId)} · Updated {formatDate(file.updatedAt)}</small></span><b>{file.purgedAt ? 'Purged' : file.legalHold ? 'Legal hold' : file.deletedAt ? 'Trash' : file.retentionUntil ? 'Retained' : 'Active'}</b><time>{file.purgeAfter ? `Purge after ${formatDate(file.purgeAfter)}` : file.retentionUntil ? `Retain until ${formatDate(file.retentionUntil)}` : 'No active deadline'}</time></div>)}{protectedFiles && protectedFiles.files.length === 0 ? <p>No protected file records exist.</p> : null}</div>
        </section>

        <section className="admin-dashboard-panel">
          <div className="admin-dashboard-panel-heading"><div><span>Ingestion evidence</span><h2>Processing lifecycle</h2></div><strong className="posture-state connected">Server controlled</strong></div>
          <dl className="capacity-signal-list"><Signal label="Tracked ingestion records" value={lifecycle ? String(lifecycle.trackedRecords) : '—'} /><Signal label="Pending processing" value={lifecycle ? String(lifecycle.pendingProcessing) : '—'} /><Signal label="Stuck processing" value={lifecycle ? String(lifecycle.stuckProcessing) : '—'} /><Signal label="Quarantine usage" value={lifecycle ? formatBytes(lifecycle.quarantineBytes) : '—'} /></dl>
        </section>
        <section className="admin-dashboard-panel"><div className="admin-dashboard-panel-heading"><div><span>Operational evidence</span><h2>Deletion operations</h2></div></div><div className="lifecycle-evidence-list">{protectedFiles?.deletionOperations.map((operation) => <div key={operation.operationId}><span className={`evidence-dot ${operation.status}`} /><span><strong>{operation.status === 'completed' ? 'Cryptographic deletion completed' : 'Deletion attempt failed closed'}</strong><small>{shortID(operation.fileId)} · {operation.attempts} attempt{operation.attempts === 1 ? '' : 's'}</small></span><b>{operation.destroyedKeys} keys</b><time>{formatDate(operation.updatedAt)}</time></div>)}{protectedFiles && protectedFiles.deletionOperations.length === 0 ? <p>No permanent-deletion operations have run.</p> : null}</div></section>
      </div>

      <aside className="lifecycle-side">
        <section className="admin-dashboard-panel"><div className="admin-dashboard-panel-heading"><div><span>Enforcement</span><h2>Lifecycle controls</h2></div></div><div className="security-gap-list"><Gap Icon={LockKeyhole} label="Encrypted protected storage" connected={summary?.capabilities.protectedStorage ?? false} /><Gap Icon={History} label="Immutable version history" connected={summary?.capabilities.versionHistory ?? false} /><Gap Icon={ArchiveRestore} label="Retention policy engine" connected={summary?.capabilities.retentionPolicy ?? false} /><Gap Icon={Scale} label="Legal holds" connected={summary?.capabilities.legalHolds ?? false} /><Gap Icon={Trash2} label="Cryptographic deletion" connected={summary?.capabilities.cryptographicDeletion ?? false} /><Gap Icon={CheckCircle2} label="Verified recovery" connected={summary?.capabilities.verifiedRecovery ?? false} /></div></section>
        <section className="admin-dashboard-panel"><div className="admin-dashboard-panel-heading"><div><span>Recovery assurance</span><h2>Verification evidence</h2></div></div><div className="lifecycle-evidence-list compact">{protectedFiles?.recoveryDrills.map((drill) => <div key={drill.drillId}><span className={`evidence-dot ${drill.outcome}`} /><span><strong>{drill.outcome === 'verified' ? 'Encrypted version verified' : 'Verification failed'}</strong><small>{shortID(drill.fileId)}</small></span><time>{formatDate(drill.verifiedAt)}</time></div>)}{protectedFiles && protectedFiles.recoveryDrills.length === 0 ? <p>No controlled recovery drill has been recorded.</p> : null}</div></section>
        <section className="admin-dashboard-panel backup-posture"><HardDrive size={21} /><div><span>Backup provider</span><h2>{protectedFiles?.backup.connected ? 'Connected' : 'Not configured'}</h2><p>{protectedFiles?.backup.detail ?? 'Loading backup posture.'}</p></div></section>
      </aside>
    </section>
    <div className="admin-dashboard-notice"><ShieldCheck size={20} /><span><strong>Deletion is fail-closed</strong><p>Trash immediately blocks owner and recipient access. Permanent deletion becomes available only after the grace period and when no retention policy or legal hold applies; wrapped encryption keys are destroyed before ciphertext cleanup.</p></span></div>
  </div>
}

function LifecycleStat({ Icon, label, value, detail }: { Icon: typeof Archive; label: string; value: string; detail: string }) { return <article><span><Icon size={20} /></span><small>{label}</small><strong>{value}</strong><p>{detail}</p></article> }
function Gap({ Icon, label, connected }: { Icon: typeof Archive; label: string; connected: boolean }) { return <div><Icon size={17} /><strong>{label}</strong><span className={`posture-state ${connected ? 'connected' : 'pending'}`}>{connected ? 'Connected' : 'Not connected'}</span></div> }
function Signal({ label, value }: { label: string; value: string }) { return <div><dt>{label}</dt><dd>{value}</dd></div> }
function formatBytes(bytes: number) { if (bytes < 1024) return `${bytes} B`; const units = ['KB', 'MB', 'GB', 'TB']; let value = bytes / 1024; let unit = 0; while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1 } return `${value >= 10 ? value.toFixed(1) : value.toFixed(2)} ${units[unit]}` }
function formatDate(value: string) { return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(value)) }
function shortID(value: string) { return value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-5)}` : value }
