import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { CheckCircle2, Download, FileCheck2, FileText, KeyRound, RefreshCw, ShieldCheck } from 'lucide-react'
import { createFileGrant, fileDownloadURL, getFileDetails, listFileGrants, restoreFileVersion, revokeFileGrant, type FileDetails, type FileGrant } from '../apiClient'

type FileTab = 'Overview' | 'Access' | 'Versions' | 'Activity'

/**
 * Displays only owner-authorized catalog data. Unconnected sharing and
 * owner-scoped audit features are stated explicitly instead of being mocked.
 */
export function FileDetailsView({ fileID, onBack }: { fileID: string | null; onBack: () => void }) {
  const [tab, setTab] = useState<FileTab>('Overview')
  const [details, setDetails] = useState<FileDetails | null>(null)
  const [error, setError] = useState('')
  const [restoring, setRestoring] = useState('')

  const load = useCallback(() => {
    if (!fileID) { setError('Select a file from the Files page.'); return }
    setError('')
    getFileDetails(fileID).then(setDetails).catch((requestError) => setError(requestError instanceof Error ? requestError.message : 'The file details could not be loaded.'))
  }, [fileID])

  useEffect(load, [load])
  const restore = async (versionID: string) => {
    if (!fileID || restoring) return
    setRestoring(versionID)
    try { await restoreFileVersion(fileID, versionID); load() }
    catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'The version could not be restored.') }
    finally { setRestoring('') }
  }
  const current = details?.versions.find((version) => version.current)

  return <div className="product-view details-view">
    <button className="back-button" onClick={onBack}>← Back to Files</button>
    <header className="view-header details-header">
      <div className="details-file-title"><span className="document-icon"><FileText size={21} /></span><div><p className="kicker">Stored and protected</p><h1>{details?.file.name ?? 'File details'}</h1><p>{current ? `${current.mediaType} · ${formatBytes(current.plaintextSize)} · Current version v${current.number}` : 'Loading authoritative metadata…'}</p></div></div>
      {fileID && details?.access !== 'read' ? <a className="primary-button" href={fileDownloadURL(fileID)}><Download size={17} />Download</a> : null}
    </header>
    <nav className="detail-tabs" aria-label="File details sections">{(['Overview', 'Access', 'Versions', 'Activity'] as FileTab[]).map((item) => <button className={tab === item ? 'active' : ''} onClick={() => setTab(item)} key={item}>{item}</button>)}</nav>
    {error ? <div className="safe-note" role="alert"><ShieldCheck size={18} /><span>{error}</span></div> : null}
    {tab === 'Overview' ? <Overview details={details} /> : tab === 'Versions' ? <Versions details={details} restoring={restoring} onRestore={restore} /> : tab === 'Access' ? details?.access === 'owner' ? <Access fileID={fileID} /> : <Unavailable title="Your access" text={details?.access === 'download' ? 'The owner granted this account metadata and download access.' : 'The owner granted this account metadata access. Download and grant management remain unavailable.'} /> : <Unavailable title="File activity" text="The organization audit chain exists, but a standard-user, file-scoped audit endpoint is not connected yet." />}
  </div>
}

function Overview({ details }: { details: FileDetails | null }) {
  const current = details?.versions.find((version) => version.current)
  return <div className="details-grid">
    <section className="view-card detail-panel"><h2>File information</h2><dl className="detail-list"><div><dt>Created</dt><dd>{details ? formatTimestamp(details.file.createdAt) : '—'}</dd></div><div><dt>Last updated</dt><dd>{details ? formatTimestamp(details.file.updatedAt) : '—'}</dd></div><div><dt>Media type</dt><dd>{current?.mediaType ?? '—'}</dd></div><div><dt>Size</dt><dd>{current ? formatBytes(current.plaintextSize) : '—'}</dd></div><div><dt>Versions</dt><dd>{details?.versions.length ?? 0}</dd></div></dl></section>
    <section className="view-card detail-panel"><h2>Security summary</h2><div className="security-summary-list"><div><CheckCircle2 /><span><strong>Authenticated storage</strong><small>Integrity checked before download</small></span></div><div><KeyRound /><span><strong>Envelope encrypted</strong><small>AES-256-GCM with per-version keys</small></span></div><div><ShieldCheck /><span><strong>Owner authorized</strong><small>Cross-owner reads return not found</small></span></div></div></section>
    <section className="view-card detail-panel wide"><h2>Authorization summary</h2><p>{details?.access === 'owner' ? 'You own this file and can manage access or restore a historical version.' : details?.access === 'download' ? 'The owner granted this account metadata and download access. Restore and grant management remain owner-only.' : 'The owner granted metadata-only access. Download, restore, and grant management remain unavailable.'} Administrators cannot download plaintext or impersonate users.</p></section>
  </div>
}

function Versions({ details, restoring, onRestore }: { details: FileDetails | null; restoring: string; onRestore: (versionID: string) => void }) {
  return <section className="view-card governance-card"><div className="panel-heading"><div><h2>Immutable version history</h2><p>Older versions are authenticated and re-encrypted before becoming current.</p></div></div><div className="version-list">{details?.versions.map((version) => <div className={`version-item${version.current ? ' current' : ''}`} key={version.versionId}><span className="version-marker">{version.current ? <FileCheck2 /> : <RefreshCw />}</span><div><strong>Version {version.number}</strong><small>{version.reason === 'initial_upload' ? 'Initial protected upload' : `Verified restore from ${version.sourceVersionId?.slice(0, 14)}…`}</small></div><span>{formatTimestamp(version.createdAt)}</span>{version.current ? <span className="status-badge stored"><CheckCircle2 size={13} />Current</span> : details.access === 'owner' ? <button className="secondary-button" disabled={Boolean(restoring)} onClick={() => onRestore(version.versionId)}>{restoring === version.versionId ? 'Restoring…' : 'Restore'}</button> : <span>Owner only</span>}</div>)}</div></section>
}

function Access({ fileID }: { fileID: string | null }) {
  const [grants, setGrants] = useState<FileGrant[]>([])
  const [email, setEmail] = useState('')
  const [permission, setPermission] = useState<'read' | 'download'>('read')
  const [expiresAt, setExpiresAt] = useState('')
  const [error, setError] = useState('')
  const [working, setWorking] = useState(false)
  const load = useCallback(() => {
    if (!fileID) return
    listFileGrants(fileID).then((page) => { setGrants(page.grants); setError('') }).catch((requestError) => setError(requestError instanceof Error ? requestError.message : 'Access grants could not be loaded.'))
  }, [fileID])
  useEffect(load, [load])
  const submit = async (event: FormEvent) => {
    event.preventDefault(); if (!fileID || working) return
    setWorking(true); setError('')
    try {
      await createFileGrant(fileID, { recipientEmail: email.trim(), permission, ...(expiresAt ? { expiresAt: new Date(expiresAt).toISOString() } : {}) })
      setEmail(''); setExpiresAt(''); load()
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'Access could not be granted.') }
    finally { setWorking(false) }
  }
  const revoke = async (grantID: string) => {
    if (!fileID || working) return
    setWorking(true); setError('')
    try { await revokeFileGrant(fileID, grantID); load() }
    catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'Access could not be revoked.') }
    finally { setWorking(false) }
  }
  return <section className="view-card governance-card"><div className="panel-heading"><div><h2>Active access grants</h2><p>Share only with verified standard users. Public links and wildcard access are prohibited.</p></div></div>
    <form className="grant-form" onSubmit={submit}><label><span>Recipient email</span><input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="student@example.edu" /></label><label><span>Permission</span><select value={permission} onChange={(event) => setPermission(event.target.value as 'read' | 'download')}><option value="read">Read metadata</option><option value="download">Read and download</option></select></label><label><span>Expires</span><input type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label><button className="primary-button" disabled={working}>{working ? 'Saving…' : 'Grant access'}</button></form>
    {error ? <div className="safe-note" role="alert"><ShieldCheck size={18} /><span>{error}</span></div> : null}
    <div className="governance-table"><div className="governance-head"><span>User</span><span>Permission</span><span>Created</span><span>Expires</span><span /></div>{grants.map((grant) => <div className="governance-row" key={grant.grantId}><strong>{grant.recipientName}<small>{grant.recipientEmail}</small></strong><span>{grant.permission === 'download' ? 'Read and download' : 'Read metadata'}</span><span>{formatTimestamp(grant.createdAt)}</span><span>{grant.expiresAt ? formatTimestamp(grant.expiresAt) : 'Never'}</span><button className="danger-link" disabled={working} onClick={() => void revoke(grant.grantId)}>Revoke</button></div>)}{!error && grants.length === 0 ? <div className="admin-directory-message">No active access grants.</div> : null}</div>
    <div className="safe-note"><ShieldCheck size={18} /><span>Revocation blocks all new metadata and download requests immediately. It cannot recall plaintext already downloaded.</span></div>
  </section>
}

function Unavailable({ title, text }: { title: string; text: string }) { return <section className="view-card governance-card"><h2>{title}</h2><div className="safe-note"><ShieldCheck size={18} /><span>{text}</span></div></section> }
function formatBytes(value: number) { if (value < 1024) return `${value} B`; if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`; return `${(value / 1024 ** 2).toFixed(1)} MB` }
function formatTimestamp(value: string) { return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) }
