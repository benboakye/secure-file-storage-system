import { useEffect, useRef, useState, type DragEvent } from 'react'
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Circle,
  Download,
  FileArchive,
  FileText,
  Film,
  Filter,
  MoreVertical,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  RotateCcw,
  Upload,
  XCircle,
} from 'lucide-react'
import {
  createUploadCandidate,
  formatFileSize,
  uploadCandidateFromAPI,
  validateUpload,
  type InspectionDecision,
  type UploadCandidate,
} from '../uploadModel'
import { fileDownloadURL, getUpload, listSharedFiles, listTrash, listUserFiles, moveFileToTrash, permanentlyDeleteFile, protectedDownloadURL, restoreFileFromTrash, uploadFile, type LifecycleFile, type LogicalFile, type SharedFile } from '../apiClient'

type Navigate = () => void

const inspectionSteps = [
  ['Upload finalized', 'File received successfully.'],
  ['Placed in quarantine', 'File isolated from protected storage.'],
  ['Content type identification', 'Declared type is treated as an untrusted hint.'],
  ['Static inspection', 'Checking the file against the current policy.'],
  ['Policy evaluation', 'Binding evidence to the current policy version.'],
  ['Final decision', 'Accept, reject, or fail closed.'],
] as const

const kindIcon = (name: string) => {
  if (name.endsWith('.mp4')) return Film
  if (name.endsWith('.zip')) return FileArchive
  return FileText
}

export function FilesView({ onUpload, onOpenFile, shared = false, trash = false }: { onUpload: Navigate; onOpenFile: (fileID: string) => void; shared?: boolean; trash?: boolean }) {
  const [files, setFiles] = useState<Array<LogicalFile | SharedFile | LifecycleFile>>([])
  const [search, setSearch] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    let cancelled = false
    const request = trash ? listTrash() : shared ? listSharedFiles() : listUserFiles()
    request
      .then((result) => { if (!cancelled) setFiles(result.files) })
      .catch((requestError) => { if (!cancelled) setError(requestError instanceof Error ? requestError.message : 'Your files could not be loaded.') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [shared, trash, refresh])

  const lifecycleAction = async (action: 'trash' | 'restore' | 'purge', fileID: string) => {
    setError('')
    try {
      if (action === 'trash') await moveFileToTrash(fileID)
      else if (action === 'restore') await restoreFileFromTrash(fileID)
      else await permanentlyDeleteFile(fileID)
      setRefresh((value) => value + 1)
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'The lifecycle operation could not be completed.') }
  }

  const visibleFiles = files.filter((file) => file.name.toLowerCase().includes(search.trim().toLowerCase()))
  return (
    <div className="product-view">
      <header className="view-header">
        <div><p className="kicker">{trash ? 'Recovery and deletion' : shared ? 'Authorized resources' : 'Protected repository'}</p><h1>{trash ? 'Trash' : shared ? 'Shared with me' : 'Files'}</h1><p>{trash ? 'Restore files during their recovery period or review when permanent deletion becomes available.' : shared ? 'Files other users have explicitly authorized you to read.' : 'Search, filter, and manage files after security processing.'}</p></div>
        {!shared && !trash ? <button className="upload-action" onClick={onUpload}><Upload size={18} /> Upload securely</button> : null}
      </header>

      <section className="view-card file-browser-card" aria-labelledby="file-browser-title">
        <div className="browser-toolbar">
          <div><h2 id="file-browser-title">{trash ? 'Deleted files' : shared ? 'Shared files' : 'All files'}</h2><span>{files.length} authoritative file record{files.length === 1 ? '' : 's'}</span></div>
          <div className="browser-controls">
            <label className="compact-search"><Search size={16} /><input aria-label="Search files" placeholder="Search files" value={search} onChange={(event) => setSearch(event.target.value)} /></label>
            <button className="control-button"><Filter size={16} /> All statuses</button>
          </div>
        </div>
        <div className="managed-table">
          <div className="managed-head"><span>File</span><span>Status</span><span>Size</span><span>Owner</span><span>Version</span><span>Updated</span><span /></div>
          {visibleFiles.map((file) => {
            const Icon = kindIcon(file.name)
            return (
              <div className="managed-row" key={file.fileId}>
                <button className="managed-file" disabled={trash} onClick={() => onOpenFile(file.fileId)}><span className="document-icon"><Icon size={18} /></span><span><strong>{file.name}</strong><small>{trash && 'purgeAfter' in file && file.purgeAfter ? `Recovery until ${formatFileDate(file.purgeAfter)}` : 'Protected logical file'}</small></span></button>
                <span><StatusBadge status={trash ? 'Trashed' : 'Stored'} /></span>
                <span>{trash && 'legalHold' in file ? file.legalHold ? 'Legal hold' : file.retentionUntil ? 'Retained' : 'Recovery period' : 'permission' in file ? (file.permission === 'download' ? 'Download' : 'Metadata') : 'See details'}</span><span>{'ownerName' in file ? file.ownerName : 'You'}</span><span>{trash ? 'Unavailable' : 'Current'}</span><span>{formatFileDate(file.updatedAt)}</span>
                <div className="row-actions">{trash ? <><button onClick={() => void lifecycleAction('restore', file.fileId)} aria-label={`Restore ${file.name}`} title="Restore"><RotateCcw size={17} /></button><button onClick={() => void lifecycleAction('purge', file.fileId)} aria-label={`Permanently delete ${file.name}`} title="Permanently delete"><Trash2 size={17} /></button></> : <>{!('permission' in file) || file.permission === 'download' ? <a href={fileDownloadURL(file.fileId)} aria-label={`Download ${file.name}`}><Download size={17} /></a> : null}{!shared ? <button onClick={() => void lifecycleAction('trash', file.fileId)} aria-label={`Move ${file.name} to Trash`} title="Move to Trash"><Trash2 size={17} /></button> : <button aria-label={`More options for ${file.name}`}><MoreVertical size={17} /></button>}</>}</div>
              </div>
            )
          })}
          {loading ? <p className="file-list-message">Loading your files…</p> : null}
          {error ? <p className="file-list-message error" role="alert">{error}</p> : null}
          {!loading && !error && visibleFiles.length === 0 ? <p className="file-list-message">{search ? 'No files match this search.' : trash ? 'Trash is empty.' : shared ? 'No files have been shared with this account.' : 'No files have been uploaded yet.'}</p> : null}
        </div>
        <div className="table-footer"><span>Showing {visibleFiles.length} of {files.length} files</span><span>{trash ? 'Recovery-controlled PostgreSQL records' : shared ? 'Grant-authorized PostgreSQL records' : 'Owner-scoped PostgreSQL records'}</span></div>
      </section>
    </div>
  )
}

function formatFileDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(value))
}

function StatusBadge({ status }: { status: string }) {
  const Icon = status === 'Stored' || status === 'Accepted' || status === 'Ready'
    ? CheckCircle2
    : status === 'Rejected'
      ? XCircle
      : status === 'Inspecting' || status === 'Uploading' || status === 'Encrypting'
        ? RefreshCw
        : AlertTriangle
  const statusClass = status.toLowerCase().replaceAll(' ', '-')
  return <span className={`status-badge ${statusClass}`}><Icon size={13} />{status}</span>
}

export function UploadView({ candidate, onSelect, onInspect }: { candidate: UploadCandidate | null; onSelect: (candidate: UploadCandidate | null) => void; onInspect: (candidate: UploadCandidate) => void }) {
  const stages = ['Upload', 'Quarantine', 'Static inspection', 'Policy decision', 'Encryption', 'Protected storage']
  const inputRef = useRef<HTMLInputElement>(null)
  const uploadAbortRef = useRef<AbortController | null>(null)
  const [dragActive, setDragActive] = useState(false)
  const [error, setError] = useState('')
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)

  useEffect(() => () => uploadAbortRef.current?.abort(), [])

  const selectFile = (file?: File) => {
    if (!file) return
    const validationError = validateUpload(file)
    if (validationError) {
      onSelect(null)
      setError(validationError)
      return
    }

    setError('')
    setProgress(0)
    onSelect(createUploadCandidate(file))
  }

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    setDragActive(false)
    selectFile(event.dataTransfer.files[0])
  }

  const startUpload = async () => {
    if (!candidate?.file || uploading) return
    setUploading(true)
    setError('')
    const abortController = new AbortController()
    uploadAbortRef.current = abortController
    try {
      const upload = await uploadFile(candidate.file, setProgress, abortController.signal)
      if (abortController.signal.aborted) return
      const serverCandidate = uploadCandidateFromAPI(upload)
      onSelect(serverCandidate)
      onInspect(serverCandidate)
    } catch (requestError) {
      if (abortController.signal.aborted) return
      setUploading(false)
      setError(requestError instanceof Error ? requestError.message : 'The secure upload service is unavailable.')
    } finally {
      if (uploadAbortRef.current === abortController) uploadAbortRef.current = null
    }
  }

  const clearSelection = () => {
    onSelect(null)
    setError('')
    setProgress(0)
    if (inputRef.current) inputRef.current.value = ''
  }

  return (
    <div className="product-view">
      <header className="view-header"><div><p className="kicker">First vertical slice</p><h1>Secure upload</h1><p>Every file is treated as untrusted until processing is complete.</p></div></header>
      <div className="upload-layout">
        <section className="view-card upload-card" aria-busy={uploading}>
          <div
            className={dragActive ? 'drop-zone drag-active' : 'drop-zone'}
            onDragEnter={(event) => { event.preventDefault(); setDragActive(true) }}
            onDragOver={(event) => event.preventDefault()}
            onDragLeave={() => setDragActive(false)}
            onDrop={handleDrop}
          >
            <span className="drop-icon"><Upload size={28} /></span>
            <h2>Drop a file here</h2><p>or choose a harmless file from your device</p>
            <input ref={inputRef} className="visually-hidden" type="file" onChange={(event) => selectFile(event.target.files?.[0])} />
            <button className="secondary-button" type="button" onClick={() => inputRef.current?.click()}>Browse files</button>
          </div>

          {candidate ? <div className="selected-file">
            <span className="document-icon"><FileText size={19} /></span>
            <div><strong>{candidate.name}</strong><span>{formatFileSize(candidate.size)} · Declared {candidate.mediaType}</span></div>
            <StatusBadge status={uploading ? 'Uploading' : 'Ready'} />
          </div> : null}

          {uploading ? <div className="upload-progress" role="progressbar" aria-label="Upload progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress}><span><strong>Streaming to quarantine</strong><em>{progress}%</em></span><div><i style={{ width: `${progress}%` }} /></div></div> : null}
          {error ? <div className="upload-error" role="alert"><AlertTriangle size={16} /><span>{error}</span></div> : null}
          <p className="field-note">Maximum file size: 25 MiB. Client checks are guidance only; filenames and browser-supplied media types remain untrusted.</p>
          <div className="upload-actions"><button className="secondary-button" type="button" onClick={clearSelection} disabled={!candidate || uploading}>Clear</button><button className="primary-button" type="button" onClick={startUpload} disabled={!candidate || uploading}><ShieldCheck size={17} />{uploading ? 'Uploading…' : 'Upload securely'}</button></div>
        </section>

        <aside className="view-card lifecycle-card">
          <p className="section-label">Security lifecycle</p><h2>Before storage</h2>
          <ol>{stages.map((stage, index) => <li className={index === 0 ? 'current' : ''} key={stage}><span>{index + 1}</span><div><strong>{stage}</strong><small>{index === 0 ? 'Ready to begin' : 'Required stage'}</small></div></li>)}</ol>
        </aside>
      </div>
    </div>
  )
}

export function InspectionView({ candidate, onUpdate, onResult, onCancel }: { candidate: UploadCandidate; onUpdate: (candidate: UploadCandidate) => void; onResult: (decision: InspectionDecision) => void; onCancel: Navigate }) {
  const [pollError, setPollError] = useState('')
  const [pollAttempt, setPollAttempt] = useState(0)
  const currentStage = candidate.status === 'quarantined' ? 1 : candidate.status === 'inspecting' ? 3 : candidate.status === 'encrypting' ? 4 : 5
  const progress = candidate.progress || Math.round(((currentStage + 1) / inspectionSteps.length) * 100)

  useEffect(() => {
    if (candidate.status === 'stored' || candidate.status === 'accepted' || candidate.status === 'rejected' || candidate.status === 'failed') {
	  onResult(candidate.status === 'stored' ? 'accepted' : candidate.status)
      return
    }

    let cancelled = false
    let pollTimer = 0
    const poll = async () => {
      try {
        const upload = await getUpload(candidate.id)
        if (cancelled) return
        const updatedCandidate = uploadCandidateFromAPI(upload)
        onUpdate(updatedCandidate)
        setPollError('')
		if (upload.status === 'stored' || upload.status === 'accepted' || upload.status === 'rejected' || upload.status === 'failed') {
		  onResult(upload.status === 'stored' ? 'accepted' : upload.status)
          return
        }
        pollTimer = window.setTimeout(poll, 500)
      } catch (requestError) {
        if (!cancelled) setPollError(requestError instanceof Error ? requestError.message : 'The inspection status is temporarily unavailable.')
      }
    }
    poll()

    return () => {
      cancelled = true
      window.clearTimeout(pollTimer)
    }
  }, [candidate.id, candidate.status, onResult, onUpdate, pollAttempt])

  return (
    <div className="product-view inspection-view">
      <header className="view-header"><div><p className="kicker">Security processing</p><h1>Inspection &amp; protection</h1><p>{candidate.name} · {formatFileSize(candidate.size)}</p></div><StatusBadge status={candidate.status === 'quarantined' ? 'Quarantined' : candidate.status === 'encrypting' ? 'Encrypting' : 'Inspecting'} /></header>
      <div className="quarantine-banner"><AlertTriangle size={19} /><div><strong>File access is blocked</strong><span>Files in quarantine cannot be downloaded or shared.</span></div></div>
      <section className="view-card inspection-card" aria-live="polite">
        <div className="inspection-progress"><span>Current progress</span><strong>{progress}%</strong></div><div className="progress-track"><i style={{ width: `${progress}%` }} /></div>
        <div className="inspection-steps">
          {inspectionSteps.map(([title, detail], index) => {
            const state = index < currentStage ? 'passed' : index === currentStage ? 'running' : 'waiting'
            return <div className={`inspection-step ${state}`} key={title}>
              <span className="step-marker">{state === 'passed' ? <Check size={16} /> : state === 'running' ? <RefreshCw size={16} /> : <Circle size={13} />}</span>
              <div><strong>{title}</strong><small>{detail}</small></div><span className="step-state">{state}</span>
              {index < inspectionSteps.length - 1 ? <i className="step-line" /> : null}
            </div>
          })}
        </div>
        {pollError ? <div className="upload-error" role="alert"><AlertTriangle size={16} /><span>{pollError}</span><button className="secondary-button" onClick={() => setPollAttempt((attempt) => attempt + 1)}>Retry status check</button></div> : null}
        <div className="inspection-footer"><span>Correlation ID: <code>{candidate.correlationId || candidate.id}</code> · authoritative server polling</span><button className="secondary-button" onClick={onCancel}>Leave this view</button></div>
      </section>
    </div>
  )
}

function ResultFile({ candidate, status }: { candidate: UploadCandidate; status: string }) {
  const Icon = candidate.name.toLowerCase().endsWith('.zip') ? FileArchive : FileText
  return <div className="result-file"><span className="document-icon"><Icon size={20} /></span><div><strong>{candidate.name}</strong><span>{formatFileSize(candidate.size)} · {candidate.mediaType}</span></div><StatusBadge status={status} /></div>
}

export function RejectedView({ candidate, onFiles, onUpload }: { candidate: UploadCandidate; onFiles: Navigate; onUpload: Navigate }) {
  return <div className="product-view result-view"><section className="view-card result-card rejected-result"><span className="result-icon"><XCircle size={42} /></span><p className="section-label">Policy decision</p><h1>File rejected</h1><p className="result-lead">The file did not meet the current upload policy. It is inaccessible and was not moved into protected storage.</p><ResultFile candidate={candidate} status="Rejected" /><dl className="result-metadata"><div><dt>Decision time</dt><dd>Just now</dd></div><div><dt>Reason category</dt><dd>Disallowed content</dd></div><div><dt>Correlation ID</dt><dd><code>{candidate.correlationId}</code></dd></div></dl><div className="safe-note"><ShieldCheck size={18} /><span>Raw scanner output, internal rules, paths, and stack traces are intentionally hidden.</span></div><div className="result-actions"><button className="secondary-button" onClick={onFiles}>Return to Files</button><button className="primary-button" onClick={onUpload}>Upload another file</button></div></section></div>
}

export function FailedView({ candidate, onUpload }: { candidate: UploadCandidate; onUpload: Navigate }) {
  return <div className="product-view result-view"><section className="view-card result-card failed-result"><span className="result-icon"><AlertTriangle size={42} /></span><p className="section-label">Fail-closed decision</p><h1>File was not accepted</h1><p className="result-lead">The inspection service did not return sufficient evidence before the deadline. The file remains inaccessible and has not entered protected storage.</p><ResultFile candidate={candidate} status="Failed closed" /><dl className="result-metadata"><div><dt>Decision time</dt><dd>Just now</dd></div><div><dt>Reason category</dt><dd>Inspection unavailable</dd></div><div><dt>Correlation ID</dt><dd><code>{candidate.correlationId}</code></dd></div></dl><div className="safe-note"><ShieldCheck size={18} /><span>Uncertainty never produces an accepted result. Retry with a harmless file or contact an administrator.</span></div><div className="result-actions"><button className="primary-button" onClick={onUpload}>Try another file</button></div></section></div>
}

export function AcceptedView({ candidate, onFiles, onUpload }: { candidate: UploadCandidate; onFiles: Navigate; onUpload: Navigate }) {
  return (
    <div className="product-view result-view">
      <section className="view-card result-card">
        <span className="result-icon"><ShieldCheck size={42} /></span>
        <p className="section-label">Protected storage</p><h1>File encrypted and stored</h1>
        <p className="result-lead">The file passed the current inspection policy and was committed as an authenticated AES-256-GCM ciphertext version. Quarantine plaintext was removed after the protected commit.</p>
        <ResultFile candidate={candidate} status="Stored" />
        <dl className="result-metadata"><div><dt>Inspection completed</dt><dd>Just now</dd></div><div><dt>Policy version</dt><dd>v1.4-demo</dd></div><div><dt>Correlation ID</dt><dd><code>{candidate.correlationId}</code></dd></div></dl>
        <div className="next-stage"><CheckCircle2 size={20} /><div><strong>Protection complete</strong><span>A unique data-encryption key protects this immutable version and is wrapped separately by the configured key provider.</span></div></div>
        <div className="result-actions"><button className="secondary-button" onClick={onFiles}>Return to Files</button><a className="secondary-button" href={protectedDownloadURL(candidate.id)}><Download size={17} />Download protected file</a><button className="primary-button" onClick={onUpload}>Upload another file</button></div>
      </section>
    </div>
  )
}
