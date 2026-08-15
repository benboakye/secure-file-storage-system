import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Bell,
  ChevronDown,
  ChevronRight,
  Clock3,
  FileArchive,
  FileImage,
  FileText,
  Film,
  Folder,
  FolderOpen,
  Gauge,
  HardDrive,
  Home,
  LayoutGrid,
  LogOut,
  MoreVertical,
  Plus,
  Search,
  Share2,
  ShieldCheck,
  Star,
  Trash2,
  Upload,
} from 'lucide-react'
import { AcceptedView, FailedView, FilesView, InspectionView, RejectedView, UploadView } from './components/Views'
import { AdministrationView, AuditView } from './components/GovernanceViews'
import { FileDetailsView } from './components/FileDetailsView'
import { ActivatePrivilegedView, AuthView, CheckEmailView, VerifyEmailView, type AuthSubmission } from './components/AuthViews'
import { AdminPortal } from './components/AdminPortal'
import {
  isAdminPage,
  isProtectedPage,
  isStandardProtectedPage,
  pageFromHash,
  type AppPage,
} from './appSession'
import { DEMO_UPLOAD, type InspectionDecision, type UploadCandidate } from './uploadModel'
import { completePrivilegedMFA, login, loginPrivileged, logout, register, restoreSession, type ApiUser } from './apiClient'
import { subscribeToAuthenticationExpiry } from './authenticationExpiry'

type FileKind = 'pdf' | 'video' | 'archive' | 'image' | 'document'

type FileItem = {
  name: string
  kind: FileKind
  updated: string
  members: string
  size: string
  starred?: boolean
}

const folders = [
  { name: 'Projects', files: 453, size: '11 GB', accent: 'steel' },
  { name: 'Marketing', files: 84, size: '3.6 GB', accent: 'blue' },
  { name: 'Personal', files: 287, size: '8.9 GB', accent: 'rose' },
  { name: 'Portfolio', files: 56, size: '6 GB', accent: 'green' },
]

const files: FileItem[] = [
  { name: 'security-training.pdf', kind: 'pdf', updated: 'Today, 10:24', members: 'Only you', size: '2.4 MB', starred: true },
  { name: 'quarterly-demo.mp4', kind: 'video', updated: 'Yesterday, 16:02', members: '5 members', size: '237 MB' },
  { name: 'project-assets.zip', kind: 'archive', updated: 'Aug 8, 2026', members: '10 members', size: '82 MB' },
  { name: 'brand-photo.png', kind: 'image', updated: 'Aug 7, 2026', members: '3 members', size: '5.1 MB' },
  { name: 'policy-notes.docx', kind: 'document', updated: 'Aug 6, 2026', members: 'Only you', size: '184 KB' },
]

const fileIcon = {
  pdf: FileText,
  video: Film,
  archive: FileArchive,
  image: FileImage,
  document: FileText,
}

const primaryNavigation = [
  { label: 'Dashboard', page: 'dashboard' as const, Icon: Home },
  { label: 'Files', page: 'files' as const, Icon: HardDrive },
  { label: 'Upload', page: 'upload' as const, Icon: Upload },
  { label: 'Audit Activity', page: 'audit' as const, Icon: Gauge },
]

const folderNavigation = ['Assets', 'Marketing', 'Personal', 'Portfolio', 'Projects', 'Templates']

const pageTitles: Record<AppPage, string> = {
  dashboard: 'Dashboard',
  files: 'Files',
  shared: 'Shared with me',
  trash: 'Trash',
  upload: 'Secure upload',
  inspection: 'File inspection',
  accepted: 'File accepted',
  rejected: 'File rejected',
  failed: 'Inspection unavailable',
  details: 'File details',
  audit: 'Audit activity',
  admin: 'Administration',
  'admin-dashboard': 'Admin dashboard',
  'admin-resources': 'Resource metadata',
  'admin-security': 'Security and compliance',
  'admin-monitoring': 'System monitoring',
  'admin-lifecycle': 'Data lifecycle',
  'admin-audit': 'Audit trail',
  'admin-signin': 'Privileged sign in',
  signin: 'Sign in',
  register: 'Create account',
  'check-email': 'Check your email',
  'verify-email': 'Verify email',
  'activate-privileged': 'Activate privileged account',
}

function verificationTokenFromHash() {
  const query = window.location.hash.split('?')[1] ?? ''
  return new URLSearchParams(query).get('token') ?? ''
}

function isPrivilegedRole(role: ApiUser['role'] | undefined) {
  return role === 'admin' || role === 'auditor'
}

function App() {
  const [query, setQuery] = useState('')
  const [session, setSession] = useState<ApiUser | null | undefined>(undefined)
  const [activePage, setActivePage] = useState<AppPage>(() => pageFromHash())
  const [view, setView] = useState<'grid' | 'list'>('list')
  const [toast, setToast] = useState('')
  const [selectedUpload, setSelectedUpload] = useState<UploadCandidate | null>(null)
  const [selectedFileID, setSelectedFileID] = useState<string | null>(null)
  const [pendingEmail, setPendingEmail] = useState('')

  const navigate = useCallback((page: AppPage, replace = false) => {
    const destination = session === null && isProtectedPage(page)
      ? isAdminPage(page) ? 'admin-signin' : 'signin'
      : isAdminPage(page) && !isPrivilegedRole(session?.role)
        ? 'dashboard'
        : page === 'admin' && session?.role !== 'admin'
          ? 'admin-dashboard'
          : session && isStandardProtectedPage(page) && isPrivilegedRole(session.role)
            ? 'admin-dashboard'
            : page
    const nextHash = `#${destination}`

    if (window.location.hash !== nextHash) {
      if (replace) window.history.replaceState(null, '', nextHash)
      else window.location.hash = destination
    }
    setActivePage(destination)
  }, [session])

  const handleInspectionResult = useCallback((decision: InspectionDecision) => {
    navigate(decision)
  }, [navigate])

  useEffect(() => subscribeToAuthenticationExpiry(() => {
    // The API has already erased its in-memory CSRF and step-up values. Clearing
    // the React owner causes the protected-route effect below to select the
    // correct standard or privileged sign-in boundary from the current hash.
    setSession(null)
  }), [])

  useEffect(() => {
    let cancelled = false
    restoreSession()
      .then((user) => { if (!cancelled) setSession(user) })
      .catch(() => { if (!cancelled) setSession(null) })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (session === undefined) return
    const syncRoute = () => {
      const requestedPage = pageFromHash()
	  let destination: AppPage = requestedPage
	  if (session === null && isProtectedPage(requestedPage)) {
	    destination = isAdminPage(requestedPage) ? 'admin-signin' : 'signin'
	  } else if (session && isAdminPage(requestedPage) && !isPrivilegedRole(session.role)) {
	    destination = 'dashboard'
	  } else if (session && requestedPage === 'admin' && session.role !== 'admin') {
	    destination = 'admin-dashboard'
	  } else if (session && isStandardProtectedPage(requestedPage) && isPrivilegedRole(session.role)) {
	    destination = 'admin-dashboard'
	  } else if (session && (requestedPage === 'signin' || requestedPage === 'admin-signin' || requestedPage === 'register' || requestedPage === 'check-email' || requestedPage === 'verify-email' || requestedPage === 'activate-privileged')) {
	    destination = isPrivilegedRole(session.role) ? 'admin-dashboard' : 'dashboard'
	  }
      if (requestedPage !== destination) window.history.replaceState(null, '', `#${destination}`)
      setActivePage(destination)
    }

    window.addEventListener('hashchange', syncRoute)
    syncRoute()
    return () => window.removeEventListener('hashchange', syncRoute)
  }, [session])

  useEffect(() => {
    document.title = `${pageTitles[activePage]} — SecureStore`
  }, [activePage])

  const filteredFiles = useMemo(
    () => files.filter((file) => file.name.toLowerCase().includes(query.toLowerCase())),
    [query],
  )

  const announce = (message: string) => {
    setToast(message)
    window.setTimeout(() => setToast(''), 2200)
  }

  const authenticate = async (submission: AuthSubmission) => {
	if (submission.recoveryCodesAcknowledged) {
		window.history.replaceState(null, '', '#admin-dashboard')
		setActivePage('admin-dashboard')
		return
	}
    if (submission.mode === 'register') {
      await register({ name: submission.name, email: submission.email, password: submission.password })
      setPendingEmail(submission.email)
      window.history.replaceState(null, '', '#check-email')
      setActivePage('check-email')
      return
    }
	if (submission.mode === 'admin-signin' && submission.mfaChallengeToken) {
		const completed = await completePrivilegedMFA(submission.mfaChallengeToken, submission.mfaCode ?? '')
		setSession(completed.user)
		if (completed.recoveryCodes?.length) return { recoveryCodes: completed.recoveryCodes }
		window.history.replaceState(null, '', '#admin-dashboard')
		setActivePage('admin-dashboard')
		return
	}
	const loginResult = submission.mode === 'admin-signin'
		? await loginPrivileged({ email: submission.email, password: submission.password })
		: await login({ email: submission.email, password: submission.password })
	if ('mfaRequired' in loginResult) return loginResult
	const user = loginResult
    setSession(user)
    const destination: AppPage = isPrivilegedRole(user.role) ? 'admin-dashboard' : 'dashboard'
    window.history.replaceState(null, '', `#${destination}`)
    setActivePage(destination)
  }

  const signOut = async () => {
    const destination: AppPage = isPrivilegedRole(session?.role) ? 'admin-signin' : 'signin'
    try {
      await logout()
    } finally {
      setSession(null)
      window.history.replaceState(null, '', `#${destination}`)
      setActivePage(destination)
    }
  }

  const beginInspection = (candidate: UploadCandidate) => {
    setSelectedUpload(candidate)
    navigate('inspection')
  }

  const restartUpload = () => {
    setSelectedUpload(null)
    navigate('upload')
  }

  if (session === undefined) {
    return <main className="app-loading" aria-live="polite"><span className="brand-mark"><ShieldCheck size={22} /></span><strong>Checking your secure session…</strong></main>
  }

  if (activePage === 'signin' || activePage === 'register' || activePage === 'admin-signin') {
    return <AuthView key={activePage} mode={activePage} onSwitch={() => navigate(activePage === 'signin' ? 'register' : 'signin')} onAuthenticated={authenticate} />
  }

  if (activePage === 'check-email') {
    return <CheckEmailView email={pendingEmail} onSignIn={() => navigate('signin')} />
  }

  if (activePage === 'verify-email') {
    return <VerifyEmailView token={verificationTokenFromHash()} onSignIn={() => navigate('signin')} />
  }

  if (activePage === 'activate-privileged') {
    return <ActivatePrivilegedView token={verificationTokenFromHash()} onSignIn={() => navigate('admin-signin')} />
  }

  if (isPrivilegedRole(session?.role) && isAdminPage(activePage)) {
    return <AdminPortal page={activePage} user={session} onNavigate={navigate} onLogout={() => void signOut()} />
  }

  return (
    <main className={activePage === 'dashboard' ? 'app-shell' : 'app-shell page-wide'}>
      <aside className="icon-rail" aria-label="Primary navigation">
        <a className="rail-brand" href="#dashboard" onClick={() => navigate('dashboard')} aria-label="SecureStore home">
          <ShieldCheck size={25} strokeWidth={2.2} />
        </a>
        <div className="rail-nav">
          {primaryNavigation.map(({ label, page, Icon }) => (
            <button
              className={activePage === page ? 'rail-button active' : 'rail-button'}
              key={label}
              onClick={() => navigate(page)}
              aria-label={label}
              aria-current={activePage === page ? 'page' : undefined}
              title={label}
            >
              <Icon size={20} />
            </button>
          ))}
        </div>
      </aside>

      <aside className="folder-sidebar">
        <div className="brand-lockup">
          <span className="brand-mark"><ShieldCheck size={21} /></span>
          <span>Secure<span>Store</span></span>
        </div>

        <button className="create-button" onClick={() => navigate('upload')}>
          <Plus size={17} /> Upload file
        </button>

        <nav className="tree-nav" aria-label="File locations">
          <p className="nav-eyebrow">My files</p>
          <a href="#files" onClick={() => navigate('files')}><ChevronDown size={14} /><FolderOpen size={16} /> All files</a>
          {folderNavigation.map((item) => (
            <a className="nested-link" href="#files" onClick={() => navigate('files')} key={item}>
              <ChevronRight size={13} /><Folder size={15} />{item}
            </a>
          ))}
          <div className="nav-divider" />
          <a href="#shared" onClick={() => navigate('shared')}><Share2 size={16} />Shared with me</a>
          <a href="#dashboard" onClick={() => navigate('dashboard')}><Clock3 size={16} />Recent</a>
          <a href="#files" onClick={() => navigate('files')}><Star size={16} />Starred</a>
          <a href="#trash" onClick={() => navigate('trash')}><Trash2 size={16} />Trash</a>
          <div className="nav-divider" />
          <a href="#audit" onClick={() => navigate('audit')}><Gauge size={16} />Audit activity</a>
          <a href="#signin" onClick={(event) => { event.preventDefault(); void signOut() }}><LogOut size={16} />Sign out</a>
        </nav>

        <div className="sidebar-security">
          <ShieldCheck size={18} />
          <div><strong>Protected storage</strong><span>All services operational</span></div>
        </div>
      </aside>

      <section className={activePage === 'dashboard' ? 'workspace' : 'workspace workspace-wide'} id="top">
        <header className="topbar">
          <label className="search-box">
            <Search size={18} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search your files"
              aria-label="Search your files"
            />
            <kbd>⌘ K</kbd>
          </label>
          <div className="view-switcher" aria-label="View options">
            <button className={view === 'grid' ? 'active' : ''} onClick={() => setView('grid')} aria-label="Grid view"><LayoutGrid size={18} /></button>
            <button className={view === 'list' ? 'active' : ''} onClick={() => setView('list')} aria-label="List view"><HardDrive size={18} /></button>
          </div>
        </header>

        {activePage === 'dashboard' ? <div className="content-wrap">
          <section className="welcome-row">
            <div>
              <p className="kicker">Monday, August 10</p>
              <h1>Your secure files</h1>
              <p>Continue working or upload something new for protected storage.</p>
            </div>
            <button className="upload-action" onClick={() => navigate('upload')}>
              <Upload size={18} /> Upload securely
            </button>
          </section>

          <section aria-labelledby="quick-access-title">
            <div className="section-heading">
              <div><span className="section-label">Workspace</span><h2 id="quick-access-title">Quick access</h2></div>
              <button>View all <ChevronRight size={16} /></button>
            </div>
            <div className="quick-grid">
              <article className="quick-card featured">
                <div className="quick-icon"><FolderOpen /></div>
                <div><strong>Projects</strong><span>8 files · Updated today</span></div>
                <div className="avatar-stack" aria-label="6 collaborators"><span>AB</span><span>KM</span><span>+4</span></div>
              </article>
              <article className="quick-card">
                <div className="file-glyph pdf"><FileText /></div>
                <div><strong>Security policy.pdf</strong><span>12 MB · Stored</span></div>
                <button aria-label="More options"><MoreVertical size={18} /></button>
              </article>
              <article className="quick-card">
                <div className="file-glyph video"><Film /></div>
                <div><strong>Product demo.mp4</strong><span>237 MB · Stored</span></div>
                <span className="avatar solo">JS</span>
              </article>
            </div>
          </section>

          <section id="folders" aria-labelledby="folders-title">
            <div className="section-heading">
              <div><span className="section-label">Organize</span><h2 id="folders-title">Folders</h2></div>
              <button>Manage folders <ChevronRight size={16} /></button>
            </div>
            <div className="folder-grid">
              {folders.map((folder) => (
                <article className="folder-card" key={folder.name}>
                  <div className={`folder-icon ${folder.accent}`}><Folder /></div>
                  <button aria-label={`More options for ${folder.name}`}><MoreVertical size={18} /></button>
                  <h3>{folder.name}</h3>
                  <p><span>{folder.files} files</span><strong>{folder.size}</strong></p>
                </article>
              ))}
            </div>
          </section>

          <section id="recent" aria-labelledby="recent-title">
            <div className="section-heading">
              <div><span className="section-label">Activity</span><h2 id="recent-title">Recent files</h2></div>
              <button>View all <ChevronRight size={16} /></button>
            </div>
            <div className={view === 'grid' ? 'files-grid' : 'file-table'}>
              {view === 'list' && <div className="table-head"><span>Name</span><span>Updated</span><span>Access</span><span>Size</span><span /></div>}
              {filteredFiles.map((file) => {
                const Icon = fileIcon[file.kind]
                return (
                  <article className="file-row" key={file.name}>
                    <div className="file-name"><span className={`file-glyph ${file.kind}`}><Icon size={19} /></span><strong>{file.name}</strong>{file.starred && <Star className="starred" size={15} fill="currentColor" />}</div>
                    <span>{file.updated}</span><span>{file.members}</span><span>{file.size}</span>
                    <button aria-label={`More options for ${file.name}`}><MoreVertical size={18} /></button>
                  </article>
                )
              })}
              {filteredFiles.length === 0 && <div className="empty-state"><Search /><strong>No files found</strong><span>Try a different search term.</span></div>}
            </div>
          </section>
        </div> : activePage === 'files' ? (
          <FilesView onUpload={() => navigate('upload')} onOpenFile={(fileID) => { setSelectedFileID(fileID); navigate('details') }} />
        ) : activePage === 'shared' ? (
          <FilesView shared onUpload={() => navigate('upload')} onOpenFile={(fileID) => { setSelectedFileID(fileID); navigate('details') }} />
        ) : activePage === 'trash' ? (
          <FilesView trash onUpload={() => navigate('upload')} onOpenFile={(fileID) => { setSelectedFileID(fileID); navigate('details') }} />
        ) : activePage === 'upload' ? (
          <UploadView candidate={selectedUpload} onSelect={setSelectedUpload} onInspect={beginInspection} />
        ) : activePage === 'inspection' ? (
          <InspectionView candidate={selectedUpload ?? DEMO_UPLOAD} onUpdate={setSelectedUpload} onResult={handleInspectionResult} onCancel={restartUpload} />
        ) : activePage === 'accepted' ? (
          <AcceptedView candidate={selectedUpload ?? DEMO_UPLOAD} onFiles={() => navigate('files')} onUpload={restartUpload} />
        ) : activePage === 'rejected' ? (
          <RejectedView candidate={selectedUpload ?? DEMO_UPLOAD} onFiles={() => navigate('files')} onUpload={restartUpload} />
        ) : activePage === 'failed' ? (
          <FailedView candidate={selectedUpload ?? DEMO_UPLOAD} onUpload={restartUpload} />
        ) : activePage === 'details' ? (
          <FileDetailsView fileID={selectedFileID} onBack={() => navigate('files')} />
        ) : activePage === 'audit' ? (
          <AuditView />
        ) : (
          <AdministrationView />
        )}
      </section>

      {activePage === 'dashboard' ? <aside className="insights-panel">
        <div className="profile-row">
          <button aria-label="Notifications"><Bell size={19} /><span className="notification-dot" /></button>
          <div><span>Welcome back</span><strong>{session?.name ?? 'Jane Student'}</strong></div>
          <div className="profile-avatar">{(session?.name ?? 'Jane Student').split(/\s+/).map((part) => part[0]).join('').slice(0, 2).toUpperCase()}</div>
        </div>

        <section className="storage-card" aria-labelledby="storage-title">
          <div className="card-heading"><div><span>Current plan</span><h2 id="storage-title">Storage</h2></div><span className="plan-badge">EDU</span></div>
          <div className="storage-ring"><div><strong>42.4 GB</strong><span>of 50 GB used</span></div></div>
          <div className="storage-legend">
            <div><i className="video" /><span>Videos<small>302 files</small></span><strong>16.2 GB</strong></div>
            <div><i className="image" /><span>Photos<small>1,872 files</small></span><strong>12.1 GB</strong></div>
            <div><i className="document" /><span>Documents<small>576 files</small></span><strong>9 GB</strong></div>
            <div><i className="other" /><span>Other files<small>249 files</small></span><strong>5.1 GB</strong></div>
          </div>
        </section>

        <section className="security-card">
          <div className="security-visual"><ShieldCheck size={40} /><span><Star size={14} fill="currentColor" /></span></div>
          <h2>Protected by design</h2>
          <p>Files are quarantined, inspected, encrypted, and verified before storage.</p>
          <button onClick={() => announce('Security overview opened')}>Security overview</button>
        </section>

        <p className="prototype-note">Educational prototype — not production-ready.</p>
      </aside> : null}

      {toast && <div className="toast" role="status">{toast}</div>}
    </main>
  )
}

export default App
