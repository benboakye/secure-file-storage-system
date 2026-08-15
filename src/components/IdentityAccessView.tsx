import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { CheckCircle2, Plus, Search, ShieldCheck, ShieldOff, Users } from 'lucide-react'
import {
  invitePrivilegedAccount,
  listAdminUsers,
  revokeAdminUserSessions,
  updateAdminUserStatus,
  type AdminUserPage,
} from '../apiClient'
import { canManageIdentity } from '../identityPermissions'

export function IdentityAccessView({ actorId, requireStepUp }: { actorId: string; requireStepUp:()=>Promise<void> }) {
  const [query, setQuery] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState<AdminUserPage | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busyUserId, setBusyUserId] = useState('')
  const [inviteOpen, setInviteOpen] = useState(false)
  const [inviteBusy, setInviteBusy] = useState(false)

  const loadDirectory = useCallback(async () => {
    setPage(await listAdminUsers(search))
  }, [search])

  useEffect(() => {
    let cancelled = false
    setError('')
    listAdminUsers(search)
      .then((result) => { if (!cancelled) setPage(result) })
      .catch((requestError) => {
        if (!cancelled) setError(requestError instanceof Error ? requestError.message : 'The user directory could not be loaded.')
      })
    return () => { cancelled = true }
  }, [search])

  const summary = useMemo(() => ({
    active: page?.users.filter((user) => user.accountStatus === 'active').length ?? 0,
    suspended: page?.users.filter((user) => user.accountStatus === 'suspended').length ?? 0,
    administrators: page?.users.filter((user) => user.role === 'admin').length ?? 0,
  }), [page])

  const submitSearch = (event: FormEvent) => {
    event.preventDefault()
    setSearch(query.trim())
  }

  const changeStatus = async (userId: string, status: 'active' | 'suspended') => {
    const description = status === 'suspended'
      ? 'suspend this account and immediately revoke all of its sessions'
      : 'reactivate this account'
    if (!window.confirm(`Are you sure you want to ${description}?`)) return
    setBusyUserId(userId)
    setError('')
    setNotice('')
    try {
	  await requireStepUp()
      const result = await updateAdminUserStatus(userId, status)
      setNotice(result.message)
      await loadDirectory()
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'The account status could not be updated.')
    } finally {
      setBusyUserId('')
    }
  }

  const revokeSessions = async (userId: string) => {
    if (!window.confirm('Revoke every active session for this account?')) return
    setBusyUserId(userId)
    setError('')
    setNotice('')
    try {
	  await requireStepUp()
      const result = await revokeAdminUserSessions(userId)
      setNotice(result.message)
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Sessions could not be revoked.')
    } finally {
      setBusyUserId('')
    }
  }

  const inviteAccount = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    setInviteBusy(true); setError(''); setNotice('')
    try {
      await requireStepUp()
      const result = await invitePrivilegedAccount({
        name: String(data.get('name') ?? '').trim(),
        email: String(data.get('email') ?? '').trim().toLowerCase(),
        role: String(data.get('role')) as 'admin' | 'auditor',
      })
      setNotice(result.message)
      setInviteOpen(false)
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'The privileged invitation could not be created.')
    } finally {
      setInviteBusy(false)
    }
  }

  return (
    <div className="product-view">
      <header className="view-header">
        <div>
          <p className="kicker">Administrator only</p>
          <h1>Identity &amp; access</h1>
          <p>Enforce account access and invalidate sessions without exposing credentials or authentication tokens.</p>
        </div>
        <div className="admin-header-actions"><button className="primary-button" onClick={() => setInviteOpen(true)}><Plus size={16} />Invite privileged account</button><span className="integrity-pill"><ShieldCheck size={16} />Server-authorized</span></div>
      </header>

      <div className="admin-grid">
        <section className="view-card governance-card admin-users">
          <div className="panel-heading">
            <div>
              <h2>Organization users</h2>
              <p>{page ? `${page.total} database record${page.total === 1 ? '' : 's'}` : 'Loading the protected directory…'}</p>
            </div>
            <form className="admin-search" onSubmit={submitSearch}>
              <label className="compact-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search users" placeholder="Search name or email" /></label>
              <button className="secondary-button" type="submit">Search</button>
            </form>
          </div>

          {error ? <div className="admin-directory-message error" role="alert">{error}</div> : null}
          {notice ? <div className="admin-directory-message success" role="status">{notice}</div> : null}

          <div className="governance-table">
            <div className="governance-head admin"><span>User</span><span>Role</span><span>Access</span><span>Actions</span></div>
            {page?.users.map((user) => {
              const self = !canManageIdentity(actorId, user.id)
              const busy = busyUserId === user.id
              return (
                <div className="governance-row admin" key={user.id}>
                  <strong>{user.name}<small>{user.email}</small></strong>
                  <span className="role-label">{user.role}<small>{user.verificationStatus}</small></span>
                  <span className={`status-badge ${user.accountStatus === 'active' ? 'stored' : 'rejected'}`}>
                    {user.accountStatus === 'active' ? <CheckCircle2 size={13} /> : <ShieldOff size={13} />}{user.accountStatus}
                  </span>
                  <span className="admin-row-actions">
                    {self ? <small>Current account</small> : <>
                      <button disabled={busy} onClick={() => changeStatus(user.id, user.accountStatus === 'active' ? 'suspended' : 'active')}>{user.accountStatus === 'active' ? 'Suspend' : 'Reactivate'}</button>
                      <button disabled={busy} onClick={() => revokeSessions(user.id)}>Revoke sessions</button>
                    </>}
                  </span>
                </div>
              )
            })}
            {page && page.users.length === 0 ? <div className="admin-directory-message">No matching user records.</div> : null}
            {!page ? <div className="admin-directory-message">Loading user records…</div> : null}
          </div>
        </section>

        <aside className="admin-status">
          <section className="view-card service-status">
            <h2>Directory summary</h2>
            {[
              ['Active in view', String(summary.active), 'Access permitted'],
              ['Suspended in view', String(summary.suspended), 'Access denied'],
              ['Administrators in view', String(summary.administrators), 'Privileged'],
            ].map((item) => <div key={item[0]}><span className="service-icon"><Users size={16} /></span><span><strong>{item[0]}</strong><small>{item[2]}</small></span><em>{item[1]}</em></div>)}
          </section>
          <div className="safe-note admin-note"><ShieldCheck size={18} /><span>Status changes and session revocation are enforced by the API. Administrators cannot apply these controls to their own active session.</span></div>
        </aside>
      </div>
      {inviteOpen ? <div className="admin-modal-backdrop" role="presentation" onMouseDown={() => setInviteOpen(false)}>
        <section className="admin-modal" role="dialog" aria-modal="true" aria-labelledby="invite-title" onMouseDown={(event) => event.stopPropagation()}>
          <header><span>Controlled provisioning</span><h2 id="invite-title">Invite a privileged identity</h2><p>Create a separate administrator or auditor identity. The recipient chooses their own password through a single-use link.</p></header>
          <form onSubmit={inviteAccount}>
            <label htmlFor="invite-name">Full name</label><input id="invite-name" name="name" maxLength={120} required />
            <label htmlFor="invite-email">Dedicated email address</label><input id="invite-email" name="email" type="email" maxLength={254} required />
            <label htmlFor="invite-role">Privileged role</label><select id="invite-role" name="role" defaultValue="auditor"><option value="auditor">Auditor — read-only oversight</option><option value="admin">Administrator — policy management</option></select>
            <small>The invitation expires in 30 minutes. Activation creates no session; TOTP enrollment occurs at first privileged sign-in.</small>
            <div><button type="button" className="secondary-button" onClick={() => setInviteOpen(false)} disabled={inviteBusy}>Cancel</button><button className="primary-button" disabled={inviteBusy}>{inviteBusy ? 'Creating…' : 'Create invitation'}</button></div>
          </form>
        </section>
      </div> : null}
    </div>
  )
}
