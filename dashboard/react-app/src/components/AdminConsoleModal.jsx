import { useState, useEffect, useCallback } from 'react'

export default function AdminConsoleModal({ isOpen, onClose, currentUser, token, onToast }) {
  const [activeTab, setActiveTab] = useState('users') // 'users' | 'audit' | 'system'

  // Users state
  const [users, setUsers] = useState([])
  const [loadingUsers, setLoadingUsers] = useState(false)
  const [showAddUser, setShowAddUser] = useState(false)
  const [newUser, setNewUser] = useState({
    username: '',
    email: '',
    password: '',
    full_name: '',
    role: 'analyst',
  })
  const [submittingUser, setSubmittingUser] = useState(false)

  // Audit logs state
  const [auditLogs, setAuditLogs] = useState([])
  const [loadingLogs, setLoadingLogs] = useState(false)
  const [actionFilter, setActionFilter] = useState('ALL')
  const [searchFilter, setSearchFilter] = useState('')

  // System telemetry & Policy state
  const [sysStatus, setSysStatus] = useState(null)
  const [policy, setPolicy] = useState(null)
  const [loadingSys, setLoadingSys] = useState(false)
  const [savingPolicy, setSavingPolicy] = useState(false)

  // Fetch Users
  const fetchUsers = useCallback(async () => {
    if (!token) return
    setLoadingUsers(true)
    try {
      const res = await fetch('/api/auth/users', {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setUsers(data || [])
    } catch (err) {
      onToast(`Failed to load users: ${err.message}`, 'error')
    } finally {
      setLoadingUsers(false)
    }
  }, [token, onToast])

  // Fetch Audit Logs
  const fetchAuditLogs = useCallback(async () => {
    if (!token) return
    setLoadingLogs(true)
    try {
      const params = new URLSearchParams()
      if (actionFilter !== 'ALL') params.append('action', actionFilter)
      if (searchFilter.trim()) params.append('search', searchFilter.trim())
      params.append('limit', '150')

      const res = await fetch(`/api/auth/audit-logs?${params.toString()}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setAuditLogs(data?.logs || [])
    } catch (err) {
      onToast(`Failed to load audit logs: ${err.message}`, 'error')
    } finally {
      setLoadingLogs(false)
    }
  }, [token, actionFilter, searchFilter, onToast])

  // Fetch System Status & Policy
  const fetchSystemData = useCallback(async () => {
    if (!token) return
    setLoadingSys(true)
    try {
      const [resStatus, resPol] = await Promise.all([
        fetch('/api/admin/status', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/admin/policy', { headers: { Authorization: `Bearer ${token}` } }),
      ])
      if (resStatus.ok) {
        const sData = await resStatus.json()
        setSysStatus(sData)
      }
      if (resPol.ok) {
        const pData = await resPol.json()
        setPolicy(pData)
      }
    } catch (err) {
      onToast(`Failed to load system telemetry: ${err.message}`, 'error')
    } finally {
      setLoadingSys(false)
    }
  }, [token, onToast])

  useEffect(() => {
    if (!isOpen) return
    if (activeTab === 'users') fetchUsers()
    else if (activeTab === 'audit') fetchAuditLogs()
    else if (activeTab === 'system') fetchSystemData()
  }, [isOpen, activeTab, fetchUsers, fetchAuditLogs, fetchSystemData])

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  // Handle user role change
  const handleRoleChange = async (userId, newRole) => {
    try {
      const res = await fetch(`/api/auth/users/${userId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ role: newRole }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data?.detail?.message || `HTTP ${res.status}`)
      }
      const updated = await res.json()
      setUsers((prev) => prev.map((u) => (u.id === userId ? updated : u)))
      onToast(`Updated role for ${updated.username} to ${newRole}`, 'success')
    } catch (err) {
      onToast(`Role update failed: ${err.message}`, 'error')
    }
  }

  // Handle user active toggle
  const handleToggleActive = async (userId, currentActive) => {
    try {
      const res = await fetch(`/api/auth/users/${userId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ is_active: !currentActive }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data?.detail?.message || `HTTP ${res.status}`)
      }
      const updated = await res.json()
      setUsers((prev) => prev.map((u) => (u.id === userId ? updated : u)))
      onToast(`User ${updated.username} is now ${updated.is_active ? 'Active' : 'Suspended'}`, 'info')
    } catch (err) {
      onToast(`Status toggle failed: ${err.message}`, 'error')
    }
  }

  // Handle user deletion
  const handleDeleteUser = async (userId, username) => {
    if (!window.confirm(`Are you sure you want to permanently delete user '${username}'?`)) return
    try {
      const res = await fetch(`/api/auth/users/${userId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data?.detail || data?.detail?.message || `HTTP ${res.status}`)
      }
      setUsers((prev) => prev.filter((u) => u.id !== userId))
      onToast(`User '${username}' deleted successfully`, 'info')
    } catch (err) {
      onToast(`Failed to delete user: ${err.message}`, 'error')
    }
  }

  // Handle add user form submission
  const handleCreateUser = async (e) => {
    e.preventDefault()
    setSubmittingUser(true)
    try {
      const res = await fetch('/api/auth/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(newUser),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data?.detail?.message || data?.detail || `HTTP ${res.status}`)
      }
      const created = await res.json()
      setUsers((prev) => [...prev, created])
      setShowAddUser(false)
      setNewUser({ username: '', email: '', password: '', full_name: '', role: 'analyst' })
      onToast(`User '${created.username}' provisioned successfully as ${created.role}`, 'success')
    } catch (err) {
      onToast(`User creation failed: ${err.message}`, 'error')
    } finally {
      setSubmittingUser(false)
    }
  }

  // Handle audit export
  const handleExportAudit = async (fmt) => {
    try {
      const res = await fetch(`/api/auth/audit-logs/export?format=${fmt}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit_logs_${Date.now()}.${fmt}`
      a.click()
      URL.revokeObjectURL(url)
      onToast(`Audit trail exported as ${fmt.toUpperCase()}`, 'success')
    } catch (err) {
      onToast(`Export failed: ${err.message}`, 'error')
    }
  }

  // Handle policy save
  const handleSavePolicy = async () => {
    if (!policy) return
    setSavingPolicy(true)
    try {
      const res = await fetch('/api/admin/policy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          min_acceptable_epi: parseFloat(policy.min_acceptable_epi),
          strict_rfc_enforcement: Boolean(policy.strict_rfc_enforcement),
          pqc_hybrid_warning: Boolean(policy.pqc_hybrid_warning),
          quarantine_critical_flows: Boolean(policy.quarantine_critical_flows),
        }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setPolicy(data.current_policy)
      onToast('Platform governance policy updated', 'success')
    } catch (err) {
      onToast(`Policy save failed: ${err.message}`, 'error')
    } finally {
      setSavingPolicy(false)
    }
  }

  // Handle bulk purge
  const handlePurgeCaptures = async () => {
    if (!window.confirm('Purge all synthetic test sample PCAP records from database? Real uploaded captures will remain.')) return
    try {
      const res = await fetch('/api/admin/history/purge?only_samples=true', {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      onToast(`Purged ${data.purged_count} test capture records`, 'info')
      fetchSystemData()
    } catch (err) {
      onToast(`Purge failed: ${err.message}`, 'error')
    }
  }

  if (!isOpen) return null

  return (
    <div className="admin-modal-overlay" onClick={onClose}>
      <div className="admin-modal-box" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="admin-modal-header">
          <div className="admin-modal-title">
            <div className="admin-modal-shield-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
            </div>
            <div>
              <h3>Platform Administration &amp; Governance</h3>
              <p>Role-Based Access Control, Regulatory Audit Trail, and Engine Governance</p>
            </div>
          </div>
          <button className="admin-modal-close" onClick={onClose} aria-label="Close">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6L6 18M6 6l12 12"/></svg>
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="admin-modal-tabs">
          <button
            type="button"
            className={`admin-modal-tab ${activeTab === 'users' ? 'admin-modal-tab--active' : ''}`}
            onClick={() => setActiveTab('users')}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
            User Management ({users.length})
          </button>
          <button
            type="button"
            className={`admin-modal-tab ${activeTab === 'audit' ? 'admin-modal-tab--active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
            Forensic Audit Trail
          </button>
          <button
            type="button"
            className={`admin-modal-tab ${activeTab === 'system' ? 'admin-modal-tab--active' : ''}`}
            onClick={() => setActiveTab('system')}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
            System &amp; Governance
          </button>
        </div>

        {/* Modal Body */}
        <div className="admin-modal-body">
          {/* TAB 1: USERS */}
          {activeTab === 'users' && (
            <div className="admin-tab-content fade-in">
              <div className="admin-actions-bar">
                <span className="admin-section-hint">
                  Manage platform operators, forensic analysts, and role authorizations.
                </span>
                <button
                  type="button"
                  className="btn-admin-primary"
                  onClick={() => setShowAddUser((prev) => !prev)}
                >
                  {showAddUser ? 'Cancel' : '+ Provision New User'}
                </button>
              </div>

              {/* Add User Form Drawer */}
              {showAddUser && (
                <form onSubmit={handleCreateUser} className="admin-add-user-form fade-in">
                  <h4>Provision New Operator Account</h4>
                  <div className="admin-form-grid">
                    <div>
                      <label>Username</label>
                      <input
                        type="text"
                        required
                        value={newUser.username}
                        onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                        placeholder="e.g. j_miller"
                      />
                    </div>
                    <div>
                      <label>Email Address</label>
                      <input
                        type="email"
                        required
                        value={newUser.email}
                        onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                        placeholder="operator@agency.gov"
                      />
                    </div>
                    <div>
                      <label>Password</label>
                      <input
                        type="password"
                        required
                        minLength={6}
                        value={newUser.password}
                        onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                        placeholder="Minimum 6 characters"
                      />
                    </div>
                    <div>
                      <label>Full Name</label>
                      <input
                        type="text"
                        value={newUser.full_name}
                        onChange={(e) => setNewUser({ ...newUser, full_name: e.target.value })}
                        placeholder="e.g. John Miller"
                      />
                    </div>
                    <div>
                      <label>Platform Role</label>
                      <select
                        value={newUser.role}
                        onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                      >
                        <option value="analyst">Analyst (Forensics &amp; Triage)</option>
                        <option value="admin">Admin (Full System Governance)</option>
                      </select>
                    </div>
                  </div>
                  <div style={{ marginTop: 12, textAlign: 'right' }}>
                    <button type="submit" className="btn-admin-primary" disabled={submittingUser}>
                      {submittingUser ? 'Provisioning...' : 'Confirm & Create Account'}
                    </button>
                  </div>
                </form>
              )}

              {/* Users Table */}
              {loadingUsers ? (
                <div className="admin-loading-state">Loading user directory...</div>
              ) : (
                <div className="admin-table-wrap">
                  <table className="admin-table">
                    <thead>
                      <tr>
                        <th>User</th>
                        <th>Email</th>
                        <th>Assigned Role</th>
                        <th>Status</th>
                        <th>Registered</th>
                        <th style={{ textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map((u) => {
                        const isSelf = u.id === currentUser?.id
                        return (
                          <tr key={u.id} className={isSelf ? 'admin-table-row--self' : ''}>
                            <td>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                                <span className="user-table-avatar">
                                  {u.username[0]?.toUpperCase()}
                                </span>
                                <div>
                                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                                    {u.username} {isSelf && <span className="admin-self-pill">(You)</span>}
                                  </div>
                                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                                    {u.full_name || 'No full name'}
                                  </div>
                                </div>
                              </div>
                            </td>
                            <td>{u.email}</td>
                            <td>
                              <select
                                className="admin-role-select"
                                value={u.role}
                                disabled={isSelf}
                                onChange={(e) => handleRoleChange(u.id, e.target.value)}
                              >
                                <option value="admin">Admin</option>
                                <option value="analyst">Analyst</option>
                              </select>
                            </td>
                            <td>
                              <button
                                type="button"
                                className={`admin-status-toggle ${u.is_active ? 'admin-status-toggle--active' : 'admin-status-toggle--suspended'}`}
                                disabled={isSelf}
                                onClick={() => handleToggleActive(u.id, u.is_active)}
                                title={isSelf ? 'Cannot deactivate self' : 'Click to toggle status'}
                              >
                                {u.is_active ? 'Active' : 'Suspended'}
                              </button>
                            </td>
                            <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                              {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <button
                                type="button"
                                className="btn-admin-del"
                                disabled={isSelf}
                                onClick={() => handleDeleteUser(u.id, u.username)}
                                title={isSelf ? 'Cannot delete your own account' : 'Delete user'}
                              >
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ display: 'inline', verticalAlign: 'middle', marginRight: 4 }} aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                                Delete
                              </button>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: AUDIT LOGS */}
          {activeTab === 'audit' && (
            <div className="admin-tab-content fade-in">
              <div className="admin-actions-bar">
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
                  <input
                    type="text"
                    className="admin-search-input"
                    placeholder="Search logs by keyword or resource..."
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                  />
                  <select
                    className="admin-action-filter"
                    value={actionFilter}
                    onChange={(e) => setActionFilter(e.target.value)}
                  >
                    <option value="ALL">All Actions</option>
                    <option value="USER_LOGIN">USER_LOGIN</option>
                    <option value="LOGIN_FAILED">LOGIN_FAILED</option>
                    <option value="USER_REGISTER">USER_REGISTER</option>
                    <option value="USER_CREATED">USER_CREATED</option>
                    <option value="USER_MODIFIED">USER_MODIFIED</option>
                    <option value="USER_DELETED">USER_DELETED</option>
                    <option value="ANALYZE_PCAP">ANALYZE_PCAP</option>
                    <option value="ANALYZE_SAMPLE">ANALYZE_SAMPLE</option>
                    <option value="TRIAGE_UPDATE">TRIAGE_UPDATE</option>
                    <option value="DELETE_ANALYSIS">DELETE_ANALYSIS</option>
                    <option value="POLICY_UPDATED">POLICY_UPDATED</option>
                    <option value="BULK_PURGE_HISTORY">BULK_PURGE_HISTORY</option>
                  </select>
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button
                    type="button"
                    className="btn-admin-ghost"
                    onClick={() => handleExportAudit('csv')}
                  >
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: 6 }}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    Export CSV
                  </button>
                  <button
                    type="button"
                    className="btn-admin-ghost"
                    onClick={() => handleExportAudit('json')}
                  >
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: 6 }}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    Export JSON
                  </button>
                </div>
              </div>

              {loadingLogs ? (
                <div className="admin-loading-state">Loading forensic audit trail...</div>
              ) : auditLogs.length === 0 ? (
                <div className="admin-empty-state">No audit logs matching query.</div>
              ) : (
                <div className="admin-table-wrap">
                  <table className="admin-table">
                    <thead>
                      <tr>
                        <th>Timestamp (UTC)</th>
                        <th>Actor</th>
                        <th>Action</th>
                        <th>Resource ID</th>
                        <th>IP Address</th>
                        <th>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLogs.map((log) => (
                        <tr key={log.id}>
                          <td style={{ fontSize: '0.72rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                            {log.timestamp ? new Date(log.timestamp).toLocaleString() : '—'}
                          </td>
                          <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                            {log.username || 'system'}
                          </td>
                          <td>
                            <span className={`admin-action-tag admin-action-tag--${log.action}`}>
                              {log.action}
                            </span>
                          </td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                            {log.resource_id || '—'}
                          </td>
                          <td style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                            {log.ip_address || '127.0.0.1'}
                          </td>
                          <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                            {log.details || '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: SYSTEM & GOVERNANCE */}
          {activeTab === 'system' && (
            <div className="admin-tab-content fade-in">
              {loadingSys ? (
                <div className="admin-loading-state">Reading telemetry and policy settings...</div>
              ) : (
                <>
                  {/* High Level KPI Cards */}
                  <div className="admin-kpi-grid">
                    <div className="admin-kpi-card">
                      <div className="admin-kpi-label">Forensic Engine Status</div>
                      <div className="admin-kpi-value admin-kpi-value--good">OPERATIONAL</div>
                      <div className="admin-kpi-sub">
                        Engine v{sysStatus?.engine_version || '1.0.0'} · Schema v{sysStatus?.schema_version || '2.0'}
                      </div>
                    </div>

                    <div className="admin-kpi-card">
                      <div className="admin-kpi-label">Total Analyses Run</div>
                      <div className="admin-kpi-value">
                        {sysStatus?.investigations?.total_analyses || 0}
                      </div>
                      <div className="admin-kpi-sub">
                        Critical: {sysStatus?.investigations?.by_tier?.CRITICAL || 0} │ High: {sysStatus?.investigations?.by_tier?.HIGH || 0}
                      </div>
                    </div>

                    <div className="admin-kpi-card">
                      <div className="admin-kpi-label">Registered Operators</div>
                      <div className="admin-kpi-value">
                        {sysStatus?.users?.total || 0}
                      </div>
                      <div className="admin-kpi-sub">
                        {sysStatus?.users?.active || 0} active │ {sysStatus?.users?.by_role?.admin || 0} Admins
                      </div>
                    </div>

                    <div className="admin-kpi-card">
                      <div className="admin-kpi-label">Database Footprint</div>
                      <div className="admin-kpi-value">
                        {((sysStatus?.storage?.database_size_bytes || 0) / (1024 * 1024)).toFixed(2)} MB
                      </div>
                      <div className="admin-kpi-sub">
                        {sysStatus?.audit_trail?.total_events || 0} audit events stored
                      </div>
                    </div>
                  </div>

                  {/* Governance Policy Configuration */}
                  {policy && (
                    <div className="admin-policy-box">
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                        <div>
                          <h4 style={{ margin: 0, fontSize: '0.95rem', color: 'var(--text-primary)' }}>
                            Platform Scoring &amp; Compliance Policy Tuning
                          </h4>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            Governs minimum posture compliance thresholds and enforcement flags.
                          </span>
                        </div>
                        <button
                          type="button"
                          className="btn-admin-primary"
                          disabled={savingPolicy}
                          onClick={handleSavePolicy}
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: 6 }}><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                          {savingPolicy ? 'Saving...' : 'Save Governance Policy'}
                        </button>
                      </div>

                      <div className="admin-policy-grid">
                        <div className="admin-policy-item">
                          <label>Minimum Acceptable Posture Index (EPI Threshold)</label>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <input
                              type="number"
                              min="0"
                              max="100"
                              step="5"
                              value={policy.min_acceptable_epi}
                              onChange={(e) => setPolicy({ ...policy, min_acceptable_epi: e.target.value })}
                            />
                            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                              / 100 (Sub-threshold captures are flagged for triage)
                            </span>
                          </div>
                        </div>

                        <div className="admin-policy-item">
                          <label>Strict RFC Compliance Enforcement</label>
                          <label className="admin-switch">
                            <input
                              type="checkbox"
                              checked={policy.strict_rfc_enforcement}
                              onChange={(e) => setPolicy({ ...policy, strict_rfc_enforcement: e.target.checked })}
                            />
                            <span>Strict RFC 8314 &amp; 9325 conformance</span>
                          </label>
                        </div>

                        <div className="admin-policy-item">
                          <label>Post-Quantum Cryptography (PQC) Warnings</label>
                          <label className="admin-switch">
                            <input
                              type="checkbox"
                              checked={policy.pqc_hybrid_warning}
                              onChange={(e) => setPolicy({ ...policy, pqc_hybrid_warning: e.target.checked })}
                            />
                            <span>Flag legacy flows lacking hybrid Kyber/ML-KEM</span>
                          </label>
                        </div>

                        <div className="admin-policy-item">
                          <label>Automated Critical Flow Quarantine Advisory</label>
                          <label className="admin-switch">
                            <input
                              type="checkbox"
                              checked={policy.quarantine_critical_flows}
                              onChange={(e) => setPolicy({ ...policy, quarantine_critical_flows: e.target.checked })}
                            />
                            <span>Issue automated firewall quarantine triggers</span>
                          </label>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Storage Maintenance */}
                  <div className="admin-danger-box">
                    <div>
                      <h4 style={{ margin: 0, color: 'var(--risk-critical)' }}>Database Maintenance</h4>
                      <p style={{ margin: '4px 0 0', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                        Remove test captures to optimize disk storage and database lookup performance.
                      </p>
                    </div>
                    <button
                      type="button"
                      className="btn-admin-danger"
                      onClick={handlePurgeCaptures}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: 6 }}><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                      Purge Test Captures
                    </button>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
