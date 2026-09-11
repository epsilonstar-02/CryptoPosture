import { useState, useEffect, useCallback } from 'react'

export default function AuthModal({ isOpen, onClose, onAuthSuccess, onToast }) {
  const [mode, setMode] = useState('login') // 'login' | 'register'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [loading, setLoading] = useState(false)
  const [errorMsg, setErrorMsg] = useState('')

  // Reset form when modal opens
  useEffect(() => {
    if (isOpen) {
      setErrorMsg('')
      setPassword('')
    }
  }, [isOpen, mode])

  // Close on ESC
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  const handleSubmit = useCallback(async (e) => {
    e.preventDefault()
    setErrorMsg('')
    setLoading(true)

    try {
      if (mode === 'login') {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: username.trim(), password }),
        })
        const data = await res.json()
        if (!res.ok) {
          throw new Error(data?.detail?.message || data?.detail || 'Authentication failed')
        }
        localStorage.setItem('auth_token', data.access_token)
        onAuthSuccess(data.user, data.access_token)
        onToast(`Signed in as ${data.user.username} (${data.user.role.toUpperCase()})`, 'success')
        onClose()
      } else {
        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: username.trim(),
            email: email.trim(),
            password,
            full_name: fullName.trim() || undefined,
          }),
        })
        const data = await res.json()
        if (!res.ok) {
          throw new Error(data?.detail?.message || data?.detail || 'Registration failed')
        }
        localStorage.setItem('auth_token', data.access_token)
        onAuthSuccess(data.user, data.access_token)
        onToast(`Registered as ${data.user.username} with role [${data.user.role.toUpperCase()}]`, 'success')
        onClose()
      }
    } catch (err) {
      setErrorMsg(err.message)
    } finally {
      setLoading(false)
    }
  }, [mode, username, password, email, fullName, onAuthSuccess, onToast, onClose])

  if (!isOpen) return null

  return (
    <div className="auth-modal-overlay" onClick={onClose}>
      <div className="auth-modal-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="auth-modal-header">
          <div className="auth-modal-brand">
            <span className="auth-modal-dot" />
            <h3>{mode === 'login' ? 'Analyst Authentication' : 'Create Forensic Account'}</h3>
          </div>
          <button className="auth-modal-close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        <div className="auth-modal-tabs">
          <button
            type="button"
            className={`auth-tab ${mode === 'login' ? 'auth-tab--active' : ''}`}
            onClick={() => setMode('login')}
          >
            Sign In
          </button>
          <button
            type="button"
            className={`auth-tab ${mode === 'register' ? 'auth-tab--active' : ''}`}
            onClick={() => setMode('register')}
          >
            Register
          </button>
        </div>

        {mode === 'register' && (
          <div className="auth-modal-note">
            ℹ️ The first user registered is automatically provisioned with the <strong>ADMIN</strong> role.
          </div>
        )}

        {errorMsg && (
          <div className="auth-modal-error">
            <span>⚠️</span> {errorMsg}
          </div>
        )}

        <form onSubmit={handleSubmit} className="auth-modal-form">
          <div className="auth-form-field">
            <label>Username</label>
            <input
              type="text"
              required
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. j_doe"
              autoComplete="username"
            />
          </div>

          {mode === 'register' && (
            <>
              <div className="auth-form-field">
                <label>Email Address</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@agency.gov"
                  autoComplete="email"
                />
              </div>
              <div className="auth-form-field">
                <label>Full Name (Optional)</label>
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Jane Doe"
                  autoComplete="name"
                />
              </div>
            </>
          )}

          <div className="auth-form-field">
            <label>Password</label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            />
          </div>

          <button type="submit" className="auth-submit-btn" disabled={loading}>
            {loading ? 'Authenticating...' : mode === 'login' ? 'Authenticate & Sign In' : 'Create Account'}
          </button>
        </form>
      </div>
    </div>
  )
}
