import { useState } from 'react'
import { ShieldCheck, User, Lock, Eye, EyeOff } from 'lucide-react'

function LoginForm({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPw,   setShowPw]   = useState(false)
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!username.trim() || !password) {
      setError('Ingresa tu usuario y contraseña.')
      return
    }
    setError('')
    setLoading(true)
    try {
      await onLogin({ username: username.trim(), password })
    } catch (err) {
      setError(err.message || 'Credenciales incorrectas o acceso denegado.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-card">
        {/* Logo + brand */}
        <div className="login-logo-wrap">
          <div className="login-logo-icon">
            <ShieldCheck size={26} strokeWidth={1.6} />
          </div>
          <p className="login-brand-title">SENTINEL</p>
          <p className="login-brand-sub">Kernel Security Monitor</p>
        </div>

        <hr className="login-divider" />

        {/* Form */}
        <form
          id="login-form"
          className="login-form"
          onSubmit={handleSubmit}
          noValidate
          autoComplete="on"
        >
          {/* Username */}
          <div className="field">
            <label htmlFor="login-user">Usuario</label>
            <div className="login-input-wrap">
              <span className="login-input-icon">
                <User size={15} strokeWidth={1.8} />
              </span>
              <input
                id="login-user"
                className="login-input"
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="nombre de usuario"
                disabled={loading}
              />
            </div>
          </div>

          {/* Password */}
          <div className="field">
            <label htmlFor="login-pass">Contraseña</label>
            <div className="login-input-wrap">
              <span className="login-input-icon">
                <Lock size={15} strokeWidth={1.8} />
              </span>
              <input
                id="login-pass"
                className="login-input"
                style={{ paddingRight: '42px' }}
                type={showPw ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                disabled={loading}
              />
              <button
                type="button"
                className="login-toggle-pw"
                onClick={() => setShowPw((v) => !v)}
                tabIndex={-1}
                aria-label={showPw ? 'Ocultar contraseña' : 'Mostrar contraseña'}
              >
                {showPw
                  ? <EyeOff size={15} strokeWidth={1.8} />
                  : <Eye    size={15} strokeWidth={1.8} />
                }
              </button>
            </div>
          </div>

          {/* Error message */}
          {error && (
            <div className="error-msg" role="alert">
              <Lock size={12} strokeWidth={2} />
              {error}
            </div>
          )}

          {/* Submit */}
          <button
            id="login-submit"
            type="submit"
            className="login-submit"
            disabled={loading}
          >
            {loading ? 'Verificando...' : 'Ingresar al sistema'}
          </button>
        </form>

        {/* Footer notice */}
        <div className="login-notice">
          <Lock size={11} strokeWidth={2} />
          <span>Acceso restringido — los intentos no autorizados son registrados</span>
        </div>
      </div>
    </div>
  )
}

export default LoginForm
