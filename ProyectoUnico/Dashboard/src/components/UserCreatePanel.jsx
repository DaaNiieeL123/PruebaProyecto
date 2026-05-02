import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  Eye,
  EyeOff,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  ShieldPlus,
  Trash2,
  UserRoundPlus,
  Users,
  X,
} from 'lucide-react'

function UserCreatePanel({ role, onCreateUser, onListUsers, onDeleteUser }) {
  const [form, setForm] = useState({
    username: '',
    password: '',
    confirmPassword: '',
    role: 'common',
  })
  const [loading, setLoading] = useState(false)
  const [toast, setToast] = useState(null)
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [users, setUsers] = useState([])
  const [listLoading, setListLoading] = useState(true)
  const [deleteBusy, setDeleteBusy] = useState('')
  const [confirmDeleteUser, setConfirmDeleteUser] = useState(null)

  if (role !== 'admin') {
    return (
      <section className="card panel">
        <h3>Creación de usuarios</h3>
        <p>Disponible solo para administradores.</p>
      </section>
    )
  }

  const updateField = (key, value) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  const showToast = (type, message) => {
    setToast({ type, message })
  }

  const roleMeta = useMemo(() => {
    if (form.role === 'admin') {
      return {
        label: 'Administrador',
        group: 'admin_user',
        accent: 'is-admin',
        summary: 'Acceso total al panel, controles operativos, consulta de procesos y administración del sistema.',
      }
    }

    return {
      label: 'Usuario común',
      group: 'common_user',
      accent: 'is-common',
      summary: 'Acceso de solo lectura para monitoreo, alertas, archivos observados y eventos de seguridad.',
    }
  }, [form.role])

  const usernamePreview = form.username.trim() || 'usuario_nuevo'

  const passwordStrength = useMemo(() => {
    const pw = form.password
    let score = 0
    if (pw.length >= 8) score++
    if (/[A-Z]/.test(pw)) score++
    if (/[a-z]/.test(pw)) score++
    if (/\d/.test(pw)) score++

    if (score <= 1) {
      return { label: 'Baja', className: 'is-weak', fill: 34, activeIndex: 0 }
    }
    if (score <= 3) {
      return { label: 'Media', className: 'is-medium', fill: 68, activeIndex: 1 }
    }
    return { label: 'Alta', className: 'is-strong', fill: 100, activeIndex: 2 }
  }, [form.password])

  const groupedUsers = useMemo(() => {
    const admins = users
      .filter((item) => item.role === 'admin')
      .sort((a, b) => a.username.localeCompare(b.username))
    const common = users
      .filter((item) => item.role === 'common')
      .sort((a, b) => a.username.localeCompare(b.username))
    return { admins, common }
  }, [users])

  const loadUsers = async () => {
    setListLoading(true)
    try {
      const data = await onListUsers()
      setUsers(data?.items || [])
    } catch (err) {
      showToast('err', err.message || 'No se pudo obtener el listado de usuarios.')
    } finally {
      setListLoading(false)
    }
  }

  useEffect(() => {
    loadUsers()
  }, [])

  useEffect(() => {
    if (!toast) {
      return undefined
    }

    const timer = setTimeout(() => setToast(null), 3200)
    return () => clearTimeout(timer)
  }, [toast])

  const validate = () => {
    const username = form.username.trim()
    if (!/^[A-Za-z][A-Za-z0-9_-]{2,31}$/.test(username)) {
      return 'El usuario debe iniciar con letra y tener 3 a 32 caracteres.'
    }
    if (form.password.length < 8) {
      return 'La contraseña debe tener al menos 8 caracteres.'
    }
    if (!/^[!-~]+$/.test(form.password) || form.password.includes(':')) {
      return "La contraseña solo puede usar caracteres ASCII visibles y no debe incluir ':'."
    }
    if (form.password !== form.confirmPassword) {
      return 'Las contraseñas no coinciden.'
    }
    if (!['admin', 'common'].includes(form.role)) {
      return 'Seleccione un rol válido.'
    }
    return ''
  }

  const handleSubmit = async () => {
    const error = validate()
    if (error) {
      showToast('err', error)
      return
    }

    setLoading(true)
    setToast(null)
    try {
      const data = await onCreateUser({
        username: form.username.trim(),
        password: form.password,
        role: form.role,
      })
      setForm({
        username: '',
        password: '',
        confirmPassword: '',
        role: 'common',
      })
      setShowPassword(false)
      setShowConfirmPassword(false)
      showToast('ok', data?.message || `Usuario ${data?.username || ''} creado correctamente.`)
      await loadUsers()
    } catch (err) {
      showToast('err', err.message || 'No se pudo crear el usuario.')
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (username) => {
    setDeleteBusy(username)
    setToast(null)
    try {
      const data = await onDeleteUser(username)
      showToast('ok', data?.message || `Usuario ${username} eliminado correctamente.`)
      setConfirmDeleteUser(null)
      await loadUsers()
    } catch (err) {
      showToast('err', err.message || `No se pudo eliminar ${username}.`)
    } finally {
      setDeleteBusy('')
    }
  }

  const renderUserList = (title, items, toneClass) => (
    <section className="card panel user-list-card">
      <div className="panel-header">
        <h3>{title}</h3>
        <span className={`user-list-badge ${toneClass}`}>{items.length}</span>
      </div>

      <div className="user-list-stack">
        {!items.length && (
          <div className="user-list-empty">No hay usuarios en esta categoría.</div>
        )}

        {items.map((item) => (
          <div key={`${item.role}-${item.username}`} className="user-row">
            <div className="user-row-main">
              <div className={`user-row-avatar ${item.role === 'admin' ? 'is-admin' : 'is-common'}`}>
                {item.username.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <div className="user-row-title">
                  <strong>{item.username}</strong>
                  {item.self && <span className="user-row-tag">Tú</span>}
                  {item.protected && !item.self && <span className="user-row-tag is-protected">Protegido</span>}
                </div>
                <p>
                  {item.role === 'admin' ? 'Administrador' : 'Usuario común'}
                  {item.protected_reason ? ` · ${item.protected_reason}` : ''}
                </p>
              </div>
            </div>

            <button
              className="danger user-delete-btn"
              disabled={item.protected || deleteBusy === item.username}
              onClick={() => setConfirmDeleteUser(item)}
              title={item.protected ? (item.protected_reason || 'Usuario protegido') : `Eliminar ${item.username}`}
            >
              <Trash2 size={14} strokeWidth={1.9} />
              {deleteBusy === item.username ? 'Eliminando...' : 'Eliminar'}
            </button>
          </div>
        ))}
      </div>
    </section>
  )

  return (
    <section className="user-admin-shell">
      {toast && (
        <div className={`export-toast export-toast--${toast.type}`} role="status">
          <span>{toast.type === 'ok' ? '✓' : '✕'}</span>
          {toast.message}
        </div>
      )}

      <div className="user-admin-head">
        <div>
          <p className="user-admin-eyebrow">Administración de acceso</p>
          <h2>Crear y administrar usuarios</h2>
          <p>
            Gestiona cuentas Linux desde la interfaz, asígnales rol y mantén el acceso operativo centralizado sin depender de consola.
          </p>
        </div>
        <div className="user-admin-chip">
          <ShieldCheck size={14} strokeWidth={1.9} />
          Solo administrador
        </div>
      </div>

      <div className="user-admin-grid">
        <div className="user-column-stack">
          <section className="card panel user-creator-card">
            <div className="user-creator-hero">
              <div className="user-creator-hero-icon">
                <UserRoundPlus size={18} strokeWidth={1.9} />
              </div>
              <div>
                <h3>Nueva cuenta</h3>
                <p>Registra credenciales, define privilegios y deja la cuenta lista para autenticación inmediata.</p>
              </div>
            </div>

            <div className="user-creator-form-grid">
              <label>
                Usuario
                <div className="user-field-wrap">
                  <span className="user-field-icon">
                    <Users size={15} strokeWidth={1.9} />
                  </span>
                  <input
                    value={form.username}
                    onChange={(e) => updateField('username', e.target.value)}
                    placeholder="Ej: analista_ops"
                    autoComplete="off"
                  />
                </div>
              </label>

              <label>
                Rol
                <select
                  value={form.role}
                  onChange={(e) => updateField('role', e.target.value)}
                >
                  <option value="common">Usuario común</option>
                  <option value="admin">Administrador</option>
                </select>
              </label>

              <label>
                Contraseña
                <div className="user-field-wrap">
                  <span className="user-field-icon">
                    <KeyRound size={15} strokeWidth={1.9} />
                  </span>
                  <input
                    value={form.password}
                    onChange={(e) => updateField('password', e.target.value)}
                    placeholder="Mínimo 8 caracteres"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                  />
                  <button
                    type="button"
                    className="user-field-toggle"
                    onClick={() => setShowPassword((v) => !v)}
                    aria-label={showPassword ? 'Ocultar contraseña' : 'Mostrar contraseña'}
                  >
                    {showPassword
                      ? <EyeOff size={15} strokeWidth={1.9} />
                      : <Eye size={15} strokeWidth={1.9} />
                    }
                  </button>
                </div>
              </label>

              <label>
                Confirmar contraseña
                <div className="user-field-wrap">
                  <span className="user-field-icon">
                    <ShieldPlus size={15} strokeWidth={1.9} />
                  </span>
                  <input
                    value={form.confirmPassword}
                    onChange={(e) => updateField('confirmPassword', e.target.value)}
                    placeholder="Repite la contraseña"
                    type={showConfirmPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                  />
                  <button
                    type="button"
                    className="user-field-toggle"
                    onClick={() => setShowConfirmPassword((v) => !v)}
                    aria-label={showConfirmPassword ? 'Ocultar confirmación' : 'Mostrar confirmación'}
                  >
                    {showConfirmPassword
                      ? <EyeOff size={15} strokeWidth={1.9} />
                      : <Eye size={15} strokeWidth={1.9} />
                    }
                  </button>
                </div>
              </label>
            </div>

            <div className="user-password-meter">
              <span>Fortaleza de contraseña</span>
              <div className="user-password-meter-main">
                <div className="user-password-meter-bar">
                  <div
                    className={`user-password-meter-fill ${passwordStrength.className}`}
                    style={{ width: `${passwordStrength.fill}%` }}
                  />
                </div>
                <div className="user-password-scale">
                  {['Baja', 'Media', 'Alta'].map((label, index) => (
                    <span
                      key={label}
                      className={`user-password-scale-pill ${
                        index === passwordStrength.activeIndex ? `is-active ${passwordStrength.className}` : ''
                      }`}
                    >
                      {label}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="user-creator-actions">
              <button onClick={handleSubmit} disabled={loading}>
                <ShieldPlus size={15} strokeWidth={1.9} />
                {loading ? 'Creando usuario...' : 'Crear usuario'}
              </button>
              <p>
                El sistema agregará esta cuenta al grupo <strong>{roleMeta.group}</strong>.
              </p>
            </div>
          </section>

          {renderUserList('Administradores', groupedUsers.admins, 'is-admin')}
        </div>

        <aside className="user-side-stack">
          <section className={`card panel user-preview-card ${roleMeta.accent}`}>
            <div className="user-preview-top">
              <span className="user-preview-badge">{roleMeta.label}</span>
              <span className="user-preview-group">{roleMeta.group}</span>
            </div>

            <div className="user-preview-identity">
              <div className="user-preview-avatar">
                {usernamePreview.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <h3>{usernamePreview}</h3>
                <p>{roleMeta.summary}</p>
              </div>
            </div>

            <div className="user-preview-credentials">
              <div>
                <span>Login PAM</span>
                <strong>{usernamePreview}</strong>
              </div>
              <div>
                <span>Acceso</span>
                <strong>{roleMeta.label}</strong>
              </div>
            </div>
          </section>

          <section className="card panel user-guide-card">
            <div className="panel-header">
              <h3>Usuarios administrados</h3>
              <button
                className="secondary user-refresh-btn"
                onClick={loadUsers}
                disabled={listLoading}
              >
                <RefreshCw size={14} strokeWidth={1.9} className={listLoading ? 'spin' : ''} />
                {listLoading ? 'Actualizando...' : 'Actualizar'}
              </button>
            </div>
            <p>Supervisa las cuentas asociadas a los perfiles operativos del sistema y aplica limpieza controlada cuando sea necesario.</p>
            <ul className="user-guide-list">
              <li>Usa nombres claros y consistentes según el rol operativo de cada cuenta.</li>
              <li>Reserva privilegios administrativos solo para usuarios que realmente lo necesiten.</li>
              <li>Elimina cuentas temporales o de prueba cuando dejen de ser necesarias.</li>
            </ul>
          </section>

          {renderUserList('Usuarios comunes', groupedUsers.common, 'is-common')}
        </aside>
      </div>

      {confirmDeleteUser && (
        <div className="modal-overlay" role="dialog" aria-modal="true">
          <div className="modal-content user-confirm-modal">
            <button className="modal-close" onClick={() => setConfirmDeleteUser(null)}>
              <X size={18} strokeWidth={2} />
            </button>

            <div className="modal-header">
              <div
                className="modal-icon-wrap"
                style={{ color: '#fca5a5', backgroundColor: 'rgba(239, 68, 68, 0.12)' }}
              >
                <AlertTriangle size={24} strokeWidth={2} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 600, color: '#f8fafc' }}>
                  Confirmar eliminación
                </h3>
                <span style={{ fontSize: '0.85rem', color: 'var(--subtle)' }}>
                  Esta acción eliminará la cuenta del sistema y su directorio personal.
                </span>
              </div>
            </div>

            <div className="modal-body">
              <div className="user-confirm-copy">
                <p>
                  Vas a eliminar a <strong>{confirmDeleteUser.username}</strong> del grupo{' '}
                  <strong>{confirmDeleteUser.role === 'admin' ? 'admin_user' : 'common_user'}</strong>.
                </p>
                <p>Esta operación es irreversible desde la interfaz.</p>
              </div>
            </div>

            <div className="user-confirm-actions">
              <button
                className="secondary"
                onClick={() => setConfirmDeleteUser(null)}
                disabled={deleteBusy === confirmDeleteUser.username}
              >
                Cancelar
              </button>
              <button
                className="danger"
                onClick={() => handleDelete(confirmDeleteUser.username)}
                disabled={deleteBusy === confirmDeleteUser.username}
              >
                <Trash2 size={14} strokeWidth={1.9} />
                {deleteBusy === confirmDeleteUser.username ? 'Eliminando...' : 'Sí, eliminar usuario'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

export default UserCreatePanel
