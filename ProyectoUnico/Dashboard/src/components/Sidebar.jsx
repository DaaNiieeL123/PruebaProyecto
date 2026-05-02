import { useState } from 'react'
import {
  LayoutDashboard,
  Bell,
  FolderSearch,
  ShieldAlert,
  Settings2,
  ShieldCheck,
  UserRoundPlus,
  LogOut,
} from 'lucide-react'

/* ── Constants ── */
const MIN_W       = 60      // icon-only strip
const MAX_W       = 340     // maximum expanded
const DEFAULT_W   = 230     // default
const SNAP_THRESH = 110     // below this → collapse to MIN_W

/* ── Tab definitions ── */
const TABS = [
  { id: 'dashboard', label: 'Dashboard', Icon: LayoutDashboard },
  { id: 'alerts',    label: 'Alertas',   Icon: Bell,         badgeKey: 'high'       },
  { id: 'files',     label: 'Archivos',  Icon: FolderSearch, badgeKey: 'quarantine'  },
  { id: 'threats',   label: 'Amenazas',  Icon: ShieldAlert,  badgeKey: 'threats'     },
  { id: 'controls',  label: 'Controles', Icon: Settings2,    adminOnly: true          },
  { id: 'users',     label: 'Usuarios',  Icon: UserRoundPlus, adminOnly: true         },
]

function Sidebar({
  activeTab,
  onTabChange,
  username = '',
  role = 'common',
  onLogout,
  highCount = 0,
  quarantineCount = 0,
  threatsCount = 0,
}) {
  const [width,    setWidth]    = useState(DEFAULT_W)
  const [dragging, setDragging] = useState(false)

  const isAdmin     = role === 'admin'
  const initials    = (username || 'U').slice(0, 2).toUpperCase()
  const isCollapsed = width < SNAP_THRESH

  const badges = {
    high:       highCount,
    quarantine: quarantineCount,
    threats:    threatsCount,
  }

  /* ── Drag-to-resize ── */
  const handleDragStart = (e) => {
    e.preventDefault()

    const startX = e.clientX
    const startW = width

    setDragging(true)
    document.body.style.cursor      = 'col-resize'
    document.body.style.userSelect  = 'none'

    const onMove = (e) => {
      const next = Math.min(MAX_W, Math.max(MIN_W, startW + (e.clientX - startX)))
      setWidth(next)
    }

    const onUp = () => {
      setDragging(false)
      document.body.style.cursor     = ''
      document.body.style.userSelect = ''
      // Snap: if let go below threshold, collapse fully
      setWidth(prev => (prev < SNAP_THRESH ? MIN_W : prev))
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
    }

    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }

  /* ── Double-click handle → toggle collapsed / default ── */
  const toggleCollapse = () => {
    setWidth(prev => (prev <= MIN_W + 5 ? DEFAULT_W : MIN_W))
  }

  return (
    <aside
      className={`sidebar${isCollapsed ? ' sidebar--collapsed' : ''}`}
      style={{
        width,
        minWidth: MIN_W,
        maxWidth: MAX_W,
        /* No transition while actively dragging */
        transition: dragging ? 'none' : 'width 0.22s cubic-bezier(0.4,0,0.2,1)',
      }}
      aria-label="Navegación principal"
    >
      {/* ── Brand ── */}
      <div className="sidebar-brand">
        <div className="sidebar-logo">
          <ShieldCheck size={18} strokeWidth={1.8} />
        </div>
        <div className="sidebar-brand-text">
          <p className="sidebar-brand-name">SENTINEL</p>
          <p className="sidebar-brand-sub">Kernel Monitor</p>
        </div>
      </div>

      {/* ── Navigation ── */}
      <nav className="sidebar-nav" aria-label="Secciones">
        <span className="sidebar-nav-label">Módulos</span>

        {TABS.map(({ id, label, Icon, adminOnly, badgeKey }) => {
          if (adminOnly && !isAdmin) return null

          const isActive = activeTab === id
          const count    = badgeKey ? (badges[badgeKey] || 0) : 0

          return (
            <button
              key={id}
              id={`nav-${id}`}
              className={`sidebar-item${isActive ? ' sidebar-item--active' : ''}`}
              onClick={() => onTabChange(id)}
              aria-current={isActive ? 'page' : undefined}
              /* Native tooltip when collapsed */
              title={isCollapsed ? label : undefined}
            >
              <span className="sidebar-item-icon">
                <Icon size={16} strokeWidth={isActive ? 2 : 1.8} />
              </span>
              <span className="sidebar-item-label">{label}</span>
              {count > 0 && (
                <span className="sidebar-nav-badge" aria-label={`${count} alertas`}>
                  {count}
                </span>
              )}
            </button>
          )
        })}
      </nav>

      {/* ── User footer ── */}
      <div className="sidebar-user">
        <div className="sidebar-avatar" aria-hidden="true" title={isCollapsed ? username : undefined}>
          {initials}
        </div>
        <div className="sidebar-user-info">
          <p className="sidebar-username">{username}</p>
          <p className="sidebar-role">{isAdmin ? 'Administrador' : 'Usuario estándar'}</p>
        </div>
        <button
          className="sidebar-logout"
          onClick={onLogout}
          title="Cerrar sesión"
          aria-label="Cerrar sesión"
        >
          <LogOut size={14} strokeWidth={1.8} />
        </button>
      </div>

      {/* ── Resize handle (right edge) ── */}
      <div
        className={`sidebar-resize-handle${dragging ? ' sidebar-resize-handle--active' : ''}`}
        onMouseDown={handleDragStart}
        onDoubleClick={toggleCollapse}
        role="separator"
        aria-label="Redimensionar menú lateral"
        title="Arrastra para cambiar el ancho · Doble clic para colapsar"
      />
    </aside>
  )
}

export default Sidebar
