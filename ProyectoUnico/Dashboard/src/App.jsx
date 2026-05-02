import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Bar, BarChart, CartesianGrid, Cell,
  Legend, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { Download } from 'lucide-react'
import { API_BASE, POLL_INTERVAL_MS } from './config'
import LoginForm      from './components/LoginForm'
import Sidebar        from './components/Sidebar'
import MetricCards    from './components/MetricCards'
import AlertsPanel    from './components/AlertsPanel'
import FilesPanel     from './components/FilesPanel'
import ThreatsPanel   from './components/ThreatsPanel'
import ScanControl    from './components/ScanControl'
import ProcessLookup  from './components/ProcessLookup'
import KernelPanicBanner from './components/KernelPanicBanner'
import UserCreatePanel from './components/UserCreatePanel'
import './styles/global.css'

const HISTORY_LIMIT = 24

/* ── Tab metadata ── */
const TAB_META = {
  dashboard: { title: 'Dashboard',  sub: 'Métricas del sistema en tiempo real' },
  alerts:    { title: 'Alertas',    sub: 'Registro de eventos de seguridad' },
  files:     { title: 'Archivos',   sub: 'Integridad y estado del sistema de archivos' },
  threats:   { title: 'Amenazas',   sub: 'Firmas detectadas por hash blacklist' },
  controls:  { title: 'Controles', sub: 'Gestión del daemon y consulta de procesos' },
  users:     { title: 'Usuarios',   sub: 'Alta de cuentas del sistema y asignación de roles' },
}

/* ── Custom recharts tooltip styling ── */
const chartTooltipStyle = {
  backgroundColor: '#21213a',
  border: '1px solid #3a3a58',
  borderRadius: 8,
  fontSize: '0.82rem',
  color: '#ffffff',
  boxShadow: '0 8px 28px rgba(0,0,0,0.5)',
  padding: '8px 12px',
}

/* recharts ignores `color` on contentStyle for item text — must pass separately */
const chartItemStyle  = { color: '#ffffff', fontWeight: 600 }
const chartLabelStyle = { color: '#8c8ca8', marginBottom: 2, fontSize: '0.75rem' }

/* Formatters for chart tooltips */
const fmtKbTooltip    = (v) => [`${(Number(v) / 1048576).toFixed(2)} GB`]
const fmtGbTooltip    = (v) => [`${Number(v).toFixed(2)} GB`]
const fmtCountTooltip = (v) => [Number(v).toLocaleString()]


/* ── Memory bar for process table ── */
function MemoryBar({ pct }) {
  const clamped = Math.min(100, Math.max(0, Number(pct) || 0))
  return (
    <div className="memory-bar-wrap">
      <div className="memory-bar">
        <div
          className="memory-bar-fill"
          style={{ width: `${clamped}%` }}
        />
      </div>
      <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--subtle)', minWidth: 42 }}>
        {clamped.toFixed(1)}%
      </span>
    </div>
  )
}

/* ══════════════════════════════════════════════
   Main App
   ══════════════════════════════════════════════ */
function App() {
  /* Auth state — persisted in localStorage */
  const [auth, setAuth] = useState(() => {
    try { return JSON.parse(localStorage.getItem('sentinel_auth') || 'null') }
    catch { return null }
  })

  /* Data state */
  const [metrics,     setMetrics]     = useState({})
  const [alerts,      setAlerts]      = useState([])
  const [files,       setFiles]       = useState([])
  const [threats,     setThreats]     = useState([])
  const [me,          setMe]          = useState({ role: auth?.role || 'common', scan_enabled: true, username: auth?.username || '' })
  const [history,     setHistory]     = useState([])
  const [processData, setProcessData] = useState(null)
  const [activeTab,   setActiveTab]   = useState('dashboard')
  const prevFaultsRef = useRef({ menores: 0, mayores: 0 })

  /* ── Live clock ── */
  const [now, setNow] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const fmtTime = (d) =>
    d.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
  const fmtDate = (d) =>
    d.toLocaleDateString('es-ES', { weekday: 'short', day: 'numeric', month: 'short' })

  /* ── API helper ── */
  const callApi = async (path, options = {}) => {
    const headers = {
      'Content-Type': 'application/json',
      ...(auth?.token ? { Authorization: `Bearer ${auth.token}` } : {}),
      ...(options.headers || {}),
    }
    const res  = await fetch(`${API_BASE}${path}`, { ...options, headers })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) {
      const err = new Error(data.message || 'Error de API')
      err.status = res.status
      throw err
    }
    return data
  }

  /* ── Login / Logout ── */
  const handleLogin = async ({ username, password }) => {
    const data = await fetch(`${API_BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    }).then(async (res) => {
      const payload = await res.json()
      if (!res.ok) throw new Error(payload.message || 'Credenciales inválidas')
      return payload
    })
    const nextAuth = { token: data.token, username: data.username, role: data.role }
    setAuth(nextAuth)
    localStorage.setItem('sentinel_auth', JSON.stringify(nextAuth))
  }

  const handleLogout = () => {
    localStorage.removeItem('sentinel_auth')
    setAuth(null)
    setMetrics({}); setAlerts([]); setFiles([]); setThreats([])
    setHistory([]); setProcessData(null)
  }

  /* ── Polling ── */
  useEffect(() => {
    if (!auth?.token) return
    let cancelled = false

    const fetchAll = async () => {
      try {
        const [nextMetrics, nextAlerts, nextFiles, nextThreats, nextMe] = await Promise.all([
          callApi('/api/metrics'),
          callApi('/api/alerts'),
          callApi('/api/files'),
          callApi('/api/threats'),
          callApi('/api/me'),
        ])
        if (cancelled) return

        setMetrics(nextMetrics)
        setAlerts(nextAlerts.items   || [])
        setFiles(nextFiles.items     || [])
        setThreats(nextThreats.items || [])
        setMe(nextMe)

        const prev = prevFaultsRef.current
        const menoresDelta = Math.max(0, (nextMetrics.fallos_menores || 0) - (prev.menores || 0))
        const mayoresDelta = Math.max(0, (nextMetrics.fallos_mayores || 0) - (prev.mayores || 0))
        prevFaultsRef.current = {
          menores: nextMetrics.fallos_menores || 0,
          mayores: nextMetrics.fallos_mayores || 0,
        }

        setHistory((old) => {
          const point = {
            time:              new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            memoria_usada_gb:  ((nextMetrics.memoria_usada || 0) / 1048576).toFixed(2),
            swap_usada_gb:     ((nextMetrics.swap_usada    || 0) / 1048576).toFixed(2),
            fallos_menores_delta: menoresDelta,
            fallos_mayores_delta: mayoresDelta,
          }
          const merged = [...old, point]
          return merged.length > HISTORY_LIMIT ? merged.slice(-HISTORY_LIMIT) : merged
        })
      } catch (err) {
        if (err?.status === 401) {
          handleLogout()
          return
        }
        console.error('[Sentinel] fetch error:', err)
      }
    }

    fetchAll()
    const timer = setInterval(fetchAll, POLL_INTERVAL_MS)
    return () => { cancelled = true; clearInterval(timer) }
  }, [auth?.token])

  /* ── Chart data ── */
  const memoryPie = useMemo(() => [
    { name: 'Usada',  value: Number(metrics.memoria_usada  || 0) },
    { name: 'Libre',  value: Number(metrics.memoria_libre  || 0) },
    { name: 'Caché',  value: Number(metrics.memoria_cache  || 0) },
  ], [metrics.memoria_usada, metrics.memoria_libre, metrics.memoria_cache])

  const pageStatusPie = useMemo(() => [
    { name: 'Activas',   value: Number(metrics.paginas_activas  || 0) },
    { name: 'Inactivas', value: Number(metrics.paginas_inactivas || 0) },
  ], [metrics.paginas_activas, metrics.paginas_inactivas])

  /* ── Scan actions ── */
  const doScanToggle = async (enabled) => {
    await callApi(enabled ? '/api/scan/start' : '/api/scan/stop', { method: 'POST' })
    const nextMe = await callApi('/api/me')
    setMe(nextMe)
  }
  const doScanOnce = async () => callApi('/api/scan/once', { method: 'POST' })

  /* ── Export report ── */
  const [exportBusy,  setExportBusy]  = useState(false)
  const [exportToast, setExportToast] = useState(null) // { type: 'ok'|'err', msg }

  const showToast = (type, msg) => {
    setExportToast({ type, msg })
    setTimeout(() => setExportToast(null), 3500)
  }

  const exportSummaryReport = async () => {
    if (exportBusy) return
    setExportBusy(true)
    try {
      const report = await callApi('/api/report/summary')
      const stamp  = new Date().toISOString().replace(/[:.]/g, '-')
      const blob   = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
      const url    = URL.createObjectURL(blob)
      const a      = Object.assign(document.createElement('a'), { href: url, download: `sentinel_report_${stamp}.json` })
      a.click()
      URL.revokeObjectURL(url)
      showToast('ok', `Reporte descargado: sentinel_report_${stamp}.json`)
    } catch (err) {
      showToast('err', `Error al exportar: ${err.message || 'No se pudo conectar con el backend'}`)
    } finally {
      setExportBusy(false)
    }
  }

  /* ── Process lookup ── */
  const lookupPid = async (pid) => {
    const data = await callApi(`/api/process?pid=${pid}`)
    setProcessData(data)
  }

  const createSystemUser = async ({ username, password, role }) => (
    callApi('/api/admin/users/create', {
      method: 'POST',
      body: JSON.stringify({ username, password, role }),
    })
  )

  const listSystemUsers = async () => callApi('/api/admin/users')

  const deleteSystemUser = async (username) => (
    callApi('/api/admin/users/delete', {
      method: 'POST',
      body: JSON.stringify({ username }),
    })
  )

  /* ── Derived counts for sidebar badges ── */
  const highCount       = alerts.filter((a) => a.severidad?.toUpperCase() === 'HIGH').length
  const quarantineCount = files.filter((f) => (f.estado || '').toLowerCase() === 'cuarentena').length
  const role            = me.role || auth?.role || 'common'
  const scanEnabled     = Boolean(me.scan_enabled)

  /* ══════════════════════════════════════════════ */
  if (!auth?.token) return <LoginForm onLogin={handleLogin} />

  const tabMeta = TAB_META[activeTab] || TAB_META.dashboard

  return (
    <div className="app-layout">
      {/* ── Sidebar ── */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        username={me.username || auth.username}
        role={role}
        onLogout={handleLogout}
        highCount={highCount}
        quarantineCount={quarantineCount}
        threatsCount={threats.length}
      />

      {/* ── Main area ── */}
      <div className="main-area">
        {/* Kernel panic overlay — sits above everything */}
        <KernelPanicBanner alerts={alerts} />

        {/* Top header strip */}
        <header className="main-header">
          <div className="main-header-left">
            <h1>{tabMeta.title}</h1>
            <p>{tabMeta.sub}</p>
          </div>
          <div className="main-header-right">
            {/* Live clock */}
            <div className="header-clock">
              <span className="header-clock-time mono">{fmtTime(now)}</span>
              <span className="header-clock-date">{fmtDate(now)}</span>
            </div>

            <div className={`scan-pill${scanEnabled ? ' scan-pill--active' : ''}`}>
              <span className="scan-dot-sm" />
              {scanEnabled ? 'Escaneo activo' : 'Escaneo detenido'}
            </div>
            <button
              id="btn-export"
              className={`secondary btn-export${exportBusy ? ' btn-export--busy' : ''}`}
              style={{ fontSize: '0.8rem', padding: '6px 12px' }}
              onClick={exportSummaryReport}
              disabled={exportBusy}
              title="Exportar reporte del sistema en JSON"
            >
              {exportBusy
                ? <span className="export-spinner" aria-label="Exportando..." />
                : <Download size={13} strokeWidth={1.8} />
              }
              {exportBusy ? 'Exportando...' : 'Exportar'}
            </button>
          </div>
        </header>

        {/* Export toast notification */}
        {exportToast && (
          <div className={`export-toast export-toast--${exportToast.type}`} role="status">
            <span>{exportToast.type === 'ok' ? '✓' : '✕'}</span>
            {exportToast.msg}
          </div>
        )}

        {/* Scrollable content */}
        <main className="main-content">

          {/* ══ DASHBOARD TAB ══ */}
          {activeTab === 'dashboard' && (
            <div className="grid" style={{ gap: 20 }}>
              {/* Metric cards row */}
              <MetricCards metrics={metrics} />

              {/* Charts row 1 */}
              <div className="grid two-col">
                <div className="card chart-card">
                  <h3>Uso de memoria en el tiempo</h3>
                  <ResponsiveContainer width="100%" height={240}>
                    <LineChart data={history}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#26263a" />
                      <XAxis dataKey="time" stroke="#515168" tick={{ fontSize: 10 }} interval="preserveEnd" />
                      <YAxis stroke="#515168" tick={{ fontSize: 10 }} />
                      <Tooltip
                        contentStyle={chartTooltipStyle}
                        itemStyle={chartItemStyle}
                        labelStyle={chartLabelStyle}
                        formatter={fmtGbTooltip}
                      />
                      <Legend wrapperStyle={{ fontSize: '0.78rem', color: '#8c8ca8' }} />
                      <Line type="monotone" dataKey="memoria_usada_gb" stroke="#7c6af7" strokeWidth={2} dot={false} name="RAM (GB)" />
                      <Line type="monotone" dataKey="swap_usada_gb"    stroke="#f59e0b" strokeWidth={2} dot={false} name="Swap (GB)" />
                    </LineChart>
                  </ResponsiveContainer>
                </div>

                <div className="card chart-card">
                  <h3>Fallos de página por intervalo</h3>
                  <ResponsiveContainer width="100%" height={240}>
                    <BarChart data={history}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#26263a" />
                      <XAxis dataKey="time" stroke="#515168" tick={{ fontSize: 10 }} interval="preserveEnd" />
                      <YAxis stroke="#515168" tick={{ fontSize: 10 }} />
                      <Tooltip
                        contentStyle={chartTooltipStyle}
                        itemStyle={chartItemStyle}
                        labelStyle={chartLabelStyle}
                        formatter={fmtCountTooltip}
                      />
                      <Legend wrapperStyle={{ fontSize: '0.78rem', color: '#8c8ca8' }} />
                      <Bar dataKey="fallos_menores_delta" fill="#22c55e" name="Menores" radius={[2, 2, 0, 0]} />
                      <Bar dataKey="fallos_mayores_delta" fill="#ef4444" name="Mayores" radius={[2, 2, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Charts row 2 */}
              <div className="grid two-col">
                <div className="card chart-card">
                  <h3>Desglose de memoria</h3>
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie data={memoryPie} dataKey="value" nameKey="name" innerRadius={60} outerRadius={88} paddingAngle={3}>
                        <Cell fill="#7c6af7" />
                        <Cell fill="#515168" />
                        <Cell fill="#38bdf8" />
                      </Pie>
                      <Tooltip
                        contentStyle={chartTooltipStyle}
                        itemStyle={chartItemStyle}
                        labelStyle={chartLabelStyle}
                        formatter={fmtKbTooltip}
                      />
                      <Legend wrapperStyle={{ fontSize: '0.78rem', color: '#8c8ca8' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>

                <div className="card chart-card">
                  <h3>Estado de páginas de memoria</h3>
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie data={pageStatusPie} dataKey="value" nameKey="name" innerRadius={60} outerRadius={88} paddingAngle={3}>
                        <Cell fill="#7c6af7" />
                        <Cell fill="#26263a" />
                      </Pie>
                      <Tooltip
                        contentStyle={chartTooltipStyle}
                        itemStyle={chartItemStyle}
                        labelStyle={chartLabelStyle}
                        formatter={fmtCountTooltip}
                      />
                      <Legend wrapperStyle={{ fontSize: '0.78rem', color: '#8c8ca8' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Top processes table */}
              <div className="card">
                <div className="panel-header">
                  <h3>Top procesos por consumo de memoria</h3>
                  <span className="badge badge-total">{(metrics.procesos_top || []).length} procesos</span>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th style={{ width: 40 }}>#</th>
                        <th>Proceso</th>
                        <th>PID</th>
                        <th style={{ width: 200 }}>Uso de memoria</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(metrics.procesos_top || []).map((p, idx) => (
                        <tr key={`${p.pid}-${idx}`}>
                          <td className="proc-rank">#{idx + 1}</td>
                          <td style={{ fontWeight: 500 }}>{p.nombre}</td>
                          <td className="mono" style={{ color: 'var(--muted)', fontSize: '0.82rem' }}>{p.pid}</td>
                          <td><MemoryBar pct={p.porcentaje} /></td>
                        </tr>
                      ))}
                      {!(metrics.procesos_top || []).length && (
                        <tr>
                          <td colSpan="4" style={{ textAlign: 'center', color: 'var(--muted)', padding: '24px' }}>
                            Sin datos de procesos
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ══ ALERTS TAB ══ */}
          {activeTab === 'alerts' && (
            <AlertsPanel alerts={alerts} />
          )}

          {/* ══ FILES TAB ══ */}
          {activeTab === 'files' && (
            <FilesPanel files={files} role={role} onCallApi={callApi} />
          )}

          {/* ══ THREATS TAB ══ */}
          {activeTab === 'threats' && (
            <ThreatsPanel threats={threats} />
          )}

          {/* ══ CONTROLS TAB (admin only) ══ */}
          {activeTab === 'controls' && (
            <div className="grid two-col" style={{ gap: 20, alignItems: 'start' }}>
              <ScanControl
                role={role}
                scanEnabled={scanEnabled}
                onScanOnce={doScanOnce}
                onStart={() => doScanToggle(true)}
                onStop={() => doScanToggle(false)}
              />
              <ProcessLookup
                role={role}
                onLookup={lookupPid}
                processData={processData}
              />
            </div>
          )}

          {activeTab === 'users' && (
            <UserCreatePanel
              role={role}
              onCreateUser={createSystemUser}
              onListUsers={listSystemUsers}
              onDeleteUser={deleteSystemUser}
            />
          )}

        </main>
      </div>
    </div>
  )
}

export default App
