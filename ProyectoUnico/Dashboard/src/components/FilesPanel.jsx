import { useState, useMemo } from 'react'
import {
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  FolderSearch,
  SlidersHorizontal,
  X,
  Lock,
  Unlock,
  ShieldOff,
} from 'lucide-react'
import Pagination from './Pagination'
import RowDetailsModal from './RowDetailsModal'
import { usePagination } from '../hooks/usePagination'

const PAGE_SIZE = 7

const ESTADO_OPTIONS = ['ALL', 'limpio', 'modificado', 'sospechoso', 'cuarentena']

const ESTADO_META = {
  limpio:     { cls: 'estado-limpio',     label: 'Limpio',     Icon: CheckCircle2  },
  modificado: { cls: 'estado-modificado', label: 'Modificado', Icon: AlertCircle   },
  sospechoso: { cls: 'estado-sospechoso', label: 'Sospechoso', Icon: AlertTriangle },
  cuarentena: { cls: 'estado-cuarentena', label: 'Cuarentena', Icon: Lock          },
}

function normalizeFileState(estado = '') {
  const key = estado.toLowerCase()
  if (key === 'nuevo') return 'limpio'
  if (key === 'limpio' || key === 'modificado' || key === 'sospechoso' || key === 'cuarentena') return key
  return key
}

function shortHash(hash = '') {
  if (!hash) return '--'
  return `${hash.slice(0, 8)}…${hash.slice(-6)}`
}

function EstadoBadge({ estado }) {
  const key  = normalizeFileState(estado || '')
  const meta = ESTADO_META[key] || { cls: 'estado-unknown', label: estado || '--', Icon: null }
  const { Icon } = meta
  return (
    <span className={`estado-badge ${meta.cls}`}>
      {Icon && <Icon size={10} strokeWidth={2.5} />}
      {meta.label}
    </span>
  )
}

function FilesPanel({ files, role, onCallApi }) {
  const [estadoFilter, setEstadoFilter] = useState('ALL')
  const [selectedRow, setSelectedRow] = useState(null)
  const [actionMsg, setActionMsg] = useState(null)

  const isAdmin = role === 'admin'

  const quarantineCount = files.filter((f) => normalizeFileState(f.estado || '') === 'cuarentena').length
  const suspiciousCount = files.filter((f) => {
    const state = normalizeFileState(f.estado || '')
    return state === 'sospechoso' || state === 'cuarentena'
  }).length

  const filtered = useMemo(() => {
    if (estadoFilter === 'ALL') return files
    return files.filter((f) => normalizeFileState(f.estado || '') === estadoFilter)
  }, [files, estadoFilter])

  const pg = usePagination(filtered, PAGE_SIZE)

  const hasFilter = estadoFilter !== 'ALL'

  const showMsg = (type, msg) => {
    setActionMsg({ type, msg })
    setTimeout(() => setActionMsg(null), 3500)
  }

  const handleQuarantine = async (filePath) => {
    try {
      await onCallApi('/api/quarantine/add', {
        method: 'POST',
        body: JSON.stringify({ path: filePath }),
      })
      showMsg('ok', 'Archivo enviado a cuarentena')
    } catch (err) {
      showMsg('err', `Error: ${err.message || 'No se pudo cuarentenar'}`)
    }
  }

  const handleRestore = async (filePath) => {
    try {
      await onCallApi('/api/quarantine/restore', {
        method: 'POST',
        body: JSON.stringify({ path: filePath }),
      })
      showMsg('ok', 'Archivo restaurado de cuarentena')
    } catch (err) {
      showMsg('err', `Error: ${err.message || 'No se pudo restaurar'}`)
    }
  }

  return (
    <div className="panel-page">
      {selectedRow && (
        <RowDetailsModal
          item={selectedRow}
          title="Detalles del Archivo"
          onClose={() => setSelectedRow(null)}
        />
      )}

      <div className="panel-page-header">
        <div>
          <h2>Archivos Analizados</h2>
          <p>Resultados del escaneo de integridad — hash SHA-256</p>
        </div>
        <div className="badge-group">
          {quarantineCount > 0 && (
            <span className="badge badge-high">{quarantineCount} en cuarentena</span>
          )}
          {suspiciousCount - quarantineCount > 0 && (
            <span className="badge badge-medium">{suspiciousCount - quarantineCount} sospechosos</span>
          )}
          <span className="badge badge-total">{files.length} archivos</span>
        </div>
      </div>

      {/* ── Action feedback toast ── */}
      {actionMsg && (
        <div className={`export-toast export-toast--${actionMsg.type === 'ok' ? 'ok' : 'err'}`} role="status">
          <span>{actionMsg.type === 'ok' ? '✓' : '✕'}</span>
          {actionMsg.msg}
        </div>
      )}

      {/* ── Filters bar ── */}
      <div className="filter-bar">
        <span className="filter-bar-icon">
          <SlidersHorizontal size={14} strokeWidth={1.8} />
          <span>Estado</span>
        </span>

        <div className="filter-btn-row">
          {ESTADO_OPTIONS.map((est) => {
            const meta = ESTADO_META[est]
            return (
              <button
                key={est}
                id={`files-estado-${est}`}
                className={`filter-btn filter-btn-estado-${est}${estadoFilter === est ? ' filter-btn--active' : ''}`}
                onClick={() => { setEstadoFilter(est); pg.goPage(1) }}
              >
                {meta?.Icon && <meta.Icon size={11} strokeWidth={2} />}
                {est === 'ALL' ? 'Todos' : meta?.label || est}
              </button>
            )
          })}
        </div>

        {hasFilter && (
          <button
            className="filter-clear"
            onClick={() => { setEstadoFilter('ALL'); pg.goPage(1) }}
            title="Limpiar filtro"
          >
            <X size={12} strokeWidth={2.5} />
            Limpiar
          </button>
        )}

        <span className="filter-result-count">
          {filtered.length} archivo{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Ruta del archivo</th>
                <th>Estado</th>
                <th>Hash SHA-256</th>
                <th>Última modificación</th>
                {isAdmin && <th style={{ minWidth: 150 }}>Acciones (admin)</th>}
              </tr>
            </thead>
            <tbody>
              {pg.items.map((f, idx) => {
                const state = normalizeFileState(f.estado || '')
                return (
                  <tr
                    key={`${f.path}-${idx}`}
                    onClick={() => setSelectedRow({ ...f, estado: state })}
                    className={state === 'cuarentena' ? 'row-high' : ''}
                  >
                    <td className="mono file-path" title={f.path}>{f.path || '--'}</td>
                    <td><EstadoBadge estado={f.estado} /></td>
                    <td className="mono" style={{ fontSize: '0.76rem', color: 'var(--muted)' }}>
                      {shortHash(f.hash)}
                    </td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--subtle)', whiteSpace: 'nowrap' }}>
                      {f.timestamp || '--'}
                    </td>
                    {isAdmin && (
                      <td onClick={(e) => e.stopPropagation()}>
                        <div className="quarantine-actions">
                          {state === 'cuarentena' ? (
                            <button
                              id={`btn-restore-${idx}`}
                              className="qbtn qbtn-restore"
                              title="Restaurar archivo de cuarentena"
                              onClick={() => handleRestore(f.path)}
                            >
                              <Unlock size={11} strokeWidth={2} />
                              Restaurar
                            </button>
                          ) : (state === 'sospechoso' || state === 'modificado') ? (
                            <button
                              id={`btn-quarantine-${idx}`}
                              className="qbtn qbtn-quarantine"
                              title="Enviar archivo a cuarentena"
                              onClick={() => handleQuarantine(f.path)}
                            >
                              <ShieldOff size={11} strokeWidth={2} />
                              Cuarentenar
                            </button>
                          ) : null}
                        </div>
                      </td>
                    )}
                  </tr>
                )
              })}
              {pg.items.length === 0 && (
                <tr>
                  <td colSpan={isAdmin ? '5' : '4'}>
                    <div className="empty-state">
                      <FolderSearch
                        size={36}
                        strokeWidth={1.2}
                        style={{ opacity: 0.28, color: 'var(--muted)' }}
                      />
                      <p>
                        {hasFilter
                          ? `Sin archivos con estado "${ESTADO_META[estadoFilter]?.label || estadoFilter}"`
                          : 'No hay archivos escaneados aún'}
                      </p>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pagination
          page={pg.page} totalPages={pg.totalPages}
          totalItems={pg.totalItems} pageSize={pg.pageSize}
          onPrev={pg.goPrev} onNext={pg.goNext}
        />
      </div>
    </div>
  )
}

export default FilesPanel
