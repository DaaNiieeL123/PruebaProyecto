import { useState, useMemo } from 'react'
import { CircleDashed, SlidersHorizontal, X } from 'lucide-react'
import Pagination from './Pagination'
import RowDetailsModal from './RowDetailsModal'
import { usePagination } from '../hooks/usePagination'

const PAGE_SIZE = 7

const SEV_OPTIONS = ['ALL', 'HIGH', 'MEDIUM', 'LOW']

function parseTs(ts) {
  if (!ts) return 0
  const d = new Date(ts)
  return isNaN(d.getTime()) ? 0 : d.getTime()
}

function AlertsPanel({ alerts }) {
  const [sevFilter,  setSevFilter]  = useState('ALL')
  const [typeFilter, setTypeFilter] = useState('ALL')

  /* Derive unique event types from data for the type filter */
  const typeOptions = useMemo(() => {
    const types = new Set(alerts.map((a) => (a.tipo || '').trim()).filter(Boolean))
    return ['ALL', ...Array.from(types).sort()]
  }, [alerts])

  const highCount = alerts.filter((a) => a.severidad?.toUpperCase() === 'HIGH').length

  /* Apply filters then sort newest first */
  const filtered = useMemo(() => {
    return [...alerts]
      .filter((a) => {
        const sevMatch  = sevFilter  === 'ALL' || (a.severidad || '').toUpperCase() === sevFilter
        const typeMatch = typeFilter === 'ALL' || (a.tipo || '').trim() === typeFilter
        return sevMatch && typeMatch
      })
      .sort((a, b) => parseTs(b.timestamp) - parseTs(a.timestamp))
  }, [alerts, sevFilter, typeFilter])

  const pg = usePagination(filtered, PAGE_SIZE)

  const hasActiveFilter = sevFilter !== 'ALL' || typeFilter !== 'ALL'

  const clearFilters = () => {
    setSevFilter('ALL')
    setTypeFilter('ALL')
  }

  const [selectedRow, setSelectedRow] = useState(null)

  return (
    <div className="panel-page">
      {selectedRow && (
        <RowDetailsModal 
          item={selectedRow} 
          title="Detalles de Alerta" 
          onClose={() => setSelectedRow(null)} 
        />
      )}
      <div className="panel-page-header">
        <div>
          <h2>Alertas de Seguridad</h2>
          <p>Eventos del sistema clasificados por severidad — más recientes primero</p>
        </div>
        <div className="badge-group">
          {highCount > 0 && (
            <span className="badge badge-high">{highCount} críticas</span>
          )}
          <span className="badge badge-total">{alerts.length} total</span>
        </div>
      </div>

      {/* ── Filters bar ── */}
      <div className="filter-bar">
        <span className="filter-bar-icon">
          <SlidersHorizontal size={14} strokeWidth={1.8} />
          <span>Filtros</span>
        </span>

        {/* Severity filter */}
        <div className="filter-group">
          <label htmlFor="alerts-sev-filter">Severidad</label>
          <div className="filter-btn-row">
            {SEV_OPTIONS.map((sev) => (
              <button
                key={sev}
                id={`alerts-sev-${sev}`}
                className={`filter-btn filter-btn-sev-${sev.toLowerCase()}${sevFilter === sev ? ' filter-btn--active' : ''}`}
                onClick={() => { setSevFilter(sev); pg.goPage(1) }}
              >
                {sev === 'ALL' ? 'Todas' : sev}
              </button>
            ))}
          </div>
        </div>

        {/* Type filter */}
        <div className="filter-group">
          <label htmlFor="alerts-type-filter">Tipo</label>
          <select
            id="alerts-type-filter"
            className="filter-select"
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); pg.goPage(1) }}
          >
            {typeOptions.map((t) => (
              <option key={t} value={t}>{t === 'ALL' ? 'Todos los tipos' : t}</option>
            ))}
          </select>
        </div>

        {/* Clear */}
        {hasActiveFilter && (
          <button className="filter-clear" onClick={clearFilters} title="Limpiar filtros">
            <X size={12} strokeWidth={2.5} />
            Limpiar
          </button>
        )}

        <span className="filter-result-count">
          {filtered.length} resultado{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Tipo de evento</th>
                <th>Severidad</th>
                <th>Descripción</th>
                <th>Fecha / Hora</th>
              </tr>
            </thead>
            <tbody>
              {pg.items.map((a, idx) => (
                <tr
                  key={`${a.timestamp}-${idx}`}
                  className={a.severidad?.toUpperCase() === 'HIGH' ? 'row-high' : ''}
                  onClick={() => setSelectedRow(a)}
                >
                  <td style={{ fontWeight: 500 }}>{a.tipo || '--'}</td>
                  <td>
                    <span className={`sev sev-${(a.severidad || 'low').toLowerCase()}`}>
                      {a.severidad || 'LOW'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--subtle)', fontSize: '0.82rem' }}>
                    {a.descripcion || '--'}
                  </td>
                  <td
                    className="mono"
                    style={{ fontSize: '0.76rem', color: 'var(--muted)', whiteSpace: 'nowrap' }}
                  >
                    {a.timestamp || '--'}
                  </td>
                </tr>
              ))}
              {pg.items.length === 0 && (
                <tr>
                  <td colSpan="4">
                    <div className="empty-state">
                      <CircleDashed
                        size={36}
                        strokeWidth={1.2}
                        style={{ opacity: 0.28, color: 'var(--muted)' }}
                      />
                      <p>
                        {hasActiveFilter
                          ? 'Sin resultados para los filtros seleccionados'
                          : 'Sin alertas por el momento'}
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

export default AlertsPanel
