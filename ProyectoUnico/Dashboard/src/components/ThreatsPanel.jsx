import { useState, useMemo } from 'react'
import { ShieldCheck, SlidersHorizontal, X } from 'lucide-react'
import Pagination from './Pagination'
import RowDetailsModal from './RowDetailsModal'
import { usePagination } from '../hooks/usePagination'

const PAGE_SIZE = 7
const SEV_OPTIONS = ['ALL', 'HIGH', 'MEDIUM', 'LOW']

function ThreatsPanel({ threats }) {
  const [sevFilter, setSevFilter] = useState('ALL')
  const [selectedRow, setSelectedRow] = useState(null)

  const filtered = useMemo(() => {
    if (sevFilter === 'ALL') return threats
    return threats.filter((t) => (t.severidad || '').toUpperCase() === sevFilter)
  }, [threats, sevFilter])

  const pg = usePagination(filtered, PAGE_SIZE)

  const hasFilter = sevFilter !== 'ALL'

  return (
    <div className="panel-page">
      {selectedRow && (
        <RowDetailsModal 
          item={selectedRow} 
          title="Detalle de Amenaza" 
          onClose={() => setSelectedRow(null)} 
        />
      )}
      <div className="panel-page-header">
        <div>
          <h2>Amenazas Detectadas</h2>
          <p>Coincidencias confirmadas con la blacklist de firmas hash</p>
        </div>
        <div className="badge-group">
          {threats.length > 0 ? (
            <span className="badge badge-high">{threats.length} detectadas</span>
          ) : (
            <span className="badge badge-ok">Sistema limpio</span>
          )}
        </div>
      </div>

      {/* ── Filters bar ── */}
      <div className="filter-bar">
        <span className="filter-bar-icon">
          <SlidersHorizontal size={14} strokeWidth={1.8} />
          <span>Severidad</span>
        </span>

        <div className="filter-btn-row">
          {SEV_OPTIONS.map((sev) => (
            <button
              key={sev}
              id={`threats-sev-${sev}`}
              className={`filter-btn filter-btn-sev-${sev.toLowerCase()}${sevFilter === sev ? ' filter-btn--active' : ''}`}
              onClick={() => { setSevFilter(sev); pg.goPage(1) }}
            >
              {sev === 'ALL' ? 'Todas' : sev}
            </button>
          ))}
        </div>

        {hasFilter && (
          <button
            className="filter-clear"
            onClick={() => { setSevFilter('ALL'); pg.goPage(1) }}
            title="Limpiar filtro"
          >
            <X size={12} strokeWidth={2.5} />
            Limpiar
          </button>
        )}

        <span className="filter-result-count">
          {filtered.length} amenaza{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Nombre de la firma</th>
                <th>Archivo afectado</th>
                <th>Severidad</th>
                <th>Descripción</th>
                <th>Detectado</th>
              </tr>
            </thead>
            <tbody>
              {pg.items.map((t, idx) => (
                <tr key={`${t.archivo}-${idx}`} className="row-high" onClick={() => setSelectedRow(t)}>
                  <td style={{ fontWeight: 600, color: '#fca5a5' }}>{t.nombre || '--'}</td>
                  <td className="mono file-path" title={t.archivo}>{t.archivo || '--'}</td>
                  <td>
                    <span className={`sev sev-${(t.severidad || 'high').toLowerCase()}`}>
                      {t.severidad || 'HIGH'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--subtle)', fontSize: '0.82rem' }}>
                    {t.descripcion || '--'}
                  </td>
                  <td
                    className="mono"
                    style={{ fontSize: '0.76rem', color: 'var(--muted)', whiteSpace: 'nowrap' }}
                  >
                    {t.timestamp || '--'}
                  </td>
                </tr>
              ))}
              {pg.items.length === 0 && (
                <tr>
                  <td colSpan="5">
                    <div className="empty-state">
                      <ShieldCheck
                        size={36}
                        strokeWidth={1.2}
                        style={{ opacity: 0.5, color: 'var(--ok)' }}
                      />
                      <p style={{ color: 'var(--ok)', fontWeight: 600 }}>
                        {hasFilter
                          ? `Sin amenazas con severidad ${sevFilter}`
                          : 'Sin amenazas detectadas'}
                      </p>
                      {!hasFilter && (
                        <p>No se encontraron coincidencias en la blacklist de firmas</p>
                      )}
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

export default ThreatsPanel
