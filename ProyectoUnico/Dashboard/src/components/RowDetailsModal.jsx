import { X, CheckCircle2, AlertTriangle, ShieldOff, AlertCircle, FilePlus, Copy, Terminal } from 'lucide-react'

// Utilidad para extraer ícono/color dependiendo de la severidad/estado
function getMeta(item) {
  if (item.severidad) {
    const sev = item.severidad.toUpperCase()
    if (sev === 'HIGH') return { color: '#fca5a5', icon: ShieldOff }
    if (sev === 'MEDIUM') return { color: '#fbbf24', icon: AlertTriangle }
    return { color: '#34d399', icon: CheckCircle2 }
  }
  if (item.estado) {
    const est = item.estado.toLowerCase()
    if (est === 'limpio') return { color: '#34d399', icon: CheckCircle2 }
    if (est === 'cuarentena' || est === 'sospechoso') return { color: '#fca5a5', icon: ShieldOff }
    if (est === 'nuevo') return { color: '#60a5fa', icon: FilePlus }
    return { color: '#fbbf24', icon: AlertCircle }
  }
  return { color: '#a1a1aa', icon: Terminal }
}

export default function RowDetailsModal({ item, title, onClose }) {
  if (!item) return null

  const { color, icon: Icon } = getMeta(item)

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <button className="modal-close" onClick={onClose}>
          <X size={18} strokeWidth={2} />
        </button>

        <div className="modal-header">
          <div className="modal-icon-wrap" style={{ color: color, backgroundColor: `${color}1A` }}>
            <Icon size={24} strokeWidth={2} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 600, color: '#f8fafc' }}>
              {title || 'Detalles del registro'}
            </h3>
            <span style={{ fontSize: '0.85rem', color: 'var(--subtle)' }}>
              Identificador único de evento en el sistema
            </span>
          </div>
        </div>

        <div className="modal-body">
          <div className="info-grid">
            {Object.entries(item).map(([key, value]) => {
              // skip some internal stuff if needed, but we'll render all
              if (!value) return null
              return (
                <div key={key} className="info-group">
                  <label className="info-label">{key.toUpperCase()}</label>
                  <div className="info-val-wrap">
                    <span className="info-value mono" title={value}>{value}</span>
                    <button 
                      className="copy-btn" 
                      onClick={(e) => { e.stopPropagation(); handleCopy(value); }}
                      title="Copiar porta-papeles"
                    >
                      <Copy size={13} strokeWidth={2} />
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
