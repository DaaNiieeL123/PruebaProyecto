import { useState } from 'react'
import { CheckCircle, XCircle } from 'lucide-react'

function ScanControl({ role, scanEnabled, onScanOnce, onStart, onStop }) {
  const [loading, setLoading] = useState(null) // 'start' | 'stop' | 'once' | null
  const [feedback, setFeedback] = useState('')

  if (role !== 'admin') {
    return (
      <section className="card panel">
        <h3>Control de escaneo</h3>
        <p>Solo administradores pueden activar o desactivar el escaneo.</p>
      </section>
    )
  }

  async function wrap(key, fn, message) {
    setLoading(key)
    setFeedback('')
    try {
      await fn()
      setFeedback(message)
    } catch (err) {
      setFeedback(`Error: ${err.message || 'No se pudo completar la acción'}`)
    } finally {
      setLoading(null)
    }
  }

  const busy = loading !== null

  return (
    <section className="card panel actions">
      <h3>Control de escaneo</h3>
      <div className="scan-status-row">
        <span className={`scan-dot ${scanEnabled ? 'scan-dot-active' : 'scan-dot-idle'}`} />
        <p>
          Estado actual:{' '}
          <strong className={scanEnabled ? 'text-ok' : 'text-muted'}>
            {scanEnabled ? 'ACTIVO' : 'DETENIDO'}
          </strong>
        </p>
      </div>

      <div className="action-buttons">
        <button
          onClick={() => wrap('start', onStart, 'Escaneo continuo activado')}
          disabled={busy}
        >
          {loading === 'start' ? 'Activando...' : 'Activar escaneo'}
        </button>

        <button
          className="secondary"
          onClick={() => wrap('once', onScanOnce, 'Escaneo puntual iniciado')}
          disabled={busy}
        >
          {loading === 'once' ? 'Escaneando...' : 'Escaneo puntual'}
        </button>

        <button
          className="danger"
          onClick={() => wrap('stop', onStop, 'Escaneo detenido')}
          disabled={busy}
        >
          {loading === 'stop' ? 'Deteniendo...' : 'Desactivar escaneo'}
        </button>
      </div>

      {feedback && (
        <div className={`scan-feedback ${feedback.startsWith('Error') ? 'scan-feedback-err' : 'scan-feedback-ok'}`}>
          {feedback.startsWith('Error')
            ? <XCircle size={14} strokeWidth={2} />
            : <CheckCircle size={14} strokeWidth={2} />
          }
          {feedback}
        </div>
      )}
    </section>
  )
}

export default ScanControl
