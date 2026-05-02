import { useState } from 'react'

function ProcessLookup({ role, onLookup, processData }) {
  const [pid, setPid] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  if (role !== 'admin') {
    return (
      <section className="card panel">
        <h3>Consulta por PID</h3>
        <p>Disponible solo para administradores.</p>
      </section>
    )
  }

  const handleLookup = async () => {
    const trimmed = pid.trim()
    if (!trimmed) {
      setError('Ingrese un PID válido.')
      return
    }
    if (!/^\d+$/.test(trimmed)) {
      setError('El PID debe ser un número entero positivo.')
      return
    }
    setError('')
    setLoading(true)
    try {
      await onLookup(trimmed)
    } catch (err) {
      setError(err.message || 'No se pudo obtener información del proceso.')
    } finally {
      setLoading(false)
    }
  }

  const handleKey = (e) => {
    if (e.key === 'Enter') handleLookup()
  }

  return (
    <section className="card panel">
      <h3>Consulta por PID</h3>
      <div className="inline-form">
        <input
          value={pid}
          onChange={(e) => setPid(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Ej: 1234"
          type="number"
          min="1"
        />
        <button onClick={handleLookup} disabled={loading}>
          {loading ? '⟳ Buscando...' : 'Consultar'}
        </button>
      </div>

      {error && <p className="error-msg" style={{ marginTop: '8px' }}>{error}</p>}

      {processData && !error && (
        <div className="process-box">
          {processData.ok ? (
            <div className="process-grid">
              <span className="proc-label">Proceso</span>
              <span className="proc-value">{processData.proceso}</span>

              <span className="proc-label">PID</span>
              <span className="proc-value mono">{processData.pid}</span>

              <span className="proc-label">Tiempo CPU</span>
              <span className="proc-value mono">{processData.tiempo_cpu} s</span>

              <span className="proc-label">Memoria RSS</span>
              <span className="proc-value mono">
                {(processData.memoria_rss_kb / 1024).toFixed(2)} MB
              </span>
            </div>
          ) : (
            <p className="error-msg">{processData.message || 'Proceso no encontrado.'}</p>
          )}
        </div>
      )}
    </section>
  )
}

export default ProcessLookup
