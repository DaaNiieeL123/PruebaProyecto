import { useEffect, useRef, useState } from 'react'
import { ShieldAlert } from 'lucide-react'

const POPUP_COOLDOWN_MS = 25000

function KernelPanicBanner({ alerts }) {
  const [dismissed, setDismissed] = useState(false)
  const [visible,   setVisible]   = useState(false)
  const [panicMsg,  setPanicMsg]  = useState('')
  const prevHighRef = useRef(0)
  const lastShownRef = useRef(0)

  const highAlerts = alerts.filter((a) => a.severidad?.toUpperCase() === 'HIGH')
  const highCount  = highAlerts.length

  useEffect(() => {
    if (highCount > prevHighRef.current) {
      const now = Date.now()
      const canShow = now - lastShownRef.current >= POPUP_COOLDOWN_MS
      if (canShow) {
        setDismissed(false)
        setVisible(true)
        const latest = highAlerts[0]
        setPanicMsg(latest?.descripcion || 'Amenaza crítica activa en el sistema.')
        lastShownRef.current = now
      }
    }
    if (highCount === 0) setVisible(false)
    prevHighRef.current = highCount
  }, [highCount])

  if (!visible || dismissed || highCount === 0) return null

  return (
    <div className="panic-overlay" role="alertdialog" aria-modal="true">
      <div className="panic-card">
        <div className="panic-icon">
          <ShieldAlert size={52} strokeWidth={1.4} />
        </div>

        <p className="panic-eyebrow">sys_simulate_panic — kernel event</p>
        <h2 className="panic-title">Amenaza Crítica Detectada</h2>

        <p className="panic-count">
          {highCount} alerta{highCount > 1 ? 's' : ''} de severidad HIGH
        </p>

        <p className="panic-msg">{panicMsg}</p>

        <div className="panic-actions">
          <button
            className="panic-dismiss"
            onClick={() => setDismissed(true)}
          >
            Entendido — Descartar
          </button>
        </div>
      </div>
    </div>
  )
}

export default KernelPanicBanner
