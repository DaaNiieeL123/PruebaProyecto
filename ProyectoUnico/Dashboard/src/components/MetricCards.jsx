import { Cpu, Activity, Database, HardDrive, TrendingDown, Zap } from 'lucide-react'

function fmtKbToGb(kb) {
  if (kb == null) return '--'
  return `${(kb / 1048576).toFixed(2)} GB`
}

function fmtNum(n) {
  if (n == null) return '--'
  return Number(n).toLocaleString()
}

const CARD_DEFS = [
  { key: 'memoria_usada',  label: 'RAM usada',      fmt: fmtKbToGb, Icon: Cpu,          accent: '#7c6af7' },
  { key: 'memoria_libre',  label: 'RAM libre',       fmt: fmtKbToGb, Icon: Activity,     accent: '#22c55e' },
  { key: 'memoria_cache',  label: 'Caché',           fmt: fmtKbToGb, Icon: Database,     accent: '#38bdf8' },
  { key: 'swap_usada',     label: 'Swap',            fmt: fmtKbToGb, Icon: HardDrive,    accent: '#f59e0b' },
  { key: 'fallos_menores', label: 'Fallos menores',  fmt: fmtNum,    Icon: TrendingDown, accent: '#a78bfa' },
  { key: 'fallos_mayores', label: 'Fallos mayores',  fmt: fmtNum,    Icon: Zap,          accent: '#ef4444' },
]

function MetricCards({ metrics }) {
  return (
    <div className="cards-grid">
      {CARD_DEFS.map(({ key, label, fmt, Icon, accent }) => (
        <article
          key={key}
          className="metric-card"
          style={{ '--mc-accent': accent }}
        >
          <div className="metric-card-icon" style={{ color: accent }}>
            <Icon size={17} strokeWidth={1.8} />
          </div>
          <span className="metric-card-label">{label}</span>
          <span className="metric-card-value">{fmt(metrics[key])}</span>
        </article>
      ))}
    </div>
  )
}

export default MetricCards
