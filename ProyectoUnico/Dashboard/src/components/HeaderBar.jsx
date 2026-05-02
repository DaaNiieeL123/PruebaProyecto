function HeaderBar({ username, role, scanEnabled, onExportReport, onLogout }) {
  return (
    <header className="topbar card">
      <div>
        <p className="eyebrow">Sistema Integral de Seguridad</p>
        <h2>Kernel Monitoring Command Center</h2>
      </div>

      <div className="topbar-right">
        <p>
          <strong>Usuario:</strong> {username}
        </p>
        <p>
          <strong>Rol:</strong> {role}
        </p>
        <p>
          <strong>Escaneo:</strong> {scanEnabled ? 'ACTIVO' : 'DETENIDO'}
        </p>
        <div className="topbar-actions">
          <button className="secondary" onClick={onExportReport}>Exportar reporte</button>
          <button onClick={onLogout}>Salir</button>
        </div>
      </div>
    </header>
  )
}

export default HeaderBar
