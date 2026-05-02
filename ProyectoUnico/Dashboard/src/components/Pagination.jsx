/**
 * Pagination
 * Renders a pagination bar.  Returns null when there is only one page.
 */
function Pagination({ page, totalPages, totalItems, pageSize, onPrev, onNext }) {
  if (totalItems === 0 || totalPages <= 1) return null

  const from = (page - 1) * pageSize + 1
  const to   = Math.min(page * pageSize, totalItems)

  return (
    <div className="pagination">
      <span className="pagination-info">
        {from}–{to} de {totalItems} resultados
      </span>

      <div className="pagination-controls">
        <button
          className="pagination-btn"
          onClick={onPrev}
          disabled={page === 1}
          aria-label="Página anterior"
        >
          ←
        </button>

        <span className="pagination-page">
          {page} <span className="pagination-sep">/</span> {totalPages}
        </span>

        <button
          className="pagination-btn"
          onClick={onNext}
          disabled={page === totalPages}
          aria-label="Siguiente página"
        >
          →
        </button>
      </div>
    </div>
  )
}

export default Pagination
