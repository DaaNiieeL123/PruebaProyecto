import { useState } from 'react'

/**
 * usePagination
 * @param {Array}  items    - The full array to paginate
 * @param {number} pageSize - Items per page (default 5)
 */
export function usePagination(items = [], pageSize = 5) {
  const [page, setPage] = useState(1)

  const totalItems = items.length
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize))

  // Clamp so stale page never exceeds new totalPages after a data refresh
  const safePage = Math.min(page, totalPages)

  const sliced = items.slice((safePage - 1) * pageSize, safePage * pageSize)

  return {
    page: safePage,
    totalPages,
    totalItems,
    pageSize,
    items: sliced,
    goNext:  () => setPage((p) => Math.min(p + 1, totalPages)),
    goPrev:  () => setPage((p) => Math.max(p - 1, 1)),
    goPage:  (n) => setPage(Math.min(Math.max(1, n), totalPages)),
    reset:   () => setPage(1),
  }
}
