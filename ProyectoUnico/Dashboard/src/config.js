const DEFAULT_VM_API = 'http://192.168.230.128:8090'

export const API_BASE = import.meta.env.VITE_API_BASE || DEFAULT_VM_API
export const POLL_INTERVAL_MS = Number(import.meta.env.VITE_POLL_INTERVAL_MS || 3000)
