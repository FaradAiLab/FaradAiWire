export const DEFAULT_GATEWAY_HOST = '127.0.0.1'
export const DEFAULT_INGRESS_PORT = 19410
export const DEFAULT_ADMIN_PORT = 19415

/**
 * Resolves the active Admin console host:port for display and WebSocket connections.
 */
export function getAdminConsoleHost(): string {
  if (typeof window !== 'undefined' && window.location.host) {
    return window.location.host
  }
  return `${DEFAULT_GATEWAY_HOST}:${DEFAULT_ADMIN_PORT}`
}

/**
 * Normalizes wildcard bind hosts (0.0.0.0, ::, [::], empty) into a client-routable hostname
 * derived from window.location.hostname or 127.0.0.1.
 */
export function normalizeBrowserIngressHost(rawHost?: string): string {
  const trimmed = (rawHost || '').trim()
  const isWildcard = !trimmed || trimmed === '0.0.0.0' || trimmed === '::' || trimmed === '[::]'
  if (!isWildcard) {
    return trimmed
  }
  if (typeof window !== 'undefined' && window.location.hostname) {
    return window.location.hostname
  }
  return DEFAULT_GATEWAY_HOST
}
