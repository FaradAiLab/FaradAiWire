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
