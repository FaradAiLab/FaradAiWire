/**
 * Copies text to the clipboard safely across both Secure Contexts (HTTPS / localhost)
 * and non-secure HTTP contexts (e.g. Containerized Security Gateway at http://<host>:19415).
 */
export async function copyTextToClipboard(
  text: string,
  env: {
    isSecureContext?: boolean
    clipboard?: { writeText?: (value: string) => Promise<void> }
    doc?: {
      createElement: (tag: string) => HTMLTextAreaElement
      body?: {
        appendChild: (el: Node) => unknown
        removeChild: (el: Node) => unknown
      }
      execCommand?: (cmd: string) => boolean
    }
  } = typeof globalThis !== 'undefined'
    ? {
        isSecureContext: (globalThis as { isSecureContext?: boolean }).isSecureContext,
        clipboard: (globalThis as { navigator?: Navigator }).navigator?.clipboard,
        doc: typeof document !== 'undefined' ? document : undefined,
      }
    : {}
): Promise<boolean> {
  if (env.isSecureContext && env.clipboard && typeof env.clipboard.writeText === 'function') {
    try {
      await env.clipboard.writeText(text)
      return true
    } catch {
      // Fall through to execCommand fallback if browser clipboard permission was denied.
    }
  }

  const doc = env.doc
  if (!doc || !doc.body || typeof doc.createElement !== 'function' || typeof doc.execCommand !== 'function') {
    return false
  }

  const textarea = doc.createElement('textarea')
  textarea.value = text
  textarea.setAttribute('readonly', '')
  textarea.style.position = 'fixed'
  textarea.style.top = '-9999px'
  textarea.style.left = '-9999px'
  textarea.style.opacity = '0'

  doc.body.appendChild(textarea)
  try {
    textarea.focus()
    textarea.select()
    return Boolean(doc.execCommand('copy'))
  } catch {
    return false
  } finally {
    doc.body.removeChild(textarea)
  }
}
