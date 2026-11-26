import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { copyTextToClipboard } from './clipboard.ts'

describe('copyTextToClipboard (STUDIO-019)', () => {
  it('uses navigator.clipboard.writeText when inside a Secure Context', async () => {
    let copied = ''
    const ok = await copyTextToClipboard('{"mcpServers":{}}', {
      isSecureContext: true,
      clipboard: {
        writeText: async (value: string) => {
          copied = value
        },
      },
    })
    assert.equal(ok, true)
    assert.equal(copied, '{"mcpServers":{}}')
  })

  it('falls back to textarea + execCommand in non-secure HTTP Containerized contexts', async () => {
    let appended = false
    let removed = false
    let selected = false
    let textareaValue = ''

    const fakeTextarea = {
      value: '',
      style: {},
      setAttribute: () => {},
      focus: () => {},
      select: () => {
        selected = true
        textareaValue = fakeTextarea.value
      },
    } as unknown as HTMLTextAreaElement

    const ok = await copyTextToClipboard('{"mcpServers":{"github":{}}}', {
      isSecureContext: false,
      clipboard: undefined,
      doc: {
        createElement: () => fakeTextarea,
        body: {
          appendChild: () => {
            appended = true
          },
          removeChild: () => {
            removed = true
          },
        },
        execCommand: (cmd: string) => cmd === 'copy',
      },
    })

    assert.equal(ok, true)
    assert.equal(appended, true)
    assert.equal(removed, true)
    assert.equal(selected, true)
    assert.equal(textareaValue, '{"mcpServers":{"github":{}}}')
  })

  it('returns false gracefully when neither clipboard API nor DOM fallback exists', async () => {
    const ok = await copyTextToClipboard('hello', {
      isSecureContext: false,
      clipboard: undefined,
      doc: undefined,
    })
    assert.equal(ok, false)
  })
})
