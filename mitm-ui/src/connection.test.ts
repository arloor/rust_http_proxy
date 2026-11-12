import { afterEach, describe, expect, it, vi } from 'vitest'

afterEach(() => { vi.unstubAllGlobals(); vi.resetModules() })

describe('management connection', () => {
  it('validates service origins and derives host permissions without ports', async () => {
    const { normalizeOrigin, hostPermission } = await import('./connection')
    expect(normalizeOrigin('https://localhost:444/')).toBe('https://localhost:444')
    expect(hostPermission('https://localhost:444')).toBe('https://localhost/*')
    for (const value of ['file:///tmp/a', 'https://user:pass@localhost', 'https://localhost/mitm/', 'https://localhost/?x=1']) {
      expect(() => normalizeOrigin(value)).toThrow()
    }
  })

  it('keeps web requests same-origin and does not inject authorization', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('{}'))
    vi.stubGlobal('fetch', fetch)
    const { managementFetch } = await import('./connection')
    await managementFetch('/mitm/api/settings')
    expect(fetch).toHaveBeenCalledWith('/mitm/api/settings', {})
  })

  it('uses session credentials only for their saved service and does not persist passwords', async () => {
    const localSet = vi.fn()
    const sessionSet = vi.fn()
    vi.stubGlobal('chrome', { runtime: { id: 'test' }, storage: {
      local: { get: async () => ({ connection: { origin: 'https://localhost:444', username: 'admin' } }), set: localSet },
      session: { get: async () => ({ credential: { origin: 'https://other', username: 'admin', password: 'old' } }), set: sessionSet },
    } })
    const fetch = vi.fn().mockResolvedValue(new Response('{}'))
    vi.stubGlobal('fetch', fetch)
    const module = await import('./connection')
    await module.loadConnection()
    expect(module.connection.password).toBe('')
    await module.saveConnection({ origin: 'https://localhost:444', username: 'admin', password: '秘密' })
    expect(localSet).toHaveBeenCalledWith({ connection: { origin: 'https://localhost:444', username: 'admin' } })
    expect(sessionSet).toHaveBeenCalledOnce()
    await module.managementFetch('/mitm/api/settings', { headers: { 'Content-Type': 'application/json' } })
    const [url, init] = fetch.mock.calls[0]
    expect(url).toBe('https://localhost:444/mitm/api/settings')
    expect(init.headers.get('Authorization')).toBe('Basic YWRtaW4656eY5a+G')
    expect(init.headers.get('Content-Type')).toBe('application/json')
    expect(init.redirect).toBe('error')
    expect(init.credentials).toBe('omit')
  })
})
