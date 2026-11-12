export const isExtension = typeof chrome !== 'undefined' && !!chrome.runtime?.id
export type Connection = { origin: string; username: string; password: string }
export let connection: Connection = { origin: 'https://127.0.0.1:444', username: '', password: '' }

export function normalizeOrigin(value: string): string {
  const url = new URL(value)
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('请输入服务地址，例如 https://127.0.0.1:444，不要包含路径或账号密码')
  }
  return url.origin
}

export function hostPermission(origin: string): string {
  const url = new URL(origin)
  return `${url.protocol}//${url.hostname}/*`
}

export async function loadConnection() {
  if (!isExtension) return
  const saved = await chrome.storage.local.get('connection')
  const session = await chrome.storage.session.get('credential')
  const value = saved.connection as Omit<Connection, 'password'> | undefined
  const credential = session.credential as Connection | undefined
  connection = { ...connection, ...value, password: credential?.origin === value?.origin && credential?.username === value?.username ? credential?.password ?? '' : '' }
}

export async function saveConnection(value: Connection) {
  await chrome.storage.session.set({ credential: value })
  await chrome.storage.local.set({ connection: { origin: value.origin, username: value.username } })
  connection = value
}

export async function managementFetch(path: string, init: RequestInit = {}) {
  if (!isExtension) return fetch(path, init)
  if (!connection.username) throw new Error('请先点击扩展图标，配置服务地址和认证信息')
  const headers = new Headers(init.headers)
  const bytes = new TextEncoder().encode(`${connection.username}:${connection.password}`)
  headers.set('Authorization', `Basic ${btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(''))}`)
  return fetch(`${connection.origin}${path}`, { ...init, headers, credentials: 'omit', redirect: 'error' })
}

export async function downloadCa() {
  const response = await managementFetch('/mitm/ca.crt')
  if (!response.ok) throw new Error(`证书下载失败 (${response.status})`)
  const url = URL.createObjectURL(await response.blob())
  const link = document.createElement('a')
  link.href = url
  link.download = 'mitm-ca.crt'
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
