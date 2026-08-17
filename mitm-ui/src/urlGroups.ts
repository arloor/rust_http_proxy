import type { HostGroup } from './api'

export type GroupSearchQuery =
  | { kind: 'text'; text: string }
  | { kind: 'url'; host: string; path: string }

export function hostMatchesSuffix(host: string, suffix: string): boolean {
  const normalizedHost = normalizeHost(host)
  const normalizedSuffix = suffix.trim().toLowerCase().replace(/^\./, '').replace(/\.$/, '')
  return Boolean(normalizedSuffix)
    && (normalizedHost === normalizedSuffix || normalizedHost.endsWith(`.${normalizedSuffix}`))
}

// 完整 URL（含 scheme）拆成 host + path；query / 锚点忽略。其它输入仍按纯文本搜。
export function parseGroupSearchQuery(query: string): GroupSearchQuery {
  const trimmed = unwrapPastedUrl(query)
  const parsed = tryParseAbsoluteUrl(trimmed)
  if (!parsed) return { kind: 'text', text: trimmed.toLowerCase() }
  return { kind: 'url', host: parsed.host, path: parsed.path }
}

export function filterUrlGroups(groups: HostGroup[], query: string, suffix: string): HostGroup[] {
  const parsed = parseGroupSearchQuery(query)
  return groups.flatMap((group) => {
    if (suffix && !hostMatchesSuffix(group.host, suffix)) return []
    if (parsed.kind === 'url') {
      if (normalizeHost(group.host) !== parsed.host) return []
      if (parsed.path === '/') return [group]
      const paths = group.paths.filter((item) => pathMatches(item.path, parsed.path))
      return paths.length ? [{ ...group, paths }] : []
    }

    const normalizedQuery = parsed.text
    if (!normalizedQuery || group.host.toLowerCase().includes(normalizedQuery)) return [group]

    const paths = group.paths.filter((item) => item.path.toLowerCase().includes(normalizedQuery))
    return paths.length ? [{ ...group, paths }] : []
  })
}

function unwrapPastedUrl(query: string): string {
  let value = query.trim()
  if ((value.startsWith('<') && value.endsWith('>')) || (value.startsWith('"') && value.endsWith('"'))
    || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1).trim()
  }
  return value
}

function tryParseAbsoluteUrl(raw: string): { host: string; path: string } | null {
  if (!/^[a-z][a-z+\-.]*:\/\//i.test(raw)) return null
  try {
    const url = new URL(raw)
    const host = normalizeHost(url.hostname)
    if (!host) return null
    return { host, path: normalizePath(url.pathname) }
  } catch {
    return null
  }
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '')
}

function normalizePath(path: string): string {
  if (!path || path === '/') return '/'
  return path.replace(/\/+$/, '') || '/'
}

function pathMatches(stored: string, wanted: string): boolean {
  const actual = normalizePath(stored).toLowerCase()
  const expected = wanted.toLowerCase()
  return actual === expected || actual.startsWith(`${expected}/`) || expected.startsWith(`${actual}/`)
}
