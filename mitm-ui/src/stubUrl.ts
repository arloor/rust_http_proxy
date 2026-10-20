// Exact rules are stored as CONNECT authority (host:port) + path; the UI edits them as one HTTPS URL.

export function exactRuleUrl(authority: string, path: string): string {
  return `https://${authority.endsWith(':443') ? authority.slice(0, -4) : authority}${path}`
}

export type ParsedExactUrl = { authority: string; path: string; ignoredQuery: boolean }

export function parseExactUrl(input: string): ParsedExactUrl | { error: string } {
  let rest = input.trim()
  const scheme = /^([a-z][a-z\d+.-]*):\/\//i.exec(rest)
  if (scheme) {
    if (scheme[1].toLowerCase() !== 'https') return { error: 'MITM 只解密 HTTPS，请使用 https:// 地址' }
    rest = rest.slice(scheme[0].length)
  }
  const split = rest.search(/[/?#]/)
  const host = (split < 0 ? rest : rest.slice(0, split)).toLowerCase()
  const tail = split < 0 ? '' : rest.slice(split)
  if (!host) return { error: '请填写地址，例如 https://api.example.com/api/profile' }
  if (/\s/.test(host) || host.includes('@')) return { error: '域名格式无效' }
  const pathEnd = tail.search(/[?#]/)
  const path = (pathEnd < 0 ? tail : tail.slice(0, pathEnd)) || '/'
  const hasPort = /:\d+$/.test(host)
  return { authority: hasPort ? host : `${host}:443`, path, ignoredQuery: pathEnd >= 0 && tail.length > pathEnd + 1 }
}

/** Starting point when switching an exact rule to regex: the same URL as plain text, without query. */
export function regexFromExactUrl(input: string): string {
  const parsed = parseExactUrl(input)
  return 'error' in parsed ? '' : exactRuleUrl(parsed.authority, parsed.path)
}
