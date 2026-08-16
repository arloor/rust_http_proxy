import type { HostGroup } from './api'

export function hostMatchesSuffix(host: string, suffix: string): boolean {
  const normalizedHost = host.trim().toLowerCase().replace(/\.$/, '')
  const normalizedSuffix = suffix.trim().toLowerCase().replace(/^\./, '').replace(/\.$/, '')
  return Boolean(normalizedSuffix)
    && (normalizedHost === normalizedSuffix || normalizedHost.endsWith(`.${normalizedSuffix}`))
}

export function filterUrlGroups(groups: HostGroup[], query: string, suffix: string): HostGroup[] {
  const normalizedQuery = query.trim().toLowerCase()
  return groups.flatMap((group) => {
    if (suffix && !hostMatchesSuffix(group.host, suffix)) return []
    if (!normalizedQuery || group.host.toLowerCase().includes(normalizedQuery)) return [group]

    const paths = group.paths.filter((item) => item.path.toLowerCase().includes(normalizedQuery))
    return paths.length ? [{ ...group, paths }] : []
  })
}
