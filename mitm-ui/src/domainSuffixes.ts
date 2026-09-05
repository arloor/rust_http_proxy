export function domainSuffixes(host: string): string[] {
  const normalized = host.trim().replace(/^\[|\]$/g, '').replace(/\.+$/, '').toLowerCase()
  if (!normalized) return []
  if (normalized === 'localhost' || normalized.includes(':') || /^\d{1,3}(\.\d{1,3}){3}$/.test(normalized)) {
    return [normalized]
  }
  const labels = normalized.split('.').filter(Boolean)
  if (labels.length < 2) return [normalized]
  return labels.slice(0, -1).map((_, index) => labels.slice(index).join('.'))
}
