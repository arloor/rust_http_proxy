export type Settings = {
  capture_enabled: boolean
  ca_available: boolean
  max_records: number
  body_limit_bytes: number
  db_bytes: number
}

export type Target = { id: number; suffix: string; created_at_ms: number; cli_managed: boolean }

export type RecordSummary = {
  id: string
  started_at_ms: number
  completed_at_ms: number | null
  client_ip: string
  client_port: number
  proxy_username: string
  authority: string
  host: string
  path: string
  query: string | null
  method: string
  status: number | null
  duration_ms: number | null
  capture_state: string
}

export type RecordDetail = RecordSummary & {
  request_version: string
  request_headers: [string, string][]
  request_body: string
  request_body_bytes: number
  request_body_truncated: boolean
  request_body_note: string | null
  request_body_image: string | null
  response_version: string | null
  response_headers: [string, string][]
  response_body: string
  response_body_bytes: number
  response_body_truncated: boolean
  response_body_note: string | null
  response_body_image: string | null
  error: string | null
}

export type RecordPage = { records: RecordSummary[]; next_before: number | null; total: number }
export type PathGroup = { path: string; count: number; last_seen_ms: number }
export type HostGroup = { host: string; count: number; last_seen_ms: number; paths: PathGroup[] }
export type TlsErrorGroup = { authority: string; client_ip: string; count: number; last_seen_ms: number }

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/mitm/api${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ error: response.statusText }))
    throw new Error(payload.error || response.statusText)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export function fullUrl(record: Pick<RecordSummary, 'authority' | 'path' | 'query'>): string {
  return `https://${record.authority}${record.path}${record.query ? `?${record.query}` : ''}`
}
