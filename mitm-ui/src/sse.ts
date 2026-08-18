export type SseFrame = {
  event: string
  data: string
  hasData: boolean
  id: string | null
  retry: number | null
  comments: string[]
  unknownFields: [string, string][]
  pending: boolean
}

function hasEventStreamContentType(headers: [string, string][]): boolean {
  return headers.some(([name, value]) => {
    if (name.toLowerCase() !== 'content-type') return false
    return value.split(';', 1)[0].trim().toLowerCase() === 'text/event-stream'
  })
}

/**
 * Detect an SSE payload when a server omitted (or supplied the wrong) content type.
 *
 * A `data:` line is the strongest useful signal because it is what dispatches an
 * SSE message. Comment-only streams are also common for heartbeat responses. All
 * other non-empty lines must still be valid field lines so prose containing an
 * incidental `data:` line is not classified as an event stream.
 */
export function looksLikeEventStream(body: string): boolean {
  const normalized = body.replace(/^\uFEFF/, '').replace(/\r\n|\r/g, '\n')
  if (!normalized.trim()) return false

  let dataLines = 0
  let comments = 0
  let knownFields = 0
  let unknownFields = 0

  for (const line of normalized.split('\n')) {
    if (line === '') continue
    if (line.startsWith(':')) {
      comments++
      continue
    }

    const colon = line.indexOf(':')
    const field = colon === -1 ? line : line.slice(0, colon)
    // SSE's field-name grammar is deliberately broad. Requiring a compact field
    // name for sniffing keeps arbitrary prose from passing the body sniff.
    if (!field || /[\0\n\r\s]/.test(field)) return false

    switch (field) {
      case 'data':
        dataLines++
        knownFields++
        break
      case 'event':
      case 'id':
      case 'retry':
        knownFields++
        break
      default:
        unknownFields++
    }
  }

  if (dataLines > 0) {
    // Extension fields are legal, but without an event boundary this shape is
    // indistinguishable from a short YAML/config fragment. Stay conservative.
    return unknownFields === 0 || normalized.includes('\n\n')
  }

  // `id`, `retry`, and `event` lines are valid SSE control frames even when no
  // data is dispatched. Require a completed frame to distinguish them from a
  // single config-style key/value line.
  if (knownFields > 0 && unknownFields === 0 && normalized.includes('\n\n')) return true
  if (comments === 0 || unknownFields > 0) return false

  // A comment-only body is a conventional SSE heartbeat. Do not let a lone
  // colon-prefixed prose line trigger the event view unless it has a boundary
  // or another SSE signal.
  return normalized.includes('\n\n') || comments + knownFields > 1
}

export function isEventStream(headers: [string, string][], body = ''): boolean {
  return hasEventStreamContentType(headers) || looksLikeEventStream(body)
}

export function parseSseFrames(body: string): SseFrame[] {
  if (!body) return []

  const normalized = body.replace(/^\uFEFF/, '').replace(/\r\n|\r/g, '\n')
  const blocks = normalized.split('\n\n')
  const hasPendingBlock = !normalized.endsWith('\n\n')
  if (!hasPendingBlock) blocks.pop()

  let lastEventId: string | null = null
  return blocks.flatMap((block, index) => {
    if (block.split('\n').every((line) => line === '')) return []

    let event = 'message'
    const data: string[] = []
    const comments: string[] = []
    const unknownFields: [string, string][] = []
    let retry: number | null = null
    for (const line of block.split('\n')) {
      if (line.startsWith(':')) {
        comments.push(line.slice(1).replace(/^ /, ''))
        continue
      }
      const colon = line.indexOf(':')
      const field = colon === -1 ? line : line.slice(0, colon)
      const value = colon === -1 ? '' : line.slice(colon + 1).replace(/^ /, '')
      switch (field) {
        case 'event':
          event = value || 'message'
          break
        case 'data':
          data.push(value)
          break
        case 'id':
          if (!value.includes('\0')) lastEventId = value
          break
        case 'retry':
          if (/^\d+$/.test(value)) retry = Number(value)
          break
        case '':
          break
        default:
          unknownFields.push([field, value])
      }
    }

    return [{
      event,
      data: data.join('\n'),
      hasData: data.length > 0,
      id: lastEventId,
      retry,
      comments,
      unknownFields,
      pending: hasPendingBlock && index === blocks.length - 1,
    }]
  })
}

/** Byte threshold for collapsed-summary field chips only; cards collapse by rendered height. */
export const LARGE_SSE_BYTES = 8 * 1024
export const SSE_PREVIEW_LINES = 80

export function isLargeSseData(data: string): boolean {
  return data.length >= LARGE_SSE_BYTES
}

export type SseLargeField = {
  name: string
  bytes: number
}

export type SseDataSummary = {
  facts: string[]
  largeFields: SseLargeField[]
}

function jsonBytes(value: unknown): number {
  if (typeof value === 'string') return value.length
  try {
    return JSON.stringify(value)?.length ?? 0
  } catch {
    return 0
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null
}

function collectLargeFields(record: Record<string, unknown>, nested: Set<string>): SseLargeField[] {
  const fields: SseLargeField[] = []
  for (const [name, value] of Object.entries(record)) {
    if (nested.has(name) && asRecord(value)) continue
    const bytes = jsonBytes(value)
    if (bytes >= LARGE_SSE_BYTES) fields.push({ name, bytes })
  }
  return fields
}

export function summarizeSseData(data: string): SseDataSummary | null {
  const trimmed = data.trim()
  if (!trimmed) return null
  try {
    const value = JSON.parse(trimmed) as unknown
    const root = asRecord(value)
    if (!root) return { facts: [], largeFields: [] }

    const response = asRecord(root.response)
    const item = asRecord(root.item)
    const facts: string[] = []
    const status = response?.status ?? root.status
    if (typeof status === 'string' || typeof status === 'number') facts.push(String(status))
    const model = response?.model ?? root.model
    if (typeof model === 'string' && model) facts.push(model)
    const itemType = item?.type
    if (typeof itemType === 'string' && itemType) facts.push(itemType)
    const itemName = item?.name
    if (typeof itemName === 'string' && itemName) facts.push(itemName)
    const output = response?.output ?? root.output
    if (Array.isArray(output)) facts.push(`output ×${output.length}`)

    const largeFields = [
      ...collectLargeFields(root, new Set(['response', 'item'])),
      ...collectLargeFields(response ?? {}, new Set()),
      ...collectLargeFields(item ?? {}, new Set()),
    ].sort((left, right) => right.bytes - left.bytes)

    return { facts, largeFields }
  } catch {
    return { facts: [], largeFields: [] }
  }
}

export function limitPrettyLines(pretty: string, maxLines: number): {
  text: string
  hiddenLines: number
  totalLines: number
} {
  if (!pretty) return { text: pretty, hiddenLines: 0, totalLines: 0 }
  let totalLines = 1
  let cut = -1
  for (let index = 0; index < pretty.length; index++) {
    if (pretty.charCodeAt(index) !== 10) continue
    if (totalLines === maxLines && cut === -1) cut = index
    totalLines++
  }
  if (cut === -1) return { text: pretty, hiddenLines: 0, totalLines }
  return {
    text: pretty.slice(0, cut),
    hiddenLines: totalLines - maxLines,
    totalLines,
  }
}
