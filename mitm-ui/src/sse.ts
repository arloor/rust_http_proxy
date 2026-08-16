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

export function isEventStream(headers: [string, string][]): boolean {
  return headers.some(([name, value]) => {
    if (name.toLowerCase() !== 'content-type') return false
    return value.split(';', 1)[0].trim().toLowerCase() === 'text/event-stream'
  })
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
