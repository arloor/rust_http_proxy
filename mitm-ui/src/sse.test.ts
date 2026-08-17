import { describe, expect, it } from 'vitest'
import { isEventStream, isLargeSseData, limitPrettyLines, parseSseFrames, summarizeSseData } from './sse'

describe('isEventStream', () => {
  it('matches content type case-insensitively and ignores parameters', () => {
    expect(isEventStream([['Content-Type', 'Text/Event-Stream; charset=utf-8']])).toBe(true)
    expect(isEventStream([['content-type', 'application/json']])).toBe(false)
  })
})

describe('parseSseFrames', () => {
  it('parses event metadata, multiline data, comments, and inherited ids', () => {
    expect(parseSseFrames(
      ': heartbeat\r\nid: 7\r\nevent: update\r\ndata: first\r\ndata: second\r\n\r\ndata: next\r\n\r\n',
    )).toEqual([
      {
        event: 'update',
        data: 'first\nsecond',
        hasData: true,
        id: '7',
        retry: null,
        comments: ['heartbeat'],
        unknownFields: [],
        pending: false,
      },
      {
        event: 'message',
        data: 'next',
        hasData: true,
        id: '7',
        retry: null,
        comments: [],
        unknownFields: [],
        pending: false,
      },
    ])
  })

  it('keeps the unfinished trailing frame visible while streaming', () => {
    expect(parseSseFrames('event: token\ndata: hel')).toEqual([{
      event: 'token',
      data: 'hel',
      hasData: true,
      id: null,
      retry: null,
      comments: [],
      unknownFields: [],
      pending: true,
    }])
  })

  it('exposes retry and extension fields without treating invalid retry as valid', () => {
    expect(parseSseFrames('retry: 1500\nx-trace: abc\n\nretry: later\n\n')).toEqual([
      {
        event: 'message',
        data: '',
        hasData: false,
        id: null,
        retry: 1500,
        comments: [],
        unknownFields: [['x-trace', 'abc']],
        pending: false,
      },
      {
        event: 'message',
        data: '',
        hasData: false,
        id: null,
        retry: null,
        comments: [],
        unknownFields: [],
        pending: false,
      },
    ])
  })

  it('ignores extra blank separators and preserves an explicitly empty data field', () => {
    expect(parseSseFrames('data:\n\n\n\ndata: next\n\n')).toEqual([
      {
        event: 'message',
        data: '',
        hasData: true,
        id: null,
        retry: null,
        comments: [],
        unknownFields: [],
        pending: false,
      },
      {
        event: 'message',
        data: 'next',
        hasData: true,
        id: null,
        retry: null,
        comments: [],
        unknownFields: [],
        pending: false,
      },
    ])
  })
})

describe('large SSE payloads', () => {
  it('treats multi-kilobyte data as large and leaves small frames expanded', () => {
    expect(isLargeSseData('x'.repeat(8192))).toBe(true)
    expect(isLargeSseData('{"type":"delta"}')).toBe(false)
  })

  it('summarizes response objects and nested oversized fields', () => {
    const tools = 't'.repeat(9000)
    const instructions = 'i'.repeat(8500)
    const data = JSON.stringify({
      type: 'response.created',
      response: {
        status: 'in_progress',
        model: 'grok-4.6-build',
        output: [],
        tools,
        instructions,
      },
    })
    expect(summarizeSseData(data)).toEqual({
      facts: ['in_progress', 'grok-4.6-build', 'output ×0'],
      largeFields: [
        { name: 'tools', bytes: 9000 },
        { name: 'instructions', bytes: 8500 },
      ],
    })
  })

  it('summarizes function-call items without treating the wrapper as a large field', () => {
    const args = 'a'.repeat(9000)
    expect(summarizeSseData(JSON.stringify({
      type: 'response.output_item.done',
      item: { type: 'function_call', name: 'exec', arguments: args },
    }))).toEqual({
      facts: ['function_call', 'exec'],
      largeFields: [{ name: 'arguments', bytes: 9000 }],
    })
  })

  it('limits pretty-printed lines without splitting the whole payload first', () => {
    expect(limitPrettyLines('a\nb\nc\nd', 2)).toEqual({ text: 'a\nb', hiddenLines: 2, totalLines: 4 })
    expect(limitPrettyLines('only', 8)).toEqual({ text: 'only', hiddenLines: 0, totalLines: 1 })
    expect(limitPrettyLines('', 8)).toEqual({ text: '', hiddenLines: 0, totalLines: 0 })
  })
})
