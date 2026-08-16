import { describe, expect, it } from 'vitest'
import { isEventStream, parseSseFrames } from './sse'

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
