import { describe, expect, it } from 'vitest'
import type { HostGroup } from './api'
import { filterUrlGroups, hostMatchesSuffix, parseGroupSearchQuery } from './urlGroups'

const groups: HostGroup[] = [
  { host: 'example.com', count: 2, last_seen_ms: 3, paths: [{ path: '/root', count: 2, last_seen_ms: 3 }] },
  { host: 'api.example.com', count: 3, last_seen_ms: 4, paths: [
    { path: '/users', count: 2, last_seen_ms: 4 },
    { path: '/events', count: 1, last_seen_ms: 2 },
  ] },
  { host: 'notexample.com', count: 1, last_seen_ms: 1, paths: [{ path: '/users', count: 1, last_seen_ms: 1 }] },
]

describe('hostMatchesSuffix', () => {
  it('matches the exact domain and label-delimited subdomains', () => {
    expect(hostMatchesSuffix('example.com', 'example.com')).toBe(true)
    expect(hostMatchesSuffix('API.Example.Com.', '.example.com')).toBe(true)
    expect(hostMatchesSuffix('notexample.com', 'example.com')).toBe(false)
  })
})

describe('filterUrlGroups', () => {
  it('filters hosts by target suffix without including lookalike domains', () => {
    expect(filterUrlGroups(groups, '', 'example.com').map((group) => group.host)).toEqual([
      'example.com',
      'api.example.com',
    ])
  })

  it('combines suffix filtering with the existing host/path search', () => {
    expect(filterUrlGroups(groups, 'events', 'example.com')).toEqual([{
      ...groups[1],
      paths: [groups[1].paths[1]],
    }])
  })

  it('parses a pasted absolute URL into host and path', () => {
    expect(filterUrlGroups(groups, 'https://api.example.com/users?id=1#top', '')).toEqual([{
      ...groups[1],
      paths: [groups[1].paths[0]],
    }])
  })

  it('matches all paths of that host when the pasted URL has no path', () => {
    expect(filterUrlGroups(groups, 'HTTPS://API.Example.Com.', '')).toEqual([groups[1]])
  })

  it('does not treat a lookalike host as a match for a pasted URL', () => {
    expect(filterUrlGroups(groups, 'https://example.com/users', '')).toEqual([])
  })
})

describe('parseGroupSearchQuery', () => {
  it('extracts host and path and drops query, hash, userinfo, and port', () => {
    expect(parseGroupSearchQuery('https://user:pass@API.Example.Com:8443/users/me?id=1#top')).toEqual({
      kind: 'url',
      host: 'api.example.com',
      path: '/users/me',
    })
  })

  it('unwraps common paste wrappers and treats a bare origin as root path', () => {
    expect(parseGroupSearchQuery('  <http://example.com/>  ')).toEqual({
      kind: 'url',
      host: 'example.com',
      path: '/',
    })
  })

  it('keeps ordinary host/path text as a substring query', () => {
    expect(parseGroupSearchQuery('  /users  ')).toEqual({ kind: 'text', text: '/users' })
    expect(parseGroupSearchQuery('api.example.com/users')).toEqual({
      kind: 'text',
      text: 'api.example.com/users',
    })
  })
})
