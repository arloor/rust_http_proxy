import { describe, expect, it } from 'vitest'
import type { HostGroup } from './api'
import { filterUrlGroups, hostMatchesSuffix } from './urlGroups'

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
})
