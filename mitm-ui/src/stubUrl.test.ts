import { describe, expect, it } from 'vitest'
import { exactRuleUrl, parseExactUrl, regexFromExactUrl } from './stubUrl'

describe('exact stub URLs', () => {
  it('defaults to port 443 and strips query and fragment', () => {
    expect(parseExactUrl('https://API.example.com/api/profile?id=1#top')).toEqual({
      authority: 'api.example.com:443', path: '/api/profile', ignoredQuery: true,
    })
    expect(parseExactUrl('api.example.com')).toEqual({ authority: 'api.example.com:443', path: '/', ignoredQuery: false })
    expect(parseExactUrl('https://localhost:8443/a/b?')).toEqual({ authority: 'localhost:8443', path: '/a/b', ignoredQuery: false })
  })

  it('rejects non-HTTPS schemes and empty hosts', () => {
    expect(parseExactUrl('http://api.example.com/')).toHaveProperty('error')
    expect(parseExactUrl('https:///path')).toHaveProperty('error')
    expect(parseExactUrl('   ')).toHaveProperty('error')
  })

  it('hides the default port when displaying', () => {
    expect(exactRuleUrl('api.example.com:443', '/x')).toBe('https://api.example.com/x')
    expect(exactRuleUrl('api.example.com:8443', '/x')).toBe('https://api.example.com:8443/x')
  })

  it('seeds the regex with the plain URL, without anchors, escaping or query', () => {
    expect(regexFromExactUrl('https://api.example.com/v1/users?q=1')).toBe('https://api.example.com/v1/users')
    expect(regexFromExactUrl('ftp://x')).toBe('')
  })
})
