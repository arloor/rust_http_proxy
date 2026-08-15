import { describe, expect, it } from 'vitest'
import { fullUrl } from './api'

describe('fullUrl', () => {
  it('includes query when present', () => {
    expect(fullUrl({ authority: 'api.example.com', path: '/v1/users', query: 'page=2' })).toBe(
      'https://api.example.com/v1/users?page=2',
    )
  })
})
