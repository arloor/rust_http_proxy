import { describe, expect, it } from 'vitest'
import { domainSuffixes } from './domainSuffixes'

describe('domainSuffixes', () => {
  it('offers every selectable domain suffix level except a bare TLD', () => {
    expect(domainSuffixes('API.us.Example.COM.')).toEqual([
      'api.us.example.com',
      'us.example.com',
      'example.com',
    ])
  })

  it('keeps localhost and IP addresses exact', () => {
    expect(domainSuffixes('localhost')).toEqual(['localhost'])
    expect(domainSuffixes('127.0.0.1')).toEqual(['127.0.0.1'])
    expect(domainSuffixes('[::1]')).toEqual(['::1'])
  })
})
