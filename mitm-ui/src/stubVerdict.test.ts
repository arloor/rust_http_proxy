import { describe, expect, it } from 'vitest'
import type { StubMatchResult } from './api'
import { describeVerdict, ruleLabel, summarizeMatch } from './stubVerdict'

const labelOf = (id: string) => ruleLabel(id, ['a', 'b'])
const result = (decided_by: string | null, verdicts: StubMatchResult['verdicts']): StubMatchResult =>
  ({ authority: 'x.com:443', path: '/', url: 'https://x.com/', decided_by, verdicts })

describe('stub verdicts', () => {
  it('labels file and ui rules', () => {
    expect(labelOf('file:x.com:443:0')).toBe('配置文件规则')
    expect(labelOf('b')).toBe('规则 2')
  })

  it('explains why a rule does not apply', () => {
    expect(describeVerdict({ id: 'b', verdict: 'shadowed', matched: true, by: 'a' }, labelOf)).toEqual({ text: '被屏蔽：响应已由「规则 1」决定', active: false })
    expect(describeVerdict({ id: 'b', verdict: 'disabled', matched: true, by: null }, labelOf).text).toBe('已停用（URL 匹配）')
    expect(describeVerdict({ id: 'b', verdict: 'headers', matched: true, by: null }, labelOf).active).toBe(true)
  })

  it('summarizes the final response source', () => {
    expect(summarizeMatch(result(null, []), labelOf)).toBe('没有生效的规则，请求原样发往原始服务')
    expect(summarizeMatch(result(null, [{ id: 'a', verdict: 'headers', matched: true, by: null }]), labelOf)).toBe('响应来自原始服务，1 条规则修改 Header')
    expect(summarizeMatch(result('file:x.com:443:0', []), labelOf)).toBe('响应由「配置文件规则」决定')
  })
})
