import type { StubMatchResult, StubRuleVerdict } from './api'

export function ruleLabel(id: string, uiIds: string[]): string {
  if (id.startsWith('file:')) return '配置文件规则'
  const index = uiIds.indexOf(id)
  return index < 0 ? '其他规则' : `规则 ${index + 1}`
}

export function describeVerdict(verdict: StubRuleVerdict, labelOf: (id: string) => string): { text: string; active: boolean } {
  switch (verdict.verdict) {
    case 'response': return { text: '决定响应', active: true }
    case 'headers': return { text: '修改 Header', active: true }
    case 'shadowed': return { text: `被屏蔽：响应已由「${labelOf(verdict.by ?? '')}」决定`, active: false }
    case 'disabled': return { text: verdict.matched ? '已停用（URL 匹配）' : '已停用 · 未匹配', active: false }
    case 'unmatched': return { text: '未匹配', active: false }
  }
}

export function summarizeMatch(result: StubMatchResult, labelOf: (id: string) => string): string {
  const headerRules = result.verdicts.filter((item) => item.verdict === 'headers').length
  if (!result.decided_by && !headerRules) return '没有生效的规则，请求原样发往原始服务'
  const source = result.decided_by ? `响应由「${labelOf(result.decided_by)}」决定` : '响应来自原始服务'
  return headerRules ? `${source}，${headerRules} 条规则修改 Header` : source
}
