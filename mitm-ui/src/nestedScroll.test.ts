import { describe, expect, it } from 'vitest'
import { firstNestedScrollTarget, nestedWheelDelta, shouldForwardNestedWheel } from './nestedScroll'

describe('shouldForwardNestedWheel', () => {
  it('forwards when the inner event cannot scroll', () => {
    expect(shouldForwardNestedWheel({ scrollTop: 0, scrollHeight: 120, clientHeight: 120 }, 40)).toBe(true)
    expect(shouldForwardNestedWheel(null, 40)).toBe(true)
  })

  it('keeps the gesture on a large event until it hits a boundary', () => {
    const scroller = { scrollTop: 40, scrollHeight: 400, clientHeight: 120 }
    expect(shouldForwardNestedWheel(scroller, 40)).toBe(false)
    expect(shouldForwardNestedWheel(scroller, -40)).toBe(false)
  })

  it('forwards at the top and bottom of a large event', () => {
    expect(shouldForwardNestedWheel({ scrollTop: 0, scrollHeight: 400, clientHeight: 120 }, -40)).toBe(true)
    expect(shouldForwardNestedWheel({ scrollTop: 280, scrollHeight: 400, clientHeight: 120 }, 40)).toBe(true)
  })
})

describe('nestedWheelDelta', () => {
  it('keeps pixel deltas and converts line deltas', () => {
    expect(nestedWheelDelta({ deltaY: 32, deltaMode: 0 })).toBe(32)
    expect(nestedWheelDelta({ deltaY: 3, deltaMode: 1 })).toBe(48)
  })
})

describe('firstNestedScrollTarget', () => {
  const event = { scrollTop: 0, scrollHeight: 120, clientHeight: 120 }
  const list = { scrollTop: 80, scrollHeight: 800, clientHeight: 240 }
  const detail = { scrollTop: 40, scrollHeight: 900, clientHeight: 400 }

  it('keeps the gesture on the event list until that list hits a boundary', () => {
    expect(firstNestedScrollTarget([event, list, detail], 40)).toBe(list)
    expect(firstNestedScrollTarget([event, { ...list, scrollTop: 0 }, detail], -40)).toBe(detail)
    expect(firstNestedScrollTarget([event, { ...list, scrollTop: 560 }, detail], 40)).toBe(detail)
  })

  it('falls through when every layer is already at its boundary', () => {
    expect(firstNestedScrollTarget([event, { ...list, scrollTop: 0 }, { ...detail, scrollTop: 0 }], -40)).toBe(null)
  })
})
