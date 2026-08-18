export function nestedWheelDelta(event: Pick<WheelEvent, 'deltaY' | 'deltaMode'>): number {
  return event.deltaMode === 1 ? event.deltaY * 16 : event.deltaY
}

export function shouldForwardNestedWheel(
  scroller: { scrollTop: number; scrollHeight: number; clientHeight: number } | null,
  deltaY: number,
): boolean {
  if (!scroller || scroller.scrollHeight <= scroller.clientHeight + 1) return true
  if (deltaY < 0 && scroller.scrollTop <= 0) return true
  if (deltaY > 0 && scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight <= 1) return true
  return false
}

export function firstNestedScrollTarget<T extends { scrollTop: number; scrollHeight: number; clientHeight: number }>(
  targets: Array<T | null | undefined>,
  deltaY: number,
): T | null {
  for (const target of targets) {
    if (target && !shouldForwardNestedWheel(target, deltaY)) return target
  }
  return null
}
