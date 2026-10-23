/** Coalesce invalidations without postponing work under continuous traffic. */
export function createRefreshQueue<T>(delay: number, refresh: (dirty: Set<T>) => Promise<void>) {
  let dirty = new Set<T>()
  let timer: ReturnType<typeof setTimeout> | undefined
  let running = false
  let disposed = false
  const schedule = () => {
    if (disposed || running || timer !== undefined || dirty.size === 0) return
    timer = setTimeout(async () => {
      timer = undefined
      const batch = dirty
      dirty = new Set<T>()
      running = true
      try {
        await refresh(batch)
      } finally {
        running = false
        schedule()
      }
    }, delay)
  }
  return {
    add(...keys: T[]) {
      if (disposed) return
      keys.forEach((key) => dirty.add(key))
      schedule()
    },
    dispose() {
      disposed = true
      clearTimeout(timer)
      dirty.clear()
    },
  }
}
