import { useCallback, useEffect, useRef, useState } from 'react'

export function useCopyToClipboard(timeoutMs = 1400) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<number | null>(null)

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
  }, [])

  useEffect(() => clearTimer, [clearTimer])

  const reset = useCallback(() => {
    clearTimer()
    setCopied(false)
  }, [clearTimer])

  const copy = useCallback(
    async (text: string) => {
      clearTimer()
      try {
        await navigator.clipboard.writeText(text)
        setCopied(true)
        timerRef.current = window.setTimeout(() => {
          setCopied(false)
          timerRef.current = null
        }, timeoutMs)
        return true
      } catch {
        setCopied(false)
        return false
      }
    },
    [clearTimer, timeoutMs],
  )

  return { copied, copy, reset }
}
