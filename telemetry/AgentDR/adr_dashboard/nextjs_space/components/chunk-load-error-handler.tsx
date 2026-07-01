'use client'

// IMPORTANT: Do not remove this component.
// It handles a known Next.js dev server race condition where dynamic chunks
// imported by next/dynamic haven't been compiled yet and cause webpack to throw
// a ChunkLoadError

import { useEffect } from 'react'

export function ChunkLoadErrorHandler() {
  useEffect(() => {
    const handler = (event: ErrorEvent) => {
      if (
        event.error?.name === 'ChunkLoadError' ||
        event.error?.message?.includes('Loading chunk')
      ) {
        event.preventDefault()
        window.location.reload()
      }
    }
    window.addEventListener('error', handler)
    return () => window.removeEventListener('error', handler)
  }, [])

  return null
}
