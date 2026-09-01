import { useCallback, useEffect, useRef, useState } from 'react'

export function useWs(url) {
  const [connected, setConnected] = useState(false)
  const [snapshot, setSnapshot] = useState(null)
  const [message, setMessage] = useState(null)
  const wsRef = useRef(null)

  useEffect(() => {
    let closed = false
    let retry = 1000

    const connect = () => {
      const ws = new WebSocket(url)
      wsRef.current = ws
      ws.onopen = () => { setConnected(true); retry = 1000 }
      ws.onclose = () => {
        if (closed) return
        setConnected(false)
        setTimeout(connect, retry)
        retry = Math.min(retry * 2, 10000)
      }
      ws.onerror = () => ws.close()
      ws.onmessage = (ev) => {
        const data = JSON.parse(ev.data)
        if (data.type === 'snapshot') setSnapshot(data)
        else setMessage(data)
      }
    }
    connect()
    return () => { closed = true; wsRef.current?.close() }
  }, [url])

  return { connected, snapshot, message }
}
