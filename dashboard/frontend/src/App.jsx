import { useEffect, useRef, useState } from 'react'
import LiveFeed from './components/LiveFeed.jsx'
import Overview from './components/Overview.jsx'
import EvalPanel from './components/EvalPanel.jsx'
import About from './components/About.jsx'
import { useWs } from './hooks/useWs.js'

const WS_URL =
  (window.location.protocol === 'https:' ? 'wss://' : 'ws://') +
  window.location.host + '/ws'

export default function App() {
  const { connected, snapshot, message } = useWs(WS_URL)
  const [tab, setTab] = useState('feed')
  const [alerts, setAlerts] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [history, setHistory] = useState([])
  const [evalData, setEvalData] = useState(null)
  const [events, setEvents] = useState([])

  useEffect(() => {
    if (snapshot) {
      setAlerts(snapshot.alerts || [])
      setEvalData(snapshot.eval || null)
    }
  }, [snapshot])

  useEffect(() => {
    if (!message) return
    switch (message.type) {
      case 'alert': {
        const a = message.alert
        setAlerts((prev) => {
          const rest = prev.filter((x) => x.alert_id !== a.alert_id)
          return [a, ...rest].slice(0, 300)
        })
        break
      }
      case 'metrics':
        setMetrics(message)
        setHistory((h) => [...h, message].slice(-180))
        break
      case 'eval':
        setEvalData(message)
        break
      case 'event':
        setEvents((e) => [JSON.stringify(message), ...e].slice(0, 30))
        break
    }
  }, [message])

  return (
    <div>
      <header className="app-header">
        <span className="app-title">DIODE<span className="accent">WATCH</span></span>
        <span className="badge">
          <span className={`dot ${connected ? 'on' : 'off'}`} />
          {connected ? 'stream live' : 'reconnecting'}
        </span>
        <span className="badge">flows/s <b>{metrics?.flows_per_sec ?? '—'}</b></span>
        <span className="badge">alerts <b>{alerts.length}</b></span>
        <span className="badge">target <b>{metrics?.throughput_target ?? 2000}/s</b></span>
        <span className="spacer" />
        <span className="badge">passive · read-only · no decryption</span>
      </header>

      <div className="tabs">
        {[['feed', 'Live Feed'], ['overview', 'Overview'], ['eval', 'Evaluation'], ['about', 'About']]
          .map(([id, label]) => (
            <button key={id} className={`tab ${tab === id ? 'active' : ''}`}
                    onClick={() => setTab(id)}>{label}</button>
          ))}
      </div>

      <div className="content">
        {tab === 'feed' && <LiveFeed alerts={alerts} />}
        {tab === 'overview' && <Overview alerts={alerts} history={history} events={events} />}
        {tab === 'eval' && <EvalPanel evalData={evalData} />}
        {tab === 'about' && <About />}
      </div>
    </div>
  )
}
