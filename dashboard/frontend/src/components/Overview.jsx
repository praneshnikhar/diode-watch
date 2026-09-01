import { useMemo } from 'react'
import {
  Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'

const SEV_COLORS = { CRITICAL: '#f87171', HIGH: '#fb923c', MEDIUM: '#facc15', LOW: '#94a3b8' }

export default function Overview({ alerts, history, events }) {
  const byClass = useMemo(() => {
    const m = {}
    alerts.forEach((a) => { m[a.threat_class] = (m[a.threat_class] || 0) + 1 })
    return Object.entries(m).map(([name, count]) => ({ name, count }))
  }, [alerts])

  const bySev = useMemo(() => {
    const m = {}
    alerts.forEach((a) => { m[a.severity] = (m[a.severity] || 0) + 1 })
    return Object.entries(m).map(([name, value]) => ({ name, value }))
  }, [alerts])

  const last = history[history.length - 1]

  return (
    <>
      <div className="cards">
        <div className="card">
          <div className="label">Throughput</div>
          <div className="value">{last?.flows_per_sec ?? '—'}</div>
          <div className="sub">flows/sec · target {last?.throughput_target ?? 2000}</div>
        </div>
        <div className="card">
          <div className="label">Flows processed</div>
          <div className="value">{last?.flows_total?.toLocaleString() ?? '—'}</div>
          <div className="sub">since engine start</div>
        </div>
        <div className="card">
          <div className="label">Alert sessions</div>
          <div className="value">{alerts.length}</div>
          <div className="sub">in live feed window</div>
        </div>
        <div className="card">
          <div className="label">Alerts / sec</div>
          <div className="value">{last?.alerts_per_sec ?? '—'}</div>
          <div className="sub">current emission rate</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="panel">
          <div className="label" style={{ marginBottom: 10 }}>Alerts by threat class</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={byClass}>
              <CartesianGrid stroke="#1e2836" strokeDasharray="3 3" />
              <XAxis dataKey="name" stroke="#6b7a8d" fontSize={10}
                     interval={0} angle={-25} textAnchor="end" height={70} />
              <YAxis stroke="#6b7a8d" fontSize={10} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#11161f', border: '1px solid #1e2836' }} />
              <Bar dataKey="count" fill="#38bdf8" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="panel">
          <div className="label" style={{ marginBottom: 10 }}>Severity distribution</div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={bySev} dataKey="value" nameKey="name"
                   innerRadius={50} outerRadius={80} paddingAngle={3}>
                {bySev.map((e) => <Cell key={e.name} fill={SEV_COLORS[e.name]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: '#11161f', border: '1px solid #1e2836' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="panel">
        <div className="label" style={{ marginBottom: 10 }}>Throughput (flows/sec, real time)</div>
        <ResponsiveContainer width="100%" height={180}>
          <LineChart data={history}>
            <CartesianGrid stroke="#1e2836" strokeDasharray="3 3" />
            <XAxis dataKey="ts" stroke="#6b7a8d" fontSize={10}
                   tickFormatter={(t) => new Date(t * 1000).toISOString().substr(14, 5)} />
            <YAxis stroke="#6b7a8d" fontSize={10} />
            <Tooltip contentStyle={{ background: '#11161f', border: '1px solid #1e2836' }} />
            <Line type="monotone" dataKey="flows_per_sec" stroke="#4dd0a1" dot={false} strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="panel">
        <div className="label" style={{ marginBottom: 8 }}>Engine events</div>
        <div className="events">
          {events.length ? events.map((e, i) => (
            <div key={i} className="event-line">{e}</div>
          )) : <div className="muted">waiting for engine events…</div>}
        </div>
      </div>
    </>
  )
}
