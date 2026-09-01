import { useState } from 'react'

function AlertRow({ alert, onToggle, open }) {
  const { threat_class, severity, confidence, src_ip, dst_ip, src_port, dst_port,
          proto, occurrences, explanation, ts } = alert
  const when = new Date(ts * 1000).toISOString().substr(11, 8)
  return (
    <>
      <div className="alert-row" onClick={onToggle}>
        <span className={`sev sev-${severity}`}>{severity}</span>
        <span className="threat">{threat_class}</span>
        <span className="mono">
          {src_ip || '?'}:{src_port || '-'} → {dst_ip || '?'}:{dst_port || '-'}
        </span>
        <span className="muted">{proto}</span>
        <span className="conf-bar">
          <span className="conf-fill" style={{ width: `${Math.round(confidence * 100)}%` }} />
        </span>
        <span>{Math.round(confidence * 100)}%</span>
        {occurrences > 1 && <span className="badge">×{occurrences}</span>}
        <span className="spacer" style={{ flex: 1 }} />
        <span className="muted">{when}</span>
      </div>
      {open && (
        <div className="alert-detail">
          <div style={{ marginBottom: 6 }}>{explanation}</div>
          <pre>{JSON.stringify(alert.evidence, null, 2)}</pre>
        </div>
      )}
    </>
  )
}

export default function LiveFeed({ alerts }) {
  const [openId, setOpenId] = useState(null)
  if (!alerts.length) {
    return (
      <div className="panel empty">
        No alerts yet — simulator warmup in progress. Attacks begin after the
        engine has learned its benign baseline.
      </div>
    )
  }
  return (
    <div className="panel" style={{ padding: 0 }}>
      <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)' }}>
        <b>{alerts.length}</b> alert sessions (latest first) — click a row for evidence
      </div>
      {alerts.map((a) => (
        <AlertRow key={a.alert_id} alert={a}
                  open={openId === a.alert_id}
                  onToggle={() => setOpenId(openId === a.alert_id ? null : a.alert_id)} />
      ))}
    </div>
  )
}
