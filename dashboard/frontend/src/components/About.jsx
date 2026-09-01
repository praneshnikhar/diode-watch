export default function About() {
  return (
    <>
      <div className="panel">
        <div className="label" style={{ marginBottom: 10 }}>What this is</div>
        <p>
          Critical-infrastructure operators watch their gateway links through a{' '}
          <b>one-way data diode</b>: the monitoring enclave can see every packet but has{' '}
          <b>no physical or protocol-level path back</b>. Diode Watch is an AI/ML pipeline
          that lives entirely inside that enclave — it ingests a stream of flow records,
          detects / classifies / scores six threat families in near real time, and emits
          standardized, evidence-backed alerts to a live dashboard.
        </p>
      </div>

      <div className="panel">
        <div className="label" style={{ marginBottom: 10 }}>Architectural constraints honoured</div>
        <ul style={{ lineHeight: 1.9 }}>
          <li><b>Read-only ingest</b> — no probes, no handshakes, no re-contact; the simulator
              emits flows and the engine never sends anything back.</li>
          <li><b>No payload decryption</b> — TLS/QUIC analysed from JA3 fingerprints,
              ClientHello/ServerHello sizes, cert depth and timing only.</li>
          <li><b>Streaming, not batch</b> — bounded-latency per-flow processing with
              sliding windows; stated throughput target of 2000 flows/sec, measured live.</li>
          <li><b>Standardized alert schema</b> — timestamp, flow id, threat class,
              confidence, severity, supporting evidence features.</li>
        </ul>
      </div>

      <div className="panel">
        <div className="label" style={{ marginBottom: 10 }}>Threat coverage</div>
        <table className="eval-table">
          <thead>
            <tr><th>Threat</th><th>Detection approach</th></tr>
          </thead>
          <tbody>
            {[
              ['Volumetric / protocol DDoS', 'rate + source-IP entropy + SYN/amplification ratios + IsolationForest window profile'],
              ['Botnet C2 beaconing', 'inter-arrival CV + FFT periodogram peak significance'],
              ['DGA domains / DNS tunnelling', 'LightGBM classifier (entropy, n-gram anomaly, TLD…) + tunnelling heuristics'],
              ['Malware in TLS', 'JA3 denylist + IsolationForest over TLS metadata'],
              ['Recon / port scanning', 'per-source fan-out (vertical & horizontal) counting'],
              ['Data exfiltration', 'out/in byte ratio + per-host EWMA volume anomaly'],
            ].map(([t, m]) => (
              <tr key={t}><td className="threat">{t}</td><td className="muted">{m}</td></tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <div className="label" style={{ marginBottom: 10 }}>Stack</div>
        <div className="muted" style={{ lineHeight: 2 }}>
          Python 3.12 · Redis Streams · TimescaleDB · scikit-learn / LightGBM / scipy ·
          FastAPI + WebSockets · React + Vite + Recharts · n8n orchestration ·
          Prometheus (+ Grafana profile) · Docker Compose — 100% open source.
        </div>
      </div>
    </>
  )
}
