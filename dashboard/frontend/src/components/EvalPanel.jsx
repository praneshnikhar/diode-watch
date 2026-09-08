export default function EvalPanel({ evalData }) {
  if (!evalData || !evalData.per_class || !Object.keys(evalData.per_class).length) {
    return (
      <div className="panel empty">
        Waiting for attack episodes… The simulator emits ground-truth labels on
        a side channel the detection engine never sees; every alert session is
        matched against those labels to produce live precision/recall.
      </div>
    )
  }
  const o = evalData.overall
  return (
    <>
      <div className="cards">
        <div className="card">
          <div className="label">Precision</div>
          <div className="value">{o.precision}</div>
          <div className="sub">TP / (TP + FP) across alert sessions</div>
        </div>
        <div className="card">
          <div className="label">Recall</div>
          <div className="value">{o.recall}</div>
          <div className="sub">attack episodes detected</div>
        </div>
        <div className="card">
          <div className="label">F1</div>
          <div className="value">{o.f1}</div>
          <div className="sub">harmonic mean</div>
        </div>
        <div className="card">
          <div className="label">Ground truth</div>
          <div className="value">{evalData.truth_flows_seen.toLocaleString()}</div>
          <div className="sub">labelled attack flows observed</div>
        </div>
      </div>

      <div className="panel" style={{ padding: 0, overflowX: 'auto' }}>
        <table className="eval-table">
          <thead>
            <tr>
              <th>Threat class</th><th>TP</th><th>FP</th><th>FN</th>
              <th>Precision</th><th>Recall</th><th>F1</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(evalData.per_class).map(([cls, m]) => (
              <tr key={cls}>
                <td className="threat">{cls}</td>
                <td>{m.tp}</td><td>{m.fp}</td><td>{m.fn}</td>
                <td>{m.precision}</td><td>{m.recall}</td><td>{m.f1}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel muted" style={{ fontSize: 12 }}>
        Method: attack flows carry ground-truth labels on a separate Redis stream
        that the detection engine never reads (enforcing the one-way constraint).
        Consecutive attack flows with the same class+source are grouped into an
        episode (campaign). An alert that overlaps a campaign counts as a hit —
        the first alert covering it is a TP, repeat alerts on the same ongoing
        campaign are deduplicated, and an alert with no campaign overlap is an FP.
        Episodes never covered by any alert after a grace window are FN.
        Evaluation is therefore campaign-level, not flow-level.
      </div>
    </>
  )
}
