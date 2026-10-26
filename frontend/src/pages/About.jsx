export function AboutPage() {
  return (
    <section>
      <header className="page-header">
        <div>
          <h1>About ThreatLens</h1>
          <p>
            Final-year engineering research prototype for explainable hybrid
            intrusion detection — not a commercial security product.
          </p>
        </div>
      </header>

      <div className="panel">
        <h2 className="panel-title">Purpose</h2>
        <p className="muted">
          ThreatLens combines supervised classification and unsupervised anomaly
          detection to identify potentially malicious network traffic, flag
          suspicious behaviour, and provide explainable, risk-scored alerts for
          investigation.
        </p>
      </div>

      <div className="panel">
        <h2 className="panel-title">Components</h2>
        <ul className="about-list">
          <li>
            <strong>Random Forest</strong> — classifies traffic using labelled
            training data (BENIGN / DDoS in the current baseline).
          </li>
          <li>
            <strong>Isolation Forest</strong> — identifies unusual traffic
            patterns without requiring attack labels for scoring.
          </li>
          <li>
            <strong>Hybrid decision engine</strong> — combines both model outputs
            into BENIGN, SUSPICIOUS, or DDoS.
          </li>
          <li>
            <strong>Risk scoring</strong> — prioritises events for investigation
            with a 0–100 heuristic score.
          </li>
          <li>
            <strong>FastAPI</strong> — serves prediction, schema, health, and
            alert-history endpoints.
          </li>
          <li>
            <strong>SQLite</strong> — persists each successful prediction as a
            separate alert occurrence.
          </li>
        </ul>
      </div>

      <div className="panel">
        <h2 className="panel-title">Important limitations</h2>
        <ul className="about-list">
          <li>
            The current model was evaluated on a DDoS-heavy subset of CICIDS2017.
          </li>
          <li>
            An anomaly does not necessarily indicate a cyberattack.
          </li>
          <li>
            Risk scores are heuristic scores, not calibrated attack probabilities.
          </li>
          <li>
            Generalisation to other datasets and real-world traffic has not yet
            been established.
          </li>
          <li>
            ThreatLens does not prevent attacks, does not claim to detect every
            zero-day, and does not claim to outperform commercial security
            products.
          </li>
          <li>
            A successful health check means models/database are ready — not that
            detection is accurate.
          </li>
        </ul>
      </div>
    </section>
  )
}
