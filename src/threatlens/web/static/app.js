(() => {
  "use strict";

  const els = {
    healthChip: document.getElementById("health-chip"),
    featurePill: document.getElementById("feature-count-pill"),
    healthDetail: document.getElementById("health-detail"),
    featureJson: document.getElementById("feature-json"),
    btnPredict: document.getElementById("btn-predict"),
    btnZeros: document.getElementById("btn-zeros"),
    btnDemo: document.getElementById("btn-demo"),
    btnSchema: document.getElementById("btn-schema"),
    copyUvicornButtons: document.querySelectorAll(".copy-command"),
    errorBanner: document.getElementById("error-banner"),
    alertList: document.getElementById("alert-list"),
    alertsEmpty: document.getElementById("alerts-empty"),
    schemaDialog: document.getElementById("schema-dialog"),
    schemaList: document.getElementById("schema-list"),
  };

  let featureNames = [];

  async function api(path, options) {
    const response = await fetch(path, options);
    let body = null;
    const text = await response.text();
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = { detail: text };
      }
    }
    if (!response.ok) {
      const detail =
        (body && (body.detail || body.error)) ||
        `Request failed (${response.status})`;
      const message = typeof detail === "string" ? detail : JSON.stringify(detail);
      throw new Error(message);
    }
    return body;
  }

  function setHealthUi(health) {
    const ready = Boolean(health.models_ready);
    els.healthChip.textContent = ready ? "Models ready" : "Models not ready";
    els.healthChip.className =
      "status-chip " + (ready ? "status-chip--ready" : "status-chip--down");
    els.featurePill.textContent = ready
      ? `${health.feature_count} features loaded`
      : "Schema unavailable";
    els.btnPredict.disabled = !ready;

    const rows = [
      ["Status", health.status],
      ["RF loaded", health.random_forest_loaded ? "yes" : "no"],
      ["IF loaded", health.isolation_forest_loaded ? "yes" : "no"],
      ["Features", String(health.feature_count ?? "—")],
    ];
    els.healthDetail.innerHTML = rows
      .map(
        ([k, v]) =>
          `<div><dt>${k}</dt><dd>${escapeHtml(String(v))}</dd></div>`
      )
      .join("");
  }

  function escapeHtml(value) {
    return value
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function showError(message) {
    els.errorBanner.hidden = false;
    els.errorBanner.textContent = message;
  }

  function clearError() {
    els.errorBanner.hidden = true;
    els.errorBanner.textContent = "";
  }

  function zeroRecord() {
    const record = {};
    for (const name of featureNames) record[name] = 0;
    return record;
  }

  /** Synthetic DDoS-shaped values for UI demos only — not real traffic. */
  function demoRecord() {
    const record = zeroRecord();
    const bump = {
      "Flow Duration": 120000,
      "Total Fwd Packets": 180,
      "Total Backward Packets": 2,
      "Total Length of Fwd Packets": 92000,
      "Flow Bytes/s": 4500000,
      "Flow Packets/s": 1800,
      "Fwd Packets/s": 1750,
      "Packet Length Mean": 512,
      "Average Packet Size": 520,
      "SYN Flag Count": 1,
      "ACK Flag Count": 1,
      "Init_Win_bytes_forward": 65535,
      "Idle Max": 50000,
      "Idle Mean": 20000,
    };
    for (const [key, value] of Object.entries(bump)) {
      if (key in record) record[key] = value;
    }
    return record;
  }

  function writeRecord(record) {
    els.featureJson.value = JSON.stringify(record, null, 2);
  }

  function renderAlerts(alerts) {
    if (!alerts.length) {
      els.alertsEmpty.hidden = false;
      els.alertList.innerHTML = "";
      return;
    }
    els.alertsEmpty.hidden = true;
    els.alertList.innerHTML = alerts.map(alertCard).join("");
    animateRiskScores();
  }

  function alertCard(alert) {
    const decision = alert.final_decision || "UNKNOWN";
    const scores = alert.supporting_scores || {};
    const components = alert.score_components || {};
    const notes = (alert.notes || []).map((n) => escapeHtml(String(n))).join(" · ");

    const scoreItems = [
      ...Object.entries(scores).map(([k, v]) => [k, formatNum(v)]),
      ...Object.entries(components).map(([k, v]) => [k, formatNum(v)]),
    ]
      .slice(0, 8)
      .map(
        ([k, v]) =>
          `<div><span>${escapeHtml(k)}</span><strong>${escapeHtml(v)}</strong></div>`
      )
      .join("");

    return `
      <article class="alert-card alert-card--${escapeHtml(decision)}">
        <div class="alert-top">
          <h3 class="alert-decision">${escapeHtml(decision)}</h3>
          <div class="risk-meter">
            <span>Risk score</span>
            <strong data-risk="${Number(alert.risk_score) || 0}">0</strong>
          </div>
        </div>
        <p class="alert-id">${escapeHtml(alert.alert_id || "")}</p>
        <p class="alert-explain">${escapeHtml(alert.explanation || alert.reason || "")}</p>
        <div class="vote-row">
          <span class="vote">RF <b>${escapeHtml(alert.random_forest_prediction || "—")}</b></span>
          <span class="vote">IF <b>${escapeHtml(alert.isolation_forest_prediction || "—")}</b></span>
        </div>
        <div class="score-grid">${scoreItems}</div>
        ${notes ? `<p class="hint">${notes}</p>` : ""}
      </article>
    `;
  }

  function formatNum(value) {
    if (value === null || value === undefined) return "—";
    if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(4);
    return String(value);
  }

  function animateRiskScores() {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      document.querySelectorAll("[data-risk]").forEach((node) => {
        node.textContent = String(Math.round(Number(node.dataset.risk) || 0));
      });
      return;
    }
    document.querySelectorAll("[data-risk]").forEach((node) => {
      const target = Number(node.dataset.risk) || 0;
      const start = performance.now();
      const duration = 650;
      const tick = (now) => {
        const t = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - t, 3);
        node.textContent = String(Math.round(target * eased));
        if (t < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    });
  }

  async function refreshHealth() {
    const health = await api("/health");
    setHealthUi(health);
    if (health.models_ready) {
      const schema = await api("/schema");
      featureNames = schema.feature_names || [];
      els.schemaList.innerHTML = featureNames
        .map((name) => `<li>${escapeHtml(name)}</li>`)
        .join("");
      if (!els.featureJson.value.trim()) writeRecord(zeroRecord());
    }
  }

  async function runPredict() {
    clearError();
    let record;
    try {
      record = JSON.parse(els.featureJson.value);
    } catch {
      showError("Feature JSON is invalid. Fix the syntax and try again.");
      return;
    }
    if (!record || Array.isArray(record) || typeof record !== "object") {
      showError("Provide a single JSON object of feature name → number.");
      return;
    }

    els.btnPredict.disabled = true;
    els.btnPredict.textContent = "Scoring…";
    try {
      const result = await api("/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ record }),
      });
      renderAlerts(result.alerts || []);
      document.getElementById("alerts").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      showError(err.message || String(err));
    } finally {
      els.btnPredict.disabled = false;
      els.btnPredict.textContent = "Score this flow";
    }
  }

  els.btnZeros.addEventListener("click", () => {
    if (!featureNames.length) {
      showError("Schema not loaded yet.");
      return;
    }
    clearError();
    writeRecord(zeroRecord());
  });

  els.btnDemo.addEventListener("click", () => {
    if (!featureNames.length) {
      showError("Schema not loaded yet.");
      return;
    }
    clearError();
    writeRecord(demoRecord());
  });

  els.btnSchema.addEventListener("click", () => {
    if (typeof els.schemaDialog.showModal === "function") {
      els.schemaDialog.showModal();
    }
  });

  els.btnPredict.addEventListener("click", runPredict);

  els.copyUvicornButtons.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const cmd = "uvicorn threatlens.api.app:app --host 127.0.0.1 --port 8000";
      try {
        await navigator.clipboard.writeText(cmd);
        const label = btn.querySelector("span");
        if (label) {
          label.textContent = "Copied";
          setTimeout(() => {
            label.textContent = "Copy";
          }, 1400);
        }
      } catch {
        showError("Could not copy to clipboard.");
      }
    });
  });

  refreshHealth().catch((err) => {
    setHealthUi({
      status: "down",
      models_ready: false,
      random_forest_loaded: false,
      isolation_forest_loaded: false,
      feature_count: 0,
    });
    showError(err.message || String(err));
  });
})();
