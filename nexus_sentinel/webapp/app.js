const form = document.getElementById("analyze-form");
const urlInput = document.getElementById("url-input");
const result = document.getElementById("result");
const formMessage = document.getElementById("form-message");
const analyzeButton = document.getElementById("analyze-button");
const batchFileInput = document.getElementById("batch-file");
const batchAnalyzeButton = document.getElementById("batch-analyze-button");
const batchMessage = document.getElementById("batch-message");
const batchResults = document.getElementById("batch-results");
const themeToggle = document.getElementById("theme-toggle");
const themeToggleIcon = document.getElementById("theme-toggle-icon");
const clearUrlButton = document.getElementById("clear-url");
const workspaceTabs = Array.from(document.querySelectorAll(".workspace-tab"));
const workspacePanels = Array.from(document.querySelectorAll(".workspace-panel"));
const THEME_STORAGE_KEY = "nexus-sentinel-theme";

applyTheme(loadThemePreference());

themeToggle.addEventListener("click", () => {
  const nextTheme = document.body.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(nextTheme);
  window.localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
});

workspaceTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    setActivePanel(tab.dataset.panelTarget || "url-panel");
  });
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const preparedUrl = prepareUrl(urlInput.value);
  if (!preparedUrl.ok) {
    formMessage.textContent = preparedUrl.message;
    formMessage.className = "form-message error";
    return;
  }

  urlInput.value = preparedUrl.url;
  formMessage.textContent = "Analysis in progress.";
  formMessage.className = "form-message muted";
  result.innerHTML = '<p class="muted">Analyzing...</p>';
  setAnalyzeButtonState(true);

  try {
    const response = await fetch(
      `/api/analyze?url=${encodeURIComponent(preparedUrl.url)}`
    );
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Analysis failed.");
    }

    renderResult(data);
    formMessage.textContent = "Analysis complete.";
    formMessage.className = "form-message success";
  } catch (error) {
    formMessage.textContent = error.message;
    formMessage.className = "form-message error";
    result.innerHTML = `<p class="error">${error.message}</p>`;
  } finally {
    setAnalyzeButtonState(false);
  }
});

document.querySelectorAll("[data-sample-url]").forEach((button) => {
  button.addEventListener("click", () => {
    urlInput.value = button.dataset.sampleUrl || "";
    formMessage.textContent = "Example URL loaded.";
    formMessage.className = "form-message muted";
    urlInput.focus();
  });
});

clearUrlButton.addEventListener("click", () => {
  urlInput.value = "";
  formMessage.textContent = "URL field cleared.";
  formMessage.className = "form-message muted";
  urlInput.focus();
});

batchFileInput.addEventListener("change", () => {
  if (!batchFileInput.files || !batchFileInput.files.length) {
    batchMessage.textContent = "Choose a CSV file to analyze.";
    batchMessage.className = "form-message muted";
    return;
  }

  batchMessage.textContent = `${batchFileInput.files[0].name} ready for analysis.`;
  batchMessage.className = "form-message muted";
});

batchAnalyzeButton.addEventListener("click", async () => {
  const file = batchFileInput.files && batchFileInput.files[0];
  if (!file) {
    batchMessage.textContent = "Choose a CSV file with URLs first.";
    batchMessage.className = "form-message error";
    return;
  }

  setBatchButtonState(true);
  batchMessage.textContent = "Batch analysis in progress.";
  batchMessage.className = "form-message muted";
  batchResults.innerHTML = '<p class="muted">Analyzing CSV...</p>';

  try {
    const csvText = await file.text();
    const response = await fetch("/api/analyze-batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        csv_text: csvText,
      }),
    });
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Batch analysis failed.");
    }

    renderBatchResults(data);
    batchMessage.textContent = `Batch complete. ${data.summary.total_urls} links analyzed.`;
    batchMessage.className = "form-message success";
  } catch (error) {
    batchMessage.textContent = error.message;
    batchMessage.className = "form-message error";
    batchResults.innerHTML = `<p class="error">${error.message}</p>`;
  } finally {
    setBatchButtonState(false);
  }
});

function setActivePanel(panelId) {
  workspaceTabs.forEach((tab) => {
    const isActive = tab.dataset.panelTarget === panelId;
    tab.classList.toggle("is-active", isActive);
  });

  workspacePanels.forEach((panel) => {
    const isActive = panel.id === panelId;
    panel.classList.toggle("is-active", isActive);
    panel.hidden = !isActive;
  });
}

function renderResult(data) {
  const scoreBreakdown = Array.isArray(data.score_breakdown) ? data.score_breakdown : [];
  const features = data.extracted_features || {};
  const contentAnalysis = data.content_analysis || {};
  const redirectAnalysis = data.redirect_analysis || {};
  const mlAnalysis = data.ml_analysis || {};
  const ringMetrics = buildRingMetrics(data.risk_score);
  const verdictTone = verdictToneClass(data.classification);

  result.innerHTML = `
    <div class="result-shell">
      <div class="score-column">
        <p class="section-kicker">Risk Score</p>
        <div class="gauge-wrap">
          <svg class="score-gauge" viewBox="0 0 90 90" aria-hidden="true">
            <circle class="gauge-track" cx="45" cy="45" r="36"></circle>
            <circle
              class="gauge-fill"
              cx="45"
              cy="45"
              r="36"
              stroke-dasharray="${ringMetrics.dashArray}"
              stroke-dashoffset="${ringMetrics.dashOffset}"
            ></circle>
          </svg>
          <div class="gauge-center">
            <p class="gauge-score">${data.risk_score}</p>
            <p class="gauge-total">/100</p>
          </div>
        </div>
      </div>

      <div class="verdict-column">
        <p class="section-kicker">Result</p>
        <div class="verdict-card ${verdictTone}">
          <div class="verdict-icon">${verdictIcon(data.classification)}</div>
          <div>
            <p class="verdict-title">${humanVerdictTitle(data.classification)}</p>
            <p class="verdict-subtitle">${data.url}<br>${formatTimestamp(data.analyzed_at)}</p>
          </div>
        </div>
      </div>
    </div>

    <div class="result-grid">
      <section class="result-card">
        <p class="section-kicker">Why it was flagged</p>
        <div class="factor-list">${buildRiskRows(scoreBreakdown)}</div>
      </section>

      <section class="result-card">
        <p class="section-kicker">Good signs</p>
        <div class="factor-list">${buildGoodSignalRows(features)}</div>
      </section>
    </div>

    <div class="result-grid result-grid-secondary">
      <section class="result-card">
        <p class="section-kicker">Link details</p>
        <div class="fact-grid">${buildFactRows(features)}</div>
      </section>

      <section class="result-card">
        <p class="section-kicker">Page check</p>
        <div class="content-status-row">
          <span class="risk-pill ${contentAnalysis.status === "fetched" ? "status-safe" : "status-suspicious"}">
            ${sentenceCase(contentAnalysis.status || "unknown")}
          </span>
          <p class="content-note">${contentAnalysis.notes || "No page details available."}</p>
        </div>
        <div class="fact-grid">${buildContentRows(contentAnalysis)}</div>
      </section>
    </div>

    <div class="result-grid result-grid-secondary">
      <section class="result-card">
        <p class="section-kicker">Destination check</p>
        <div class="content-status-row">
          <span class="risk-pill ${redirectAnalysis.status === "fetched" ? "status-safe" : "status-suspicious"}">
            ${sentenceCase(redirectAnalysis.status || "unknown")}
          </span>
          <p class="content-note">${redirectAnalysis.notes || "No redirect details available."}</p>
        </div>
        <div class="fact-grid">${buildRedirectRows(redirectAnalysis)}</div>
      </section>

      <section class="result-card">
        <p class="section-kicker">Model check</p>
        <div class="ml-summary">
          ${buildMlSummary(mlAnalysis)}
        </div>
      </section>
    </div>

    <div class="result-grid result-grid-secondary">
      <section class="result-card">
        <p class="section-kicker">What this means</p>
        <div class="info-list">${buildTips(data, features)}</div>
      </section>
    </div>
  `;
}

function renderBatchResults(data) {
  const summary = data.summary || {};
  const results = Array.isArray(data.results) ? data.results : [];

  if (!results.length) {
    batchResults.innerHTML = '<p class="muted">No URLs were analyzed from this file.</p>';
    return;
  }

  batchResults.innerHTML = `
    <div class="batch-results-header">
      <div>
        <p class="section-kicker">Batch Results</p>
        <h2>CSV analysis results</h2>
      </div>
      <div class="meta-strip">
        <span class="meta-pill">${summary.total_urls || results.length} scanned</span>
        <span class="meta-pill">${summary.safe || 0} safe</span>
        <span class="meta-pill">${summary.suspicious || 0} suspicious</span>
        <span class="meta-pill">${summary.phishing || 0} phishing</span>
      </div>
    </div>
    <div class="batch-table-wrap">
      <table class="batch-table">
        <thead>
          <tr>
            <th>URL</th>
            <th>Result</th>
            <th>Score</th>
            <th>Similar Links</th>
          </tr>
        </thead>
        <tbody>
          ${results
            .map(
              (item) => `
                <tr>
                  <td class="batch-url-cell" title="${item.url}">${item.url}</td>
                  <td><span class="risk-pill ${statusClass(item.classification)}">${sentenceCase(item.classification)}</span></td>
                  <td>${item.risk_score}</td>
                  <td>${item.similar_group_size}</td>
                </tr>
              `
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function setAnalyzeButtonState(isLoading) {
  analyzeButton.disabled = isLoading;
  analyzeButton.textContent = isLoading ? "Analyzing..." : "Analyze";
}

function setBatchButtonState(isLoading) {
  batchAnalyzeButton.disabled = isLoading;
  batchAnalyzeButton.textContent = isLoading ? "Analyzing CSV..." : "Analyze CSV";
}

function prepareUrl(rawValue) {
  const trimmed = rawValue.trim();
  if (!trimmed) {
    return { ok: false, message: "Enter a URL or link to analyze." };
  }

  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  try {
    const parsed = new URL(withScheme);
    if (!parsed.hostname || !looksLikeLinkTarget(parsed.hostname)) {
      return {
        ok: false,
        message: "Enter a full URL or link, such as https://example.com",
      };
    }
    return { ok: true, url: parsed.toString() };
  } catch (_error) {
    return {
      ok: false,
      message: "Enter a full URL or link, such as https://example.com",
    };
  }
}

function looksLikeLinkTarget(hostname) {
  if (!hostname) {
    return false;
  }
  if (hostname === "localhost") {
    return true;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return true;
  }
  return hostname.includes(".");
}

function buildRingMetrics(score) {
  const dashArray = 226;
  const normalizedScore = Math.max(0, Math.min(score, 100));
  const dashOffset = dashArray - (normalizedScore / 100) * dashArray;
  return { dashArray, dashOffset };
}

function buildRiskRows(scoreBreakdown) {
  if (!scoreBreakdown.length) {
    return `
      <div class="factor-row">
        <span class="factor-icon factor-good">✓</span>
        <div class="factor-copy">
          <p class="factor-title">No major risk signals</p>
          <p class="factor-impact">This link did not trigger any strong warning signs in the available checks.</p>
        </div>
      </div>
    `;
  }

  return scoreBreakdown
    .map((item) => {
      const toneClass = item.points >= 12 ? "factor-bad" : "factor-warn";
      return `
        <div class="factor-row">
          <span class="factor-icon ${toneClass}">!</span>
          <div class="factor-copy">
            <div class="factor-title-row">
              <p class="factor-title">${item.title || item.reason}</p>
              <span class="tooltip-wrap" tabindex="0">
                <span class="tooltip-trigger" aria-label="Why this matters">?</span>
                <span class="tooltip-bubble">
                  ${item.impact || item.reason}
                </span>
              </span>
            </div>
            <p class="factor-impact">${item.reason}</p>
          </div>
          <span class="factor-points">+${item.points}</span>
        </div>
      `;
    })
    .join("");
}

function buildMlSummary(mlAnalysis) {
  if (mlAnalysis.status !== "available") {
    return `
      <p class="factor-impact">${mlAnalysis.notes || "The model explanation is unavailable right now."}</p>
    `;
  }

  const signals = Array.isArray(mlAnalysis.top_signals) ? mlAnalysis.top_signals : [];
  const signalMarkup = signals.length
    ? signals
        .map(
          (signal) => `
            <div class="factor-row">
              <span class="factor-icon ${signal.direction === "raises risk" ? "factor-warn" : "factor-good"}">
                ${signal.direction === "raises risk" ? "!" : "✓"}
              </span>
              <div class="factor-copy">
                <div class="factor-title-row">
                  <p class="factor-title">${signal.label}</p>
                  <span class="tooltip-wrap" tabindex="0">
                    <span class="tooltip-trigger" aria-label="Why this matters">?</span>
                    <span class="tooltip-bubble">
                      ${signal.description}
                    </span>
                  </span>
                </div>
                <p class="factor-impact">${sentenceCase(signal.direction)}</p>
              </div>
            </div>
          `
        )
        .join("")
    : `<p class="factor-impact">No standout model signals were available.</p>`;

  return `
    <div class="ml-probability-row">
      <span class="risk-pill ${statusClass(mlAnalysis.predicted_classification)}">
        ${sentenceCase(mlAnalysis.predicted_classification)}
      </span>
      <p class="ml-probability">${mlAnalysis.prediction_probability}% model risk</p>
    </div>
    <p class="factor-impact">${mlAnalysis.notes || ""}</p>
    <div class="factor-list">${signalMarkup}</div>
  `;
}

function buildGoodSignalRows(features) {
  const rows = [];

  if (features.uses_https) {
    rows.push("Uses HTTPS");
  }
  if (!features.is_ip_hostname) {
    rows.push("Hostname is not a raw IP address");
  }
  if (!features.has_suspicious_tld) {
    rows.push("Website ending is not high-risk");
  }
  if (Array.isArray(features.suspicious_keywords) && features.suspicious_keywords.length === 0) {
    rows.push("No suspicious keywords were detected");
  }

  if (!rows.length) {
    return `
      <div class="factor-row">
        <span class="factor-icon factor-warn">!</span>
        <div class="factor-copy">
          <p class="factor-title">No strong positive signs</p>
          <p class="factor-impact">The link did not show clear trust signals that would lower concern on their own.</p>
        </div>
      </div>
    `;
  }

  return rows
    .map(
      (row) => `
        <div class="factor-row">
          <span class="factor-icon factor-good">✓</span>
          <div class="factor-copy">
            <p class="factor-title">${row}</p>
          </div>
        </div>
      `
    )
    .join("");
}

function buildFactRows(features) {
  const facts = [
    ["Website name", features.hostname || "Unknown"],
    ["Extra subdomains", features.subdomain_count ?? "Unknown"],
    ["Query items", features.query_parameter_count ?? "Unknown"],
    ["Path depth", features.path_depth ?? "Unknown"],
    ["Encoded characters", features.has_encoded_characters ? "Yes" : "No"],
    [
      "Suspicious words",
      Array.isArray(features.suspicious_keywords) && features.suspicious_keywords.length
        ? features.suspicious_keywords.join(", ")
        : "None",
    ],
  ];

  return facts.map(buildFactItem).join("");
}

function buildContentRows(contentAnalysis) {
  const facts = [
    ["Page title", contentAnalysis.page_title || "Not fetched"],
    ["Login form", booleanLabel(contentAnalysis.login_form_detected)],
    ["Password field", booleanLabel(contentAnalysis.password_field_detected)],
    ["Urgency wording", booleanLabel(contentAnalysis.urgency_language_detected)],
    ["Outside scripts", booleanLabel(contentAnalysis.external_scripts_detected)],
  ];

  return facts.map(buildFactItem).join("");
}

function buildRedirectRows(redirectAnalysis) {
  const facts = [
    ["Redirect count", redirectAnalysis.redirect_count ?? "Not fetched"],
    ["Final destination", redirectAnalysis.final_url || "Not fetched"],
    ["Different-site redirect", booleanLabel(redirectAnalysis.cross_domain_redirect_detected)],
    ["Suspicious redirect chain", booleanLabel(redirectAnalysis.suspicious_redirect_chain)],
  ];

  return facts.map(buildFactItem).join("");
}

function buildFactItem([label, value]) {
  return `
    <div class="fact-item">
      <p class="fact-label">${label}</p>
      <p class="fact-value">${value}</p>
    </div>
  `;
}

function buildTips(data, features) {
  const tips = [];

  if (data.classification === "safe") {
    tips.push("No strong warning signs were found in the checks that could be completed.");
  } else if (data.classification === "suspicious") {
    tips.push("This link has several warning signs. Treat it carefully before clicking or entering information.");
  } else {
    tips.push("This link looks high-risk and could be a phishing page. Avoid entering passwords or payment details.");
  }

  if (data.content_analysis?.status === "fetched" || data.redirect_analysis?.status === "fetched") {
    tips.push("This result includes live page or redirect checks, not just the link text.");
  }

  if (features.uses_https === false) {
    tips.push("Lack of HTTPS is a warning sign because information can be exposed more easily.");
  }

  return tips
    .map(
      (tip) => `
        <div class="info-row">
          <span class="factor-icon factor-good">i</span>
          <span class="factor-text">${tip}</span>
        </div>
      `
    )
    .join("");
}

function booleanLabel(value) {
  if (value === true) {
    return "Detected";
  }
  if (value === false) {
    return "Not detected";
  }
  return "Not fetched";
}

function verdictToneClass(classification) {
  if (classification === "phishing") {
    return "verdict-high";
  }
  if (classification === "suspicious") {
    return "verdict-medium";
  }
  return "verdict-safe";
}

function verdictIcon(classification) {
  if (classification === "safe") {
    return "✓";
  }
  return "⚠";
}

function humanVerdictTitle(classification) {
  if (classification === "safe") {
    return "Looks safe";
  }
  if (classification === "suspicious") {
    return "Use caution";
  }
  return "Likely phishing";
}

function statusClass(classification) {
  if (classification === "phishing") {
    return "status-phishing";
  }
  if (classification === "suspicious") {
    return "status-suspicious";
  }
  return "status-safe";
}

function sentenceCase(value) {
  if (!value) {
    return "";
  }
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function formatTimestamp(timestamp) {
  if (!timestamp) {
    return "Time unavailable";
  }

  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "Time unavailable";
  }

  return date.toLocaleString();
}

function loadThemePreference() {
  const savedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
  if (savedTheme === "light" || savedTheme === "dark") {
    return savedTheme;
  }

  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function applyTheme(theme) {
  document.body.dataset.theme = theme;
  themeToggleIcon.textContent = theme === "dark" ? "☀" : "☾";
  themeToggle.setAttribute(
    "aria-label",
    theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
  );
  themeToggle.setAttribute(
    "title",
    theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
  );
}
