const form = document.getElementById("analyze-form");
const urlInput = document.getElementById("url-input");
const result = document.getElementById("result");
const campaigns = document.getElementById("campaigns");
const refreshButton = document.getElementById("refresh-campaigns");
const totalScans = document.getElementById("total-scans");
const activeCampaigns = document.getElementById("active-campaigns");
const highestRisk = document.getElementById("highest-risk");
const formMessage = document.getElementById("form-message");
const analyzeButton = document.getElementById("analyze-button");
const themeToggle = document.getElementById("theme-toggle");
const themeToggleIcon = document.getElementById("theme-toggle-icon");
const clearUrlButton = document.getElementById("clear-url");
const THEME_STORAGE_KEY = "nexus-sentinel-theme";

applyTheme(loadThemePreference());

themeToggle.addEventListener("click", () => {
  const nextTheme = document.body.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(nextTheme);
  window.localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const preparedUrl = prepareUrl(urlInput.value);
  if (!preparedUrl.ok) {
    formMessage.textContent = preparedUrl.message;
    formMessage.className = "form-message error";
    return;
  }

  const url = preparedUrl.url;
  if (!url) {
    return;
  }

  urlInput.value = url;
  formMessage.textContent = "Analysis in progress.";
  formMessage.className = "form-message muted";
  result.innerHTML = '<p class="muted">Analyzing...</p>';
  setAnalyzeButtonState(true);

  try {
    const response = await fetch(`/api/analyze?url=${encodeURIComponent(url)}`);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Analysis failed.");
    }

    renderResult(data);
    await loadCampaigns();
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
    urlInput.value = button.dataset.sampleUrl;
    formMessage.textContent = "Sample URL loaded.";
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

refreshButton.addEventListener("click", () => {
  void loadCampaigns();
});

async function loadCampaigns() {
  try {
    const response = await fetch("/api/campaigns");
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Could not load campaigns.");
    }

    if (!data.campaigns.length) {
      campaigns.innerHTML = '<p class="muted">No campaign data yet.</p>';
    } else {
      campaigns.innerHTML = data.campaigns
        .map(
          (campaign) => `
            <article class="campaign-item">
              <div class="campaign-topline">
                <p class="campaign-id">${campaign.campaign_id}</p>
                <span class="risk-pill ${statusClass(campaign.classification)}">${sentenceCase(campaign.classification)}</span>
              </div>
              <p class="campaign-meta">Matched URLs: ${campaign.size}</p>
              <p class="campaign-meta">First seen: ${formatTimestamp(campaign.first_seen)}</p>
              <p class="campaign-meta">Latest seen: ${formatTimestamp(campaign.latest_seen)}</p>
              <p class="campaign-detail">${campaign.grouping_reason}</p>
              <div class="signal-pill-row">
                ${renderCampaignSignals(campaign)}
              </div>
              <div class="url-pill-row">
                ${campaign.example_urls
                  .map((url) => `<span class="url-pill">${url}</span>`)
                  .join("")}
              </div>
            </article>
          `
        )
        .join("");
    }

    renderOverview(data.overview || {});
  } catch (error) {
    campaigns.innerHTML = `<p class="error">${error.message}</p>`;
    renderOverview({});
  }
}

function renderResult(data) {
  const scoreBreakdown = Array.isArray(data.score_breakdown) ? data.score_breakdown : [];
  const features = data.extracted_features || {};
  const contentAnalysis = data.content_analysis || {};
  const redirectAnalysis = data.redirect_analysis || {};
  const ringMetrics = buildRingMetrics(data.risk_score);
  const verdictTone = verdictToneClass(data.classification);
  const riskRows = buildRiskRows(scoreBreakdown);
  const goodRows = buildGoodSignalRows(features);
  const factRows = buildFactRows(features);
  const contentRows = buildContentRows(contentAnalysis);
  const redirectRows = buildRedirectRows(redirectAnalysis);
  const tipsMarkup = buildTips(data, features);

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
        <p class="section-kicker">Verdict</p>
        <div class="verdict-card ${verdictTone}">
          <div class="verdict-icon">${verdictIcon(data.classification)}</div>
          <div>
            <p class="verdict-title">${sentenceCase(data.classification)}</p>
            <p class="verdict-subtitle">
              ${data.url}<br>${formatTimestamp(data.analyzed_at)}
            </p>
          </div>
        </div>
        <div class="meta-strip">
          <span class="meta-pill">${data.campaign_id}</span>
          <span class="meta-pill">Campaign size ${data.campaign_size}</span>
        </div>
      </div>
    </div>
    <div class="explanation-grid">
      <section class="explanation-card">
        <p class="section-kicker">Detected Risks</p>
        <div class="factor-list compact">${riskRows}</div>
      </section>
      <section class="explanation-card">
        <p class="section-kicker">Positive Signals</p>
        <div class="factor-list compact">${goodRows}</div>
      </section>
      <section class="explanation-card explanation-card-facts">
        <p class="section-kicker">Observed Facts</p>
        <div class="fact-grid">${factRows}</div>
      </section>
    </div>
    <section class="content-card">
      <p class="section-kicker">Content Analysis</p>
      <div class="content-status-row">
        <span class="risk-pill ${contentAnalysis.status === "not_fetched" ? "status-suspicious" : "status-safe"}">
          ${sentenceCase(contentAnalysis.status || "unknown")}
        </span>
        <p class="content-note">${contentAnalysis.notes || "No content analysis notes available."}</p>
      </div>
      <div class="fact-grid">${contentRows}</div>
    </section>
    <section class="content-card">
      <p class="section-kicker">Redirect Analysis</p>
      <div class="content-status-row">
        <span class="risk-pill ${redirectAnalysis.status === "not_fetched" ? "status-suspicious" : "status-safe"}">
          ${sentenceCase(redirectAnalysis.status || "unknown")}
        </span>
        <p class="content-note">${redirectAnalysis.notes || "No redirect analysis notes available."}</p>
      </div>
      <div class="fact-grid">${redirectRows}</div>
    </section>
    <section class="content-card info-card">
      <p class="section-kicker">Tips</p>
      <div class="info-list">
        ${tipsMarkup}
      </div>
    </section>
  `;
}

function setAnalyzeButtonState(isLoading) {
  analyzeButton.disabled = isLoading;
  analyzeButton.textContent = isLoading ? "Analyzing..." : "Analyze";
}

function renderOverview(overview) {
  totalScans.textContent = String(overview.total_scans || 0);
  activeCampaigns.textContent = String(overview.active_campaigns || 0);
  highestRisk.textContent = String(overview.highest_risk || 0);
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

function prepareUrl(rawValue) {
  const trimmed = rawValue.trim();
  if (!trimmed) {
    return { ok: false, message: "Enter a URL to analyze." };
  }

  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  try {
    const parsed = new URL(withScheme);
    if (!parsed.hostname) {
      return { ok: false, message: "Please enter a valid URL." };
    }
    return { ok: true, url: parsed.toString() };
  } catch (_error) {
    return { ok: false, message: "Please enter a valid URL." };
  }
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
        <span class="factor-text">No major URL-level risks were triggered.</span>
        <span class="factor-points">0</span>
      </div>
    `;
  }

  return scoreBreakdown
    .map((item) => {
      const toneClass = item.points >= 12 ? "factor-bad" : "factor-warn";
      return `
        <div class="factor-row">
          <span class="factor-icon ${toneClass}">!</span>
          <span class="factor-text">${item.reason}</span>
          <span class="factor-points">+${item.points}</span>
        </div>
      `;
    })
    .join("");
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
    rows.push("Top-level domain is not high-risk");
  }
  if (Array.isArray(features.suspicious_keywords) && features.suspicious_keywords.length === 0) {
    rows.push("No suspicious keywords were detected");
  }

  if (!rows.length) {
    return `
      <div class="factor-row">
        <span class="factor-icon factor-warn">!</span>
        <span class="factor-text">No strong positive URL-level signals were detected.</span>
        <span class="factor-points">-</span>
      </div>
    `;
  }

  return rows
    .map(
      (row) => `
        <div class="factor-row">
          <span class="factor-icon factor-good">✓</span>
          <span class="factor-text">${row}</span>
          <span class="factor-points factor-points-good">OK</span>
        </div>
      `
    )
    .join("");
}

function buildFactRows(features) {
  const facts = [
    ["Hostname", features.hostname || "Unknown"],
    ["Subdomains", features.subdomain_count ?? "Unknown"],
    ["Query Params", features.query_parameter_count ?? "Unknown"],
    ["Path Depth", features.path_depth ?? "Unknown"],
    ["Encoded Chars", features.has_encoded_characters ? "Yes" : "No"],
    [
      "Keywords",
      Array.isArray(features.suspicious_keywords) && features.suspicious_keywords.length
        ? features.suspicious_keywords.join(", ")
        : "None",
    ],
  ];

  return facts
    .map(
      ([label, value]) => `
        <div class="fact-item">
          <p class="fact-label">${label}</p>
          <p class="fact-value">${value}</p>
        </div>
      `
    )
    .join("");
}

function buildContentRows(contentAnalysis) {
  const contentFacts = [
    ["Page Title", contentAnalysis.page_title || "Not fetched"],
    ["Login Form", booleanLabel(contentAnalysis.login_form_detected)],
    ["Password Field", booleanLabel(contentAnalysis.password_field_detected)],
    ["Urgency Language", booleanLabel(contentAnalysis.urgency_language_detected)],
    ["External Scripts", booleanLabel(contentAnalysis.external_scripts_detected)],
  ];

  return contentFacts
    .map(
      ([label, value]) => `
        <div class="fact-item">
          <p class="fact-label">${label}</p>
          <p class="fact-value">${value}</p>
        </div>
      `
    )
    .join("");
}

function buildRedirectRows(redirectAnalysis) {
  const redirectFacts = [
    ["Redirect Count", redirectAnalysis.redirect_count ?? "Not fetched"],
    ["Final URL", redirectAnalysis.final_url || "Not fetched"],
    [
      "Cross-domain Redirect",
      booleanLabel(redirectAnalysis.cross_domain_redirect_detected),
    ],
    [
      "Suspicious Chain",
      booleanLabel(redirectAnalysis.suspicious_redirect_chain),
    ],
  ];

  return redirectFacts
    .map(
      ([label, value]) => `
        <div class="fact-item">
          <p class="fact-label">${label}</p>
          <p class="fact-value">${value}</p>
        </div>
      `
    )
    .join("");
}

function buildTips(data, features) {
  const tips = [
    "Each run is still saved as a new scan, so the timestamp, recent history, and campaign size can change.",
  ];

  if (data.classification === "safe") {
    tips.push(
      "Safe here means no strong URL-level warnings were found yet. Live page-content and redirect fetching are still placeholders."
    );
  } else {
    tips.push(
      "Treat suspicious links as untrusted until content and redirect checks are fully enabled."
    );
  }

  if (features.uses_https === false) {
    tips.push("Lack of HTTPS is a warning sign, but it should be read together with the rest of the pattern.");
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

function sentenceCase(value) {
  if (!value) {
    return "";
  }
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function renderCampaignSignals(campaign) {
  const repeatedSignals = Array.isArray(campaign.common_risk_factors)
    ? campaign.common_risk_factors
    : [];
  const sharedTraits = Array.isArray(campaign.shared_traits) ? campaign.shared_traits : [];
  const signals = [...sharedTraits, ...repeatedSignals];

  if (!signals.length) {
    return '<span class="signal-pill signal-good">Stable pattern</span>';
  }

  return signals
    .map((signal) => {
      const normalizedSignal = signal.toLowerCase();
      const tone =
        normalizedSignal.includes("https") ||
        normalizedSignal.includes("shared") ||
        normalizedSignal.includes("stable")
          ? "signal-good"
          : "signal-bad";
      return `<span class="signal-pill ${tone}">${signal}</span>`;
    })
    .join("");
}

void loadCampaigns();
