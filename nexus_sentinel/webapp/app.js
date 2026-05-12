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
const privateScanToggle = document.getElementById("private-scan");
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
  const privateScan = privateScanToggle.checked;

  try {
    const response = await fetch(
      `/api/analyze?url=${encodeURIComponent(url)}&private=${privateScan ? "1" : "0"}`
    );
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Analysis failed.");
    }

    renderResult(data);
    await loadCampaigns();
    formMessage.textContent = data.saved_to_history
      ? "Analysis complete. Scan saved."
      : "Analysis complete. Scan kept private.";
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
    const response = await fetch("/api/similar-groups");
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Could not load similar threat matches.");
    }

    if (!data.similar_groups.length) {
      campaigns.innerHTML = '<p class="muted">No similar threat matches yet.</p>';
    } else {
      campaigns.innerHTML = data.similar_groups
        .map(
          (similarGroup) => `
            <article class="campaign-item">
              <div class="campaign-topline">
                <p class="campaign-id">Similar threat group</p>
                <span class="risk-pill ${statusClass(similarGroup.classification)}">${sentenceCase(similarGroup.classification)}</span>
              </div>
              <p class="campaign-meta">Matched links: ${similarGroup.size}</p>
              <p class="campaign-meta">First seen: ${formatTimestamp(similarGroup.first_seen)}</p>
              <p class="campaign-meta">Last seen: ${formatTimestamp(similarGroup.latest_seen)}</p>
              <p class="campaign-detail">${similarGroup.grouping_reason}</p>
              <div class="signal-pill-row">
                ${renderCampaignSignals(similarGroup)}
              </div>
              <div class="url-pill-row">
                ${similarGroup.example_urls
                  .map((url) => `<span class="url-pill">${url}</span>`)
                  .join("")}
              </div>
              <details class="advanced-details">
                <summary>More details</summary>
                <div class="advanced-detail-grid">
                  <p class="advanced-detail-row"><span>Threat group ID</span><span>${similarGroup.similar_group_id}</span></p>
                </div>
              </details>
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
        <p class="section-kicker">Result</p>
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
          <span class="meta-pill">Similar links ${data.similar_group_size}</span>
          <span class="meta-pill">${data.saved_to_history ? "Saved to history" : "Private scan"}</span>
        </div>
      </div>
    </div>
    <div class="explanation-grid">
      <section class="explanation-card">
        <p class="section-kicker">Why it was flagged</p>
        <div class="factor-list compact">${riskRows}</div>
      </section>
      <section class="explanation-card">
        <p class="section-kicker">Good signs</p>
        <div class="factor-list compact">${goodRows}</div>
      </section>
      <section class="explanation-card explanation-card-facts">
        <p class="section-kicker">Link details</p>
        <div class="fact-grid">${factRows}</div>
      </section>
    </div>
    <section class="content-card">
      <p class="section-kicker">Page check</p>
      <div class="content-status-row">
        <span class="risk-pill ${contentAnalysis.status === "not_fetched" ? "status-suspicious" : "status-safe"}">
          ${sentenceCase(contentAnalysis.status || "unknown")}
        </span>
        <p class="content-note">${contentAnalysis.notes || "No content analysis notes available."}</p>
      </div>
      <div class="fact-grid">${contentRows}</div>
    </section>
    <section class="content-card">
      <p class="section-kicker">Destination check</p>
      <div class="content-status-row">
        <span class="risk-pill ${redirectAnalysis.status === "not_fetched" ? "status-suspicious" : "status-safe"}">
          ${sentenceCase(redirectAnalysis.status || "unknown")}
        </span>
        <p class="content-note">${redirectAnalysis.notes || "No redirect analysis notes available."}</p>
      </div>
      <div class="fact-grid">${redirectRows}</div>
    </section>
    <section class="content-card info-card">
      <p class="section-kicker">What to know</p>
      <div class="info-list">
        ${tipsMarkup}
      </div>
    </section>
    <details class="advanced-details advanced-details-result">
      <summary>More details</summary>
      <div class="advanced-detail-grid">
        <p class="advanced-detail-row"><span>Threat group ID</span><span>${data.similar_group_id}</span></p>
        <p class="advanced-detail-row"><span>Classification</span><span>${sentenceCase(data.classification)}</span></p>
      </div>
    </details>
  `;
}

function setAnalyzeButtonState(isLoading) {
  analyzeButton.disabled = isLoading;
  analyzeButton.textContent = isLoading ? "Analyzing..." : "Analyze";
}

function renderOverview(overview) {
  totalScans.textContent = String(overview.total_scans || 0);
  activeCampaigns.textContent = String(overview.active_similar_groups || 0);
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
    return { ok: false, message: "Enter a URL or link to analyze." };
  }

  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  try {
    const parsed = new URL(withScheme);
    if (!parsed.hostname || !_looksLikeLinkTarget(parsed.hostname)) {
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

function _looksLikeLinkTarget(hostname) {
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
        <div class="factor-copy">
          <p class="factor-title">No major risk signals</p>
          <p class="factor-impact">This link did not trigger any strong warning signs in the checks that were available.</p>
        </div>
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
          <div class="factor-copy">
            <p class="factor-title">${item.title || item.reason}</p>
            <p class="factor-impact">${item.impact || item.reason}</p>
          </div>
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
        <div class="factor-copy">
          <p class="factor-title">No strong positive signs</p>
          <p class="factor-impact">The link did not show clear trust signals that would lower concern on their own.</p>
        </div>
        <span class="factor-points">-</span>
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
          <span class="factor-points factor-points-good">OK</span>
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
    ["Page title", contentAnalysis.page_title || "Not fetched"],
    ["Login form", booleanLabel(contentAnalysis.login_form_detected)],
    ["Password field", booleanLabel(contentAnalysis.password_field_detected)],
    ["Urgency wording", booleanLabel(contentAnalysis.urgency_language_detected)],
    ["Outside scripts", booleanLabel(contentAnalysis.external_scripts_detected)],
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
    ["Redirect count", redirectAnalysis.redirect_count ?? "Not fetched"],
    ["Final destination", redirectAnalysis.final_url || "Not fetched"],
    [
      "Different-site redirect",
      booleanLabel(redirectAnalysis.cross_domain_redirect_detected),
    ],
    [
      "Suspicious redirect chain",
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
    data.saved_to_history
      ? "This scan was saved to history, so the timestamp and similar-link count can change over time."
      : "This scan was kept private and was not added to shared history.",
  ];

  if (data.content_analysis && data.redirect_analysis) {
    if (data.content_analysis.status === "fetched" || data.redirect_analysis.status === "fetched") {
      tips.push(
        "This result includes live page and destination checks, not just the link text."
      );
    } else if (
      data.content_analysis.status === "unavailable" ||
      data.redirect_analysis.status === "unavailable"
    ) {
      tips.push(
        "Some live checks were unavailable, so this result leans more heavily on the link itself."
      );
    }
  }

  if (data.classification === "safe") {
    tips.push(
      "Safe here means no strong warning signs were found in the checks that could be completed."
    );
  } else {
    tips.push(
      "Treat suspicious links as untrusted, especially if they ask for a password, payment details, or urgent action."
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

function renderCampaignSignals(similarGroup) {
  const repeatedSignals = Array.isArray(similarGroup.common_risk_factors)
    ? similarGroup.common_risk_factors
    : [];
  const sharedTraits = Array.isArray(similarGroup.shared_traits)
    ? similarGroup.shared_traits
    : [];
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
