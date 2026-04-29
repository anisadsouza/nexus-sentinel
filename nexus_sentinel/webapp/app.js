const form = document.getElementById("analyze-form");
const urlInput = document.getElementById("url-input");
const result = document.getElementById("result");
const campaigns = document.getElementById("campaigns");
const recentScans = document.getElementById("recent-scans");
const refreshButton = document.getElementById("refresh-campaigns");
const totalScans = document.getElementById("total-scans");
const activeCampaigns = document.getElementById("active-campaigns");
const highestRisk = document.getElementById("highest-risk");
const formMessage = document.getElementById("form-message");
const themeToggle = document.getElementById("theme-toggle");
const themeToggleIcon = document.getElementById("theme-toggle-icon");
const THEME_STORAGE_KEY = "nexus-sentinel-theme";
let latestRecentScans = [];

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
  formMessage.textContent = "Analysis request ready.";
  formMessage.className = "form-message muted";
  result.innerHTML = '<p class="muted">Analyzing...</p>';

  try {
    const response = await fetch(`/api/analyze?url=${encodeURIComponent(url)}`);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Analysis failed.");
    }

    renderResult(data);
    await loadCampaigns();
  } catch (error) {
    result.innerHTML = `<p class="error">${error.message}</p>`;
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

refreshButton.addEventListener("click", () => {
  void loadCampaigns();
});

recentScans.addEventListener("click", (event) => {
  const button = event.target.closest("[data-scan-index]");
  if (!button) {
    return;
  }

  const index = Number(button.dataset.scanIndex);
  const scan = latestRecentScans[index];
  if (scan) {
    renderResult(scan);
  }
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
                <h3>${campaign.campaign_id}</h3>
                <span class="badge ${statusClass(campaign.classification)}">${campaign.classification}</span>
              </div>
              <p class="campaign-meta">Fingerprint: ${campaign.threat_fingerprint_id}</p>
              <p class="campaign-meta">Matched URLs: ${campaign.size}</p>
              <p class="campaign-meta">Common signals: ${
                campaign.common_risk_factors.length
                  ? campaign.common_risk_factors.join(" | ")
                  : "No repeated factors yet"
              }</p>
              <ul>
                ${campaign.example_urls.map((url) => `<li>${url}</li>`).join("")}
              </ul>
            </article>
          `
        )
        .join("");
    }

    renderRecentScans(data.recent_scans);
    renderOverview(data.recent_scans, data.campaigns);
  } catch (error) {
    campaigns.innerHTML = `<p class="error">${error.message}</p>`;
    recentScans.innerHTML = '<p class="muted">Recent scans unavailable.</p>';
    renderOverview([], []);
  }
}

function renderResult(data) {
  const factorItems = data.risk_factors.length
    ? data.risk_factors.map((factor) => `<li>${factor}</li>`).join("")
    : "<li>No major URL-level rules were triggered.</li>";
  const features = data.extracted_features || {};
  const scoreBreakdown = Array.isArray(data.score_breakdown) ? data.score_breakdown : [];
  const featureItems = [
    ["HTTPS", features.uses_https ? "Yes" : "No"],
    ["Hostname", features.hostname || "Unknown"],
    ["IP Hostname", features.is_ip_hostname ? "Yes" : "No"],
    ["URL Length", features.url_length ?? "Unknown"],
    ["Subdomains", features.subdomain_count ?? "Unknown"],
    ["Hyphens in Hostname", features.hostname_hyphen_count ?? "Unknown"],
    ["Path Depth", features.path_depth ?? "Unknown"],
    ["Encoded Characters", features.has_encoded_characters ? "Yes" : "No"],
    ["High-Risk TLD", features.has_suspicious_tld ? "Yes" : "No"],
    ["Query Parameters", features.query_parameter_count ?? "Unknown"],
    [
      "Keywords",
      Array.isArray(features.suspicious_keywords) && features.suspicious_keywords.length
        ? features.suspicious_keywords.join(", ")
        : "None",
    ],
  ]
    .map(
      ([label, value]) => `
        <div class="feature-item">
          <p class="metric-label">${label}</p>
          <p class="feature-value">${value}</p>
        </div>
      `
    )
    .join("");
  const scoreItems = scoreBreakdown.length
    ? scoreBreakdown
        .map(
          (item) => `
            <article class="score-item">
              <div class="score-item-topline">
                <p class="metric-label">${item.rule.replaceAll("_", " ")}</p>
                <p class="score-points">+${item.points}</p>
              </div>
              <p class="score-reason">${item.reason}</p>
            </article>
          `
        )
        .join("")
    : '<p class="muted">No risk rules were triggered.</p>';

  result.innerHTML = `
    <div class="result-header">
      <div>
        <p class="metric-label">Last Scan</p>
        <p class="result-url">${data.url}</p>
        <p class="result-time">${formatTimestamp(data.analyzed_at)}</p>
      </div>
      <span class="badge large ${statusClass(data.classification)}">${data.classification}</span>
    </div>
    <div class="result-grid">
      <article class="overview-item">
        <p class="metric-label">Risk Score</p>
        <p class="metric-value">${data.risk_score}/100</p>
      </article>
      <article class="overview-item">
        <p class="metric-label">Fingerprint</p>
        <p class="metric-value small">${data.threat_fingerprint_id}</p>
      </article>
      <article class="overview-item">
        <p class="metric-label">Campaign</p>
        <p class="metric-value small">${data.campaign_id}</p>
      </article>
      <article class="overview-item">
        <p class="metric-label">Campaign Size</p>
        <p class="metric-value">${data.campaign_size}</p>
      </article>
    </div>
    <div class="list-block">
      <p class="metric-label">Risk Factors</p>
      <ul>${factorItems}</ul>
    </div>
    <div class="list-block">
      <p class="metric-label">Score Breakdown</p>
      <div class="score-list">${scoreItems}</div>
    </div>
    <div class="list-block">
      <p class="metric-label">Extracted Features</p>
      <div class="feature-grid">${featureItems}</div>
    </div>
  `;
}

function renderRecentScans(scans) {
  latestRecentScans = scans;

  if (!scans.length) {
    recentScans.innerHTML = '<p class="muted">No recent scans yet.</p>';
    return;
  }

  recentScans.innerHTML = scans
    .map(
      (scan, index) => `
        <button type="button" class="recent-item" data-scan-index="${index}">
          <div class="campaign-topline">
            <p class="recent-url">${scan.url}</p>
            <span class="badge ${statusClass(scan.classification)}">${scan.classification}</span>
          </div>
          <div class="recent-meta">
            <span>Risk ${scan.risk_score}/100</span>
            <span>${scan.campaign_id}</span>
            <span>${formatTimestamp(scan.analyzed_at)}</span>
          </div>
        </button>
      `
    )
    .join("");
}

function renderOverview(scans, campaignList) {
  totalScans.textContent = String(scans.length);
  activeCampaigns.textContent = String(campaignList.length);
  highestRisk.textContent = String(
    scans.reduce((max, scan) => Math.max(max, scan.risk_score), 0)
  );
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

void loadCampaigns();
