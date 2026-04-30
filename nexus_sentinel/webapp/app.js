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
const clearUrlButton = document.getElementById("clear-url");
const THEME_STORAGE_KEY = "nexus-sentinel-theme";
let latestRecentScans = [];
let selectedRecentScanIndex = null;

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
    selectedRecentScanIndex = 0;
    highlightSelectedRecentScan();
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

clearUrlButton.addEventListener("click", () => {
  urlInput.value = "";
  formMessage.textContent = "URL field cleared.";
  formMessage.className = "form-message muted";
  urlInput.focus();
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
    selectedRecentScanIndex = index;
    renderResult(scan);
    highlightSelectedRecentScan();
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
                <p class="campaign-id">${campaign.campaign_id}</p>
                <span class="risk-pill ${statusClass(campaign.classification)}">${sentenceCase(campaign.classification)}</span>
              </div>
              <p class="campaign-meta">Matched URLs: ${campaign.size}</p>
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

    renderRecentScans(data.recent_scans);
    renderOverview(data.recent_scans, data.campaigns);
    highlightSelectedRecentScan();
  } catch (error) {
    campaigns.innerHTML = `<p class="error">${error.message}</p>`;
    recentScans.innerHTML = '<p class="muted">Recent scans unavailable.</p>';
    renderOverview([], []);
  }
}

function renderResult(data) {
  const scoreBreakdown = Array.isArray(data.score_breakdown) ? data.score_breakdown : [];
  const ringMetrics = buildRingMetrics(data.risk_score);
  const verdictTone = verdictToneClass(data.classification);
  const factorRows = buildFactorRows(data, scoreBreakdown);

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
        <div class="factor-list">${factorRows}</div>
        <div class="meta-strip">
          <span class="meta-pill">${data.threat_fingerprint_id}</span>
          <span class="meta-pill">${data.campaign_id}</span>
          <span class="meta-pill">Campaign size ${data.campaign_size}</span>
        </div>
      </div>
    </div>
  `;
}

function renderRecentScans(scans) {
  latestRecentScans = scans;

  if (selectedRecentScanIndex !== null && selectedRecentScanIndex >= scans.length) {
    selectedRecentScanIndex = null;
  }

  if (!scans.length) {
    recentScans.innerHTML = '<p class="muted">No recent scans yet.</p>';
    return;
  }

  recentScans.innerHTML = scans
    .map(
      (scan, index) => `
        <button type="button" class="recent-item" data-scan-index="${index}">
          <p class="recent-url">${scan.url}</p>
          <div class="scan-progress">
            <div
              class="scan-progress-fill ${riskBarClass(scan.risk_score)}"
              style="width: ${Math.max(4, scan.risk_score)}%;"
            ></div>
          </div>
          <div class="recent-meta">
            <span class="risk-pill ${statusClass(scan.classification)}">${sentenceCase(scan.classification)}</span>
            <span>${scan.risk_score}/100</span>
            <span>${formatTimestamp(scan.analyzed_at)}</span>
          </div>
          <div class="recent-meta subtle">
            <span>${scan.campaign_id}</span>
          </div>
        </button>
      `
    )
    .join("");
}

function highlightSelectedRecentScan() {
  recentScans.querySelectorAll("[data-scan-index]").forEach((element) => {
    const isSelected = Number(element.dataset.scanIndex) === selectedRecentScanIndex;
    element.classList.toggle("recent-item-selected", isSelected);
  });
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

function buildRingMetrics(score) {
  const dashArray = 226;
  const normalizedScore = Math.max(0, Math.min(score, 100));
  const dashOffset = dashArray - (normalizedScore / 100) * dashArray;
  return { dashArray, dashOffset };
}

function buildFactorRows(data, scoreBreakdown) {
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

function riskBarClass(score) {
  if (score >= 70) {
    return "bar-high";
  }
  if (score >= 35) {
    return "bar-medium";
  }
  return "bar-safe";
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

  if (!repeatedSignals.length) {
    return '<span class="signal-pill signal-good">Stable fingerprint</span>';
  }

  return repeatedSignals
    .map((signal) => {
      const tone = signal.toLowerCase().includes("https") ? "signal-good" : "signal-bad";
      return `<span class="signal-pill ${tone}">${signal}</span>`;
    })
    .join("");
}

void loadCampaigns();
