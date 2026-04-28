const form = document.getElementById("analyze-form");
const urlInput = document.getElementById("url-input");
const result = document.getElementById("result");
const campaigns = document.getElementById("campaigns");
const recentScans = document.getElementById("recent-scans");
const refreshButton = document.getElementById("refresh-campaigns");
const totalScans = document.getElementById("total-scans");
const activeCampaigns = document.getElementById("active-campaigns");
const highestRisk = document.getElementById("highest-risk");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = urlInput.value.trim();
  if (!url) {
    return;
  }

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

refreshButton.addEventListener("click", () => {
  void loadCampaigns();
});

async function loadCampaigns() {
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
}

function renderResult(data) {
  const factorItems = data.risk_factors.length
    ? data.risk_factors.map((factor) => `<li>${factor}</li>`).join("")
    : "<li>No major URL-level rules were triggered.</li>";

  result.innerHTML = `
    <div class="result-header">
      <div>
        <p class="metric-label">Last Scan</p>
        <p class="result-url">${data.url}</p>
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
  `;
}

function renderRecentScans(scans) {
  if (!scans.length) {
    recentScans.innerHTML = '<p class="muted">No recent scans yet.</p>';
    return;
  }

  recentScans.innerHTML = scans
    .map(
      (scan) => `
        <article class="recent-item">
          <div class="campaign-topline">
            <p class="recent-url">${scan.url}</p>
            <span class="badge ${statusClass(scan.classification)}">${scan.classification}</span>
          </div>
          <div class="recent-meta">
            <span>Risk ${scan.risk_score}/100</span>
            <span>${scan.campaign_id}</span>
          </div>
        </article>
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

void loadCampaigns();
