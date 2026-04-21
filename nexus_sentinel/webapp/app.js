const form = document.getElementById("analyze-form");
const urlInput = document.getElementById("url-input");
const result = document.getElementById("result");
const campaigns = document.getElementById("campaigns");
const refreshButton = document.getElementById("refresh-campaigns");

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
    return;
  }

  campaigns.innerHTML = data.campaigns
    .map(
      (campaign) => `
        <article class="campaign-item">
          <div class="campaign-topline">
            <h3>${campaign.campaign_id}</h3>
            <span class="badge">${campaign.classification}</span>
          </div>
          <p>Fingerprint: ${campaign.threat_fingerprint_id}</p>
          <p>Matched URLs: ${campaign.size}</p>
          <ul>
            ${campaign.example_urls.map((url) => `<li>${url}</li>`).join("")}
          </ul>
        </article>
      `
    )
    .join("");
}

function renderResult(data) {
  const factorItems = data.risk_factors.length
    ? data.risk_factors.map((factor) => `<li>${factor}</li>`).join("")
    : "<li>No major URL-level rules were triggered.</li>";

  result.innerHTML = `
    <div class="result-grid">
      <div>
        <p class="metric-label">Risk Score</p>
        <p class="metric-value">${data.risk_score}/100</p>
      </div>
      <div>
        <p class="metric-label">Classification</p>
        <p class="metric-value">${data.classification}</p>
      </div>
      <div>
        <p class="metric-label">Fingerprint</p>
        <p class="metric-value small">${data.threat_fingerprint_id}</p>
      </div>
      <div>
        <p class="metric-label">Campaign</p>
        <p class="metric-value small">${data.campaign_id}</p>
      </div>
    </div>
    <div class="list-block">
      <p class="metric-label">Risk Factors</p>
      <ul>${factorItems}</ul>
    </div>
  `;
}

void loadCampaigns();
