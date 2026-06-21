const form = document.getElementById("analyze-form");
const urlInput = document.getElementById("url-input");
const result = document.getElementById("result");
const formMessage = document.getElementById("form-message");
const analyzeButton = document.getElementById("analyze-button");
const batchFileInput = document.getElementById("batch-file");
const batchAnalyzeButton = document.getElementById("batch-analyze-button");
const batchSampleButton = document.getElementById("batch-sample-button");
const batchMessage = document.getElementById("batch-message");
const batchResults = document.getElementById("batch-results");
const modelReportPanel = document.getElementById("model-report-panel");
const threatLensPanel = document.getElementById("threatlens-results");
const themeToggle = document.getElementById("theme-toggle");
const themeToggleIcon = document.getElementById("theme-toggle-icon");
const clearUrlButton = document.getElementById("clear-url");
const workspaceTabs = Array.from(document.querySelectorAll(".workspace-tab"));
const workspacePanels = Array.from(document.querySelectorAll(".workspace-panel"));
const THEME_STORAGE_KEY = "nexus-sentinel-theme";
let currentBatchData = null;
let currentSingleResult = null;
let batchFilterValue = "all";
let batchSortValue = "score_desc";
let currentThreatLensRange = "all";

applyTheme(loadThemePreference());
loadModelReport();
loadThreatLens();

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
    loadThreatLens();
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
    loadThreatLens();
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

batchSampleButton.addEventListener("click", () => {
  const sampleCsv = [
    "url",
    "https://example.com",
    "http://192.168.1.5/login",
    "https://pay-update-secure-login.top/a/b/c/d/%2Freset?next=home",
  ].join("\n");
  const sampleBlob = new Blob([sampleCsv], { type: "text/csv" });
  const sampleFile = new File([sampleBlob], "nexus-sentinel-sample.csv", {
    type: "text/csv",
  });
  const transfer = new DataTransfer();
  transfer.items.add(sampleFile);
  batchFileInput.files = transfer.files;
  batchMessage.textContent = "Sample CSV loaded. You can analyze it right away.";
  batchMessage.className = "form-message muted";
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
  currentSingleResult = data;
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
        <div class="ml-summary">${buildCompactMlSummary(mlAnalysis, data.classification, data.risk_score)}</div>
      </section>
    </div>

    <div class="result-grid result-grid-secondary">
      <section class="result-card">
        <p class="section-kicker">What this means</p>
        <div class="info-list">${buildTips(data, features)}</div>
      </section>
    </div>

    <details class="advanced-details result-advanced-details">
      <summary>More details</summary>
      <div class="result-grid result-grid-secondary result-advanced-grid">
        <section class="result-card">
          <p class="section-kicker">Link details</p>
          <div class="fact-grid">${buildFactRows(features)}</div>
        </section>
        <section class="result-card">
          <p class="section-kicker">Full model details</p>
          <div class="ml-summary">${buildMlSummary(mlAnalysis, data.classification, data.risk_score)}</div>
        </section>
      </div>
    </details>

    <div class="result-actions">
      <button id="download-single-report" type="button" class="secondary">Download result JSON</button>
    </div>
  `;

  const downloadButton = document.getElementById("download-single-report");
  if (downloadButton) {
    downloadButton.addEventListener("click", downloadSingleResult);
  }
}

function renderBatchResults(data) {
  currentBatchData = {
    summary: data.summary || {},
    results: Array.isArray(data.results) ? data.results : [],
  };

  if (!currentBatchData.results.length) {
    batchResults.innerHTML = '<p class="muted">No URLs were analyzed from this file.</p>';
    return;
  }

  renderBatchWorkspace();
}

function renderBatchWorkspace() {
  if (!currentBatchData) {
    batchResults.innerHTML = '<p class="muted">No batch upload yet.</p>';
    return;
  }

  const summary = currentBatchData.summary || {};
  const results = getFilteredBatchResults();
  const visibleCount = results.length;
  const totalCount = currentBatchData.results.length;
  const filterLabel = humanBatchFilter(batchFilterValue);

  batchResults.innerHTML = `
    <div class="batch-results-header">
      <div>
        <p class="section-kicker">Batch Results</p>
        <h2>CSV analysis results</h2>
        <p class="panel-copy">Showing ${visibleCount} of ${totalCount} result${totalCount === 1 ? "" : "s"}${batchFilterValue === "all" ? "" : ` for ${filterLabel.toLowerCase()}`}. </p>
      </div>
      <div class="meta-strip">
        <span class="meta-pill">${summary.total_urls || currentBatchData.results.length} scanned</span>
        <span class="meta-pill">${summary.safe || 0} safe</span>
        <span class="meta-pill">${summary.suspicious || 0} suspicious</span>
        <span class="meta-pill">${summary.phishing || 0} phishing</span>
      </div>
    </div>
    <div class="batch-summary-cards">
      ${buildBatchSummaryCards(summary)}
    </div>
    <div class="batch-insights-grid">
      ${buildBatchInsights(results)}
    </div>
    <div class="batch-toolbar">
      <label class="batch-control">
        <span>Show</span>
        <select id="batch-filter">
          <option value="all">All results</option>
          <option value="phishing">Likely phishing</option>
          <option value="suspicious">Use caution</option>
          <option value="safe">Looks safe</option>
        </select>
      </label>
      <label class="batch-control">
        <span>Sort</span>
        <select id="batch-sort">
          <option value="score_desc">Highest risk first</option>
          <option value="score_asc">Lowest risk first</option>
          <option value="model_desc">Highest model risk first</option>
          <option value="url_asc">URL A-Z</option>
        </select>
      </label>
      <button id="batch-export-button" type="button" class="secondary">Download CSV</button>
    </div>
    <div class="batch-table-wrap">
      <table class="batch-table">
        <thead>
          <tr>
            <th>URL</th>
            <th>Result</th>
            <th>Score</th>
            <th>Model View</th>
            <th>Pattern Matches</th>
          </tr>
        </thead>
        <tbody>
          ${results.length ? results
            .map(
              (item) => `
                <tr class="batch-row-main">
                  <td class="batch-url-cell" title="${item.url}">${item.url}</td>
                  <td><span class="risk-pill ${statusClass(item.classification)}">${sentenceCase(item.classification)}</span></td>
                  <td>${item.risk_score}</td>
                  <td>${formatModelRisk(item.ml_analysis)}</td>
                  <td>${item.similar_group_size}</td>
                </tr>
                <tr class="batch-row-detail">
                  <td colspan="5">
                    <details class="batch-detail-toggle">
                      <summary>Why this was flagged</summary>
                      <div class="batch-detail-grid">
                        <div class="batch-detail-card">
                          <p class="section-kicker">Top Rule Signals</p>
                          <div class="batch-signal-list">
                            ${buildBatchRuleSignals(item.score_breakdown)}
                          </div>
                        </div>
                        <div class="batch-detail-card">
                          <p class="section-kicker">Model Signals</p>
                          <div class="batch-signal-list">
                            ${buildBatchModelSignals(item.ml_analysis)}
                          </div>
                        </div>
                      </div>
                    </details>
                  </td>
                </tr>
              `
            )
            .join("") : `
              <tr>
                <td colspan="5">
                  <div class="batch-empty-state">
                    <p class="factor-title">No rows match this filter</p>
                    <p class="factor-impact">Try another result filter or sort option to bring rows back into view.</p>
                  </div>
                </td>
              </tr>
            `}
        </tbody>
      </table>
    </div>
  `;

  bindBatchControls();
}

async function loadModelReport() {
  if (!modelReportPanel) {
    return;
  }

  modelReportPanel.innerHTML = '<p class="muted">Loading model summary...</p>';

  try {
    const response = await fetch("/api/model-report");
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Unable to load model summary.");
    }

    modelReportPanel.innerHTML = buildModelReportPanel(data.model_report || {});
  } catch (error) {
    modelReportPanel.innerHTML = `
      <div class="model-report-card">
        <p class="section-kicker">Model Report</p>
        <h3 class="model-report-title">Model summary unavailable</h3>
        <p class="factor-impact">${error.message}</p>
      </div>
    `;
  }
}

async function loadThreatLens() {
  if (!threatLensPanel) {
    return;
  }

  threatLensPanel.innerHTML = '<p class="muted">Loading ThreatLens...</p>';

  try {
    const response = await fetch(`/api/threatlens?range=${encodeURIComponent(currentThreatLensRange)}`);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Unable to load ThreatLens.");
    }

    threatLensPanel.innerHTML = buildThreatLensPanel(data.threatlens || {});
    bindThreatLensControls();
  } catch (error) {
    threatLensPanel.innerHTML = `
      <div class="result-card">
        <p class="section-kicker">ThreatLens</p>
        <p class="factor-title">ThreatLens is unavailable right now</p>
        <p class="factor-impact">${error.message}</p>
      </div>
    `;
  }
}

function buildThreatLensPanel(summary) {
  const overview = summary.overview || {};
  const classifications = summary.classification_breakdown || {};
  const topTheme = firstThreatLensLabel(summary.top_themes, "No theme yet");
  const topCategory = firstThreatLensLabel(summary.top_categories, "No category yet");
  const topGroups = Array.isArray(summary.top_similar_groups) ? summary.top_similar_groups : [];
  const themeGroups = Array.isArray(summary.theme_groups) ? summary.theme_groups : [];
  const classificationShares = Array.isArray(summary.classification_shares) ? summary.classification_shares : [];
  const topBrandTargets = Array.isArray(summary.top_brand_targets) ? summary.top_brand_targets : [];
  const campaignSpotlights = Array.isArray(summary.campaign_spotlights) ? summary.campaign_spotlights : [];
  const trend = Array.isArray(summary.daily_trend) ? summary.daily_trend : [];
  const trendChange = summary.trend_change || {};
  const rangeLabel = summary.range_label || "All saved activity";

  return `
    <div class="threatlens-shell">
      <div class="result-card threatlens-summary-card">
        <div class="threatlens-summary-head">
          <div>
            <p class="section-kicker">ThreatLens Summary</p>
            <p class="threatlens-summary-copy">${summary.generated_summary || "ThreatLens will summarize saved results here."}</p>
          </div>
          <div class="threatlens-actions">
            <label class="batch-control threatlens-range-control">
              <span>Window</span>
              <select id="threatlens-range">
                <option value="all">All saved activity</option>
                <option value="30">Last 30 days</option>
                <option value="7">Last 7 days</option>
              </select>
            </label>
            <a class="report-link" href="/api/threatlens/download?range=${encodeURIComponent(currentThreatLensRange)}">Download ThreatLens report</a>
          </div>
        </div>
        <p class="helper-copy threatlens-helper">
          This view reads saved scan history. Private one-off checks stay out of it. Current window: ${rangeLabel}.
        </p>
      </div>

      <div class="threatlens-metrics">
        ${buildThreatLensMetric("Saved scans", overview.total_scans || 0, "Saved analysis records")}
        ${buildThreatLensMetric("Likely phishing", classifications.phishing || 0, "High-risk results in history")}
        ${buildThreatLensMetric("Top category", topCategory, "Highest-level threat category")}
        ${buildThreatLensMetric("Activity trend", trendChange.label || "No saved trend yet", "Compared with the earlier saved window")}
      </div>

      <div class="result-grid result-grid-secondary">
        <section class="result-card">
          <p class="section-kicker">Weekly Briefing</p>
          <p class="threatlens-briefing">${summary.weekly_briefing || "ThreatLens will generate a weekly-style summary here once saved results build up."}</p>
          <div class="dataset-name-list">
            ${buildThreatLensPills(summary.top_categories)}
          </div>
        </section>
        <section class="result-card">
          <p class="section-kicker">Current Share</p>
          ${buildThreatLensShareList(classificationShares)}
        </section>
      </div>

      <div class="result-grid result-grid-secondary">
        <section class="result-card">
          <p class="section-kicker">Campaign Spotlights</p>
          ${buildThreatLensSpotlights(campaignSpotlights)}
        </section>
        <section class="result-card">
          <p class="section-kicker">Top Threat Groups</p>
          ${buildThreatLensGroups(topGroups)}
        </section>
      </div>

      <div class="result-grid result-grid-secondary">
        <section class="result-card">
          <p class="section-kicker">Threat Trend</p>
          ${buildThreatLensTrendChart(trend)}
        </section>
        <section class="result-card">
          <p class="section-kicker">Theme Groups</p>
          ${buildThreatLensThemeGroups(themeGroups)}
        </section>
      </div>

      <div class="result-grid result-grid-secondary">
        <section class="result-card">
          <p class="section-kicker">Repeated Warning Signs</p>
          ${buildThreatLensCountList(summary.top_risk_signals, "No repeated warning signs yet.")}
        </section>
        <section class="result-card">
          <p class="section-kicker">Top Target Brands</p>
          ${buildThreatLensCountList(topBrandTargets, "No brand targets were detected in this window.")}
        </section>
      </div>

      <div class="result-grid result-grid-secondary">
        <section class="result-card">
          <p class="section-kicker">Common Risk Insights</p>
          ${buildThreatLensInsightList(summary.top_risk_insights, "No shared risk insights yet.")}
        </section>
        <section class="result-card">
          <p class="section-kicker">How to read this</p>
          <p class="factor-impact">ThreatLens keeps this section focused on the patterns that repeat most often in the selected window. It is meant to show what is recurring, not everything that was ever seen.</p>
        </section>
      </div>
    </div>
  `;
}

function bindThreatLensControls() {
  const rangeSelect = document.getElementById("threatlens-range");
  if (!rangeSelect) {
    return;
  }

  rangeSelect.value = currentThreatLensRange;
  rangeSelect.addEventListener("change", () => {
    currentThreatLensRange = rangeSelect.value;
    loadThreatLens();
  });
}

function buildThreatLensMetric(label, value, copy) {
  return `
    <article class="batch-summary-card threatlens-metric-card">
      <p class="fact-label">${label}</p>
      <p class="batch-summary-value">${value}</p>
      <p class="factor-impact">${copy}</p>
    </article>
  `;
}

function buildThreatLensShareList(items) {
  const rows = Array.isArray(items) ? items : [];
  if (!rows.length) {
    return '<p class="factor-impact">No saved share data yet.</p>';
  }

  return `
    <div class="factor-list">
      ${rows
        .map(
          (item) => `
            <div class="candidate-model-row threatlens-share-row">
              <div class="threatlens-trend-row-head">
                <p class="factor-title">${item.label}</p>
                <p class="threatlens-inline-meta">${item.count} · ${item.pct}%</p>
              </div>
              <div class="threatlens-bar-track">
                <div class="threatlens-bar-fill" style="width: ${Math.max(8, item.pct)}%"></div>
              </div>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function buildThreatLensSpotlights(items) {
  const rows = Array.isArray(items) ? items : [];
  if (!rows.length) {
    return '<p class="factor-impact">No campaign spotlights yet. Save more scans and ThreatLens will highlight the strongest repeated groups here.</p>';
  }

  return `
    <div class="threatlens-spotlight-grid">
      ${rows
        .map(
          (item) => `
            <article class="batch-summary-card threatlens-spotlight-card">
              <p class="section-kicker">Spotlight</p>
              <p class="factor-title">${item.headline}</p>
              <p class="batch-insight-value">${item.size} related link${item.size === 1 ? "" : "s"}</p>
              <p class="factor-impact">${item.grouping_reason}</p>
              <div class="dataset-name-list threatlens-chip-list">
                <span class="meta-pill">${sentenceCase(item.classification)}</span>
                <span class="meta-pill">${item.top_signal}</span>
              </div>
              <p class="example-url">${item.example_url || ""}</p>
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function buildThreatLensGroups(groups) {
  const items = Array.isArray(groups) ? groups : [];
  if (!items.length) {
    return '<p class="factor-impact">No saved groups yet. Once saved phishing-style links build up, ThreatLens will surface the biggest repeated patterns here.</p>';
  }

  return `
    <div class="factor-list">
      ${items
        .map(
          (group) => `
            <div class="candidate-model-row threatlens-group-row">
              <div>
                <p class="factor-title">${group.size} related link${group.size === 1 ? "" : "s"} · ${sentenceCase(group.classification)}</p>
                <div class="dataset-name-list threatlens-chip-list">
                  <span class="meta-pill">${group.category || "General phishing"}</span>
                  <span class="meta-pill">${group.theme || "General phishing"}</span>
                </div>
                <p class="factor-impact">${group.grouping_reason}</p>
                <p class="threatlens-inline-meta">
                  First seen ${formatShortDate(group.first_seen)} · Latest seen ${formatShortDate(group.latest_seen)}
                </p>
              </div>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function buildThreatLensThemeGroups(items) {
  const rows = Array.isArray(items) ? items : [];
  if (!rows.length) {
    return '<p class="factor-impact">No saved theme groups yet.</p>';
  }

  return `
    <div class="factor-list">
      ${rows
        .map(
          (item) => `
            <div class="candidate-model-row threatlens-theme-row">
              <div class="threatlens-trend-row-head">
                <p class="factor-title">${item.label}</p>
                <p class="threatlens-inline-meta">${item.count} total</p>
              </div>
              <div class="threatlens-bar-track">
                <div class="threatlens-bar-fill" style="width: ${Math.max(8, Math.min(item.count * 18, 100))}%"></div>
              </div>
              <p class="factor-impact">
                ${item.phishing} phishing · ${item.suspicious} suspicious · ${item.safe} safe
              </p>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function buildThreatLensTrendChart(trend) {
  const items = Array.isArray(trend) ? trend : [];
  if (!items.length) {
    return '<p class="factor-impact">No saved scan history yet for trend analysis.</p>';
  }

  const maxTotal = Math.max(...items.map((item) => Number(item.total || 0)), 1);

  return `
    <div class="factor-list threatlens-trend-list">
      ${items
        .map(
          (item) => `
            <div class="candidate-model-row threatlens-trend-row">
              <div class="threatlens-trend-row-head">
                <p class="factor-title">${formatShortDate(item.date)}</p>
                <p class="threatlens-inline-meta">${item.total} total</p>
              </div>
              <div class="threatlens-bar-track">
                <div class="threatlens-bar-fill" style="width: ${Math.max(8, Math.round((Number(item.total || 0) / maxTotal) * 100))}%"></div>
              </div>
              <div>
                <p class="factor-impact">
                  ${item.phishing} phishing · ${item.suspicious} suspicious · ${item.safe} safe
                </p>
              </div>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function buildThreatLensCountList(items, emptyCopy) {
  const rows = Array.isArray(items) ? items : [];
  if (!rows.length) {
    return `<p class="factor-impact">${emptyCopy}</p>`;
  }

  return `
    <div class="factor-list">
      ${rows
        .map(
          (item) => `
            <div class="factor-row">
              <span class="factor-icon factor-warn">i</span>
              <div class="factor-copy">
                <p class="factor-title">${item.label}</p>
                <p class="factor-impact">${item.count} saved link${item.count === 1 ? "" : "s"}</p>
              </div>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function buildThreatLensInsightList(items, emptyCopy) {
  const rows = Array.isArray(items) ? items : [];
  if (!rows.length) {
    return `<p class="factor-impact">${emptyCopy}</p>`;
  }

  return `
    <div class="factor-list">
      ${rows
        .map(
          (item) => `
            <div class="factor-row">
              <span class="factor-icon factor-bad">!</span>
              <div class="factor-copy">
                <p class="factor-title">${item.label}</p>
                <div class="threatlens-inline-bar">
                  <div class="threatlens-inline-bar-fill" style="width: ${Math.max(12, Math.min(item.count * 12, 100))}%"></div>
                </div>
                <p class="factor-impact">${item.count} saved link${item.count === 1 ? "" : "s"} showed this pattern</p>
              </div>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function firstThreatLensLabel(items, fallback) {
  if (!Array.isArray(items) || !items.length) {
    return fallback;
  }
  return items[0].label || fallback;
}

function buildThreatLensPills(items) {
  const rows = Array.isArray(items) ? items.slice(0, 4) : [];
  if (!rows.length) {
    return "";
  }

  return rows
    .map((item) => `<span class="meta-pill">${item.label}</span>`)
    .join("");
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

function buildMlSummary(mlAnalysis, ruleClassification, ruleRiskScore) {
  if (mlAnalysis.status !== "available") {
    return `
      <p class="factor-impact">${mlAnalysis.notes || "The model explanation is unavailable right now."}</p>
    `;
  }

  const signals = Array.isArray(mlAnalysis.top_signals) ? mlAnalysis.top_signals : [];
  const raisesRisk = signals.filter((signal) => signal.direction === "raises risk");
  const lowersRisk = signals.filter((signal) => signal.direction !== "raises risk");

  return `
    <div class="ml-probability-row">
      <span class="risk-pill ${statusClass(mlAnalysis.predicted_classification)}">
        ${sentenceCase(mlAnalysis.predicted_classification)}
      </span>
      <p class="ml-probability">${mlAnalysis.prediction_probability}% model risk</p>
      <span class="meta-pill">${sentenceCase(mlAnalysis.confidence_label || "unknown confidence")}</span>
    </div>
    <div class="ml-comparison-grid">
      <div class="fact-item">
        <p class="fact-label">Model name</p>
        <p class="fact-value">${mlAnalysis.model_name || "Unknown"}</p>
      </div>
      <div class="fact-item">
        <p class="fact-label">Explanation style</p>
        <p class="fact-value">${humanizeMethod(mlAnalysis.explanation_method)}</p>
      </div>
      <div class="fact-item">
        <p class="fact-label">Training source</p>
        <p class="fact-value">${mlAnalysis.training_source || "Unknown"}</p>
      </div>
      <div class="fact-item">
        <p class="fact-label">Training samples</p>
        <p class="fact-value">${mlAnalysis.training_samples || "Unknown"}</p>
      </div>
      <div class="fact-item">
        <p class="fact-label">Model version</p>
        <p class="fact-value">${mlAnalysis.model_version || "Unknown"}</p>
      </div>
      <div class="fact-item">
        <p class="fact-label">Calibration</p>
        <p class="fact-value">${sentenceCase(mlAnalysis.calibration_method || "unknown")}</p>
      </div>
      <div class="fact-item">
        <p class="fact-label">Risk thresholds</p>
        <p class="fact-value">${formatThresholds(mlAnalysis.decision_thresholds)}</p>
      </div>
    </div>
    ${buildEvaluationGrid(mlAnalysis.evaluation)}
    ${buildAgreementPanel(mlAnalysis, ruleClassification, ruleRiskScore)}
    <div class="ml-meta-row">
      <span class="meta-pill">Method: ${humanizeMethod(mlAnalysis.explanation_method)}</span>
      <span class="meta-pill ${mlAnalysis.shap_status === "available" ? "ml-pill-ready" : "ml-pill-pending"}">
        SHAP: ${sentenceCase(mlAnalysis.shap_status || "unavailable")}
      </span>
    </div>
    <p class="factor-impact">${mlAnalysis.notes || ""}</p>
    <div class="ml-signal-sections">
      ${buildSignalSection("Risk-raising signals", raisesRisk, "These pushed the model toward a higher-risk verdict.")}
      ${buildSignalSection("Reassuring signals", lowersRisk, "These gave the model reasons to be less concerned.")}
    </div>
    <details class="advanced-details">
      <summary>Model feature vector</summary>
      <div class="advanced-detail-grid">
        ${buildFeatureVectorRows(mlAnalysis.feature_vector)}
      </div>
    </details>
  `;
}

function buildCompactMlSummary(mlAnalysis, ruleClassification, ruleRiskScore) {
  if (mlAnalysis.status !== "available") {
    return `
      <p class="factor-impact">${mlAnalysis.notes || "The model explanation is unavailable right now."}</p>
    `;
  }

  const agrees =
    (mlAnalysis.predicted_classification || "unknown") === ruleClassification;
  const leadingSignal =
    Array.isArray(mlAnalysis.top_signals) && mlAnalysis.top_signals.length
      ? mlAnalysis.top_signals[0]
      : null;

  return `
    <div class="ml-probability-row">
      <span class="risk-pill ${statusClass(mlAnalysis.predicted_classification)}">
        ${sentenceCase(mlAnalysis.predicted_classification)}
      </span>
      <p class="ml-probability">${mlAnalysis.prediction_probability}% model risk</p>
      <span class="meta-pill">${agrees ? "Agrees with rule score" : "Differs from rule score"}</span>
    </div>
    <div class="fact-grid compact-fact-grid">
      ${buildFactItem(["Model", mlAnalysis.model_name || "Unknown"])}
      ${buildFactItem(["Method", humanizeMethod(mlAnalysis.explanation_method)])}
      ${buildFactItem(["Confidence", sentenceCase(mlAnalysis.confidence_label || "unknown")])}
      ${buildFactItem(["Rule score", `${ruleRiskScore}/100`])}
    </div>
    ${
      leadingSignal
        ? `
          <div class="compact-ml-note">
            <p class="factor-title">${leadingSignal.label}</p>
            <p class="factor-impact">${leadingSignal.description}</p>
          </div>
        `
        : `<p class="factor-impact">${mlAnalysis.notes || "No standout model signals were returned."}</p>`
    }
  `;
}

function buildModelReportPanel(report) {
  const evaluation = report.evaluation || {};
  const trainingSamples = report.training_samples ?? "Unknown";
  const trainRows = evaluation.train_samples ?? "Unknown";
  const testRows = evaluation.test_samples ?? "Unknown";
  const splitLabel =
    Number.isFinite(Number(trainRows)) && Number.isFinite(Number(testRows))
      ? buildSplitLabel(Number(trainRows), Number(testRows))
      : "Unknown split";

  return `
    <div class="model-report-card">
      <div class="model-report-header">
        <div>
          <p class="section-kicker">Model Report</p>
          <h3 class="model-report-title">Current ML snapshot</h3>
          <p class="model-report-copy">
            A quick view of the model behind the scanner, with the deeper benchmark details tucked just below.
          </p>
        </div>
        <span class="meta-pill model-report-pill">${trainingSamples} rows</span>
      </div>

      <div class="ml-comparison-grid">
        <div class="fact-item">
          <p class="fact-label">Model</p>
          <p class="fact-value">${report.model_name || "Unknown"}</p>
        </div>
        <div class="fact-item">
          <p class="fact-label">Explainability</p>
          <p class="fact-value">${report.status === "available" ? "SHAP" : "Fallback proxy"}</p>
        </div>
        <div class="fact-item">
          <p class="fact-label">Dataset</p>
          <p class="fact-value">${report.training_source || "Unknown"}</p>
        </div>
        <div class="fact-item">
          <p class="fact-label">Train / test split</p>
          <p class="fact-value">${splitLabel}</p>
        </div>
        <div class="fact-item">
          <p class="fact-label">Decision thresholds</p>
          <p class="fact-value">${formatThresholds(report.decision_thresholds)}</p>
        </div>
      </div>
      <div class="model-health-grid">
        ${buildModelHealthCard("Accuracy", formatMetric(evaluation.accuracy), "Held-out benchmark")}
        ${buildModelHealthCard("F1 score", formatMetric(evaluation.f1_score), "Balanced quality signal")}
        ${buildModelHealthCard("Datasets", report.dataset_count ?? 1, "Tracked local sources")}
        ${buildModelHealthCard("Benchmark runs", report.history_count ?? 0, "Model history captured")}
      </div>
      <div class="compact-ml-note model-health-note">
        <p class="factor-title">Strengthening over time</p>
        <p class="factor-impact">${buildModelProgressNarrative(report, evaluation)}</p>
      </div>
      ${buildEvaluationGrid(evaluation)}

      <details class="advanced-details model-report-details">
        <summary>Full model report</summary>
        ${buildConfusionMatrix(evaluation)}
        <div class="model-report-grid">
          <section class="model-report-section">
            <p class="section-kicker">Most influential features</p>
            <div class="factor-list">${buildGlobalFeatureRows(report.global_top_features)}</div>
          </section>
          <section class="model-report-section">
            <p class="section-kicker">Training metadata</p>
            <div class="fact-grid">
              ${buildFactItem(["Model version", report.model_version || "Unknown"])}
              ${buildFactItem(["Trained at", formatTimestamp(report.trained_at)])}
              ${buildFactItem(["Calibration", sentenceCase(report.calibration_method || "unknown")])}
              ${buildFactItem(["Datasets used", report.dataset_count ?? 1])}
              ${buildFactItem(["Benchmark runs saved", report.history_count ?? 0])}
            </div>
            ${buildDatasetNames(report.dataset_names)}
            <div class="factor-list model-candidate-list">
              ${buildCandidateModelRows(report.candidate_models)}
            </div>
            ${buildBenchmarkHistory(report.history)}
            <div class="model-report-actions">
              <a class="report-link" href="/api/model-report/download">Download model report</a>
            </div>
          </section>
        </div>
      </details>
    </div>
  `;
}

function buildModelHealthCard(label, value, copy) {
  return `
    <article class="batch-summary-card model-health-card">
      <p class="fact-label">${label}</p>
      <p class="batch-summary-value">${value}</p>
      <p class="factor-impact">${copy}</p>
    </article>
  `;
}

function buildModelProgressNarrative(report, evaluation) {
  const datasetCount = report.dataset_count ?? 1;
  const historyCount = report.history_count ?? 0;
  const split = buildSplitLabel(
    Number(evaluation.train_samples || 0),
    Number(evaluation.test_samples || 0)
  );
  const trainedAt = formatTimestamp(report.trained_at);

  return `The current model uses ${datasetCount} tracked dataset${datasetCount === 1 ? "" : "s"}, was last trained on ${trainedAt}, and keeps ${historyCount} benchmark snapshot${historyCount === 1 ? "" : "s"} for comparison. The current evaluation split is ${split}.`;
}

function humanizeMethod(method) {
  if (method === "feature_gap_proxy") {
    return "Feature-gap proxy";
  }
  if (method === "fallback_proxy") {
    return "Fallback proxy";
  }
  if (method === "shap") {
    return "SHAP";
  }
  return sentenceCase(method || "Unknown");
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
    ["Form count", contentAnalysis.form_count ?? "Not fetched"],
    ["Hidden fields", contentAnalysis.hidden_input_count ?? "Not fetched"],
    ["External form action", booleanLabel(contentAnalysis.form_action_external_detected)],
    ["Brand wording mismatch", booleanLabel(contentAnalysis.brand_impersonation_clues_detected)],
    ["Meta refresh", booleanLabel(contentAnalysis.meta_refresh_detected)],
    [
      "Brand words seen",
      Array.isArray(contentAnalysis.brand_keywords_detected) && contentAnalysis.brand_keywords_detected.length
        ? contentAnalysis.brand_keywords_detected.join(", ")
        : "None",
    ],
    ["External links found", contentAnalysis.external_link_count ?? "Not fetched"],
    ["Embedded frame", booleanLabel(contentAnalysis.iframe_detected)],
  ];

  return facts.map(buildFactItem).join("");
}

function buildRedirectRows(redirectAnalysis) {
  const facts = [
    ["Redirect count", redirectAnalysis.redirect_count ?? "Not fetched"],
    ["Final destination", redirectAnalysis.final_url || "Not fetched"],
    ["Final scheme", redirectAnalysis.final_scheme || "Not fetched"],
    ["Status code", redirectAnalysis.status_code ?? "Not fetched"],
    ["Different-site redirect", booleanLabel(redirectAnalysis.cross_domain_redirect_detected)],
    ["Cross-domain hops", redirectAnalysis.cross_domain_hops ?? "Not fetched"],
    ["HTTPS downgraded", booleanLabel(redirectAnalysis.downgrade_to_http_detected)],
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

  if (data.content_analysis?.brand_impersonation_clues_detected) {
    tips.push("The page mentions a known brand but the website name does not match, which is a common phishing trick.");
  }

  if (data.redirect_analysis?.downgrade_to_http_detected) {
    tips.push("The link dropped from HTTPS to HTTP during redirecting, which weakens protection in transit.");
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

function buildFeatureVectorRows(featureVector) {
  if (!featureVector || typeof featureVector !== "object") {
    return '<p class="advanced-detail-row"><span>Feature vector</span><span>Unavailable</span></p>';
  }

  return Object.entries(featureVector)
    .map(
      ([name, value]) => `
        <p class="advanced-detail-row">
          <span>${humanizeFeatureName(name)}</span>
          <span>${value}</span>
        </p>
      `
    )
    .join("");
}

function humanizeFeatureName(name) {
  return String(name || "")
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatModelRisk(mlAnalysis) {
  if (!mlAnalysis || mlAnalysis.status !== "available") {
    return "Unavailable";
  }
  return `${mlAnalysis.prediction_probability}%`;
}

function buildBatchRuleSignals(scoreBreakdown) {
  const items = Array.isArray(scoreBreakdown) ? scoreBreakdown.slice(0, 3) : [];
  if (!items.length) {
    return '<p class="factor-impact">No major rule signals were triggered.</p>';
  }

  return items
    .map(
      (item) => `
        <div class="batch-signal-item">
          <span class="risk-pill ${item.points >= 12 ? "status-phishing" : "status-suspicious"}">+${item.points}</span>
          <div>
            <p class="factor-title">${item.title || item.reason}</p>
            <p class="factor-impact">${item.impact || item.reason}</p>
          </div>
        </div>
      `
    )
    .join("");
}

function topRuleReason(scoreBreakdown) {
  const items = Array.isArray(scoreBreakdown) ? scoreBreakdown : [];
  if (!items.length) {
    return "No major rule signals";
  }
  return items[0].title || items[0].reason || "No major rule signals";
}

function buildBatchModelSignals(mlAnalysis) {
  if (!mlAnalysis || mlAnalysis.status !== "available") {
    return '<p class="factor-impact">Model output unavailable.</p>';
  }

  const items = Array.isArray(mlAnalysis.top_signals) ? mlAnalysis.top_signals : [];
  if (!items.length) {
    return '<p class="factor-impact">No standout model signals were found.</p>';
  }

  return items
    .map(
      (signal) => `
        <div class="batch-signal-item">
          <span class="risk-pill ${signal.direction === "raises risk" ? "status-suspicious" : "status-safe"}">
            ${signal.direction === "raises risk" ? "Risk" : "Low"}
          </span>
          <div>
            <p class="factor-title">${signal.label}</p>
            <p class="factor-impact">${signal.description}</p>
            ${buildSignalBar(signal)}
          </div>
        </div>
      `
    )
    .join("");
}

function buildSignalSection(title, signals, emptyCopy) {
  if (!signals.length) {
    return `
      <div class="ml-signal-card">
        <p class="section-kicker">${title}</p>
        <p class="factor-impact">${emptyCopy}</p>
      </div>
    `;
  }

  return `
    <div class="ml-signal-card">
      <p class="section-kicker">${title}</p>
      <div class="factor-list">
        ${signals
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
                      <span class="tooltip-bubble">${signal.description}</span>
                    </span>
                  </div>
                  <p class="factor-impact">${sentenceCase(signal.direction)}</p>
                  ${buildSignalBar(signal)}
                </div>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
  `;
}

function buildGlobalFeatureRows(features) {
  const items = Array.isArray(features) ? features : [];
  if (!items.length) {
    return '<p class="factor-impact">No global feature importance summary is available yet.</p>';
  }

  return items
    .map(
      (item) => `
        <div class="factor-row">
          <span class="factor-icon factor-warn">i</span>
          <div class="factor-copy">
            <p class="factor-title">${item.label}</p>
            <p class="factor-impact">${item.description}</p>
            ${buildImportanceBar(item)}
          </div>
        </div>
      `
    )
    .join("");
}

function buildCandidateModelRows(models) {
  const items = Array.isArray(models) ? models : [];
  if (!items.length) {
    return '<p class="factor-impact">No candidate model comparison is available.</p>';
  }

  return items
    .map(
      (item) => `
        <div class="candidate-model-row">
          <div>
            <p class="factor-title">${item.model_name}</p>
            <p class="factor-impact">F1 ${formatMetric(item.f1_score)} · Precision ${formatMetric(item.precision)} · Recall ${formatMetric(item.recall)}</p>
          </div>
        </div>
      `
    )
    .join("");
}

function buildDatasetNames(datasetNames) {
  const items = Array.isArray(datasetNames) ? datasetNames : [];
  if (!items.length) {
    return "";
  }

  return `
    <div class="dataset-name-list">
      ${items
        .map(
          (name) => `
            <span class="meta-pill">${name}</span>
          `
        )
        .join("")}
    </div>
  `;
}

function buildBenchmarkHistory(history) {
  const items = Array.isArray(history) ? history.slice(-3).reverse() : [];
  if (!items.length) {
    return "";
  }

  return `
    <div class="benchmark-history">
      <p class="section-kicker">Recent Benchmarks</p>
      <div class="factor-list">
        ${items
          .map(
            (item) => `
              <div class="candidate-model-row">
                <div>
                  <p class="factor-title">${item.model_name || "Unknown model"} · ${item.model_version || "Unknown version"}</p>
                  <p class="factor-impact">
                    ${formatTimestamp(item.trained_at)} · F1 ${formatMetric(item.evaluation?.f1_score)} · ROC AUC ${formatMetric(item.evaluation?.roc_auc)}
                  </p>
                </div>
              </div>
            `
          )
          .join("")}
      </div>
    </div>
  `;
}

function buildAgreementPanel(mlAnalysis, ruleClassification, ruleRiskScore) {
  const modelClassification = mlAnalysis.predicted_classification || "unknown";
  const agrees = modelClassification === ruleClassification;
  const toneClass = agrees ? "agreement-positive" : "agreement-warning";
  const title = agrees ? "Rule and model agree" : "Rule and model differ";
  const copy = agrees
    ? `Both checks point to ${sentenceCase(ruleClassification)} for this link.`
    : `Rules say ${sentenceCase(ruleClassification)}, while the model leans ${sentenceCase(modelClassification)}.`;

  return `
    <div class="agreement-card ${toneClass}">
      <div>
        <p class="fact-label">Agreement check</p>
        <p class="agreement-title">${title}</p>
        <p class="factor-impact">${copy}</p>
      </div>
      <div class="agreement-metrics">
        <span class="meta-pill">Rule score ${ruleRiskScore}/100</span>
        <span class="meta-pill">Model risk ${mlAnalysis.prediction_probability}%</span>
      </div>
    </div>
  `;
}

function buildSignalBar(signal) {
  const width = Math.max(6, Math.min(Number(signal.strength_pct || 0), 100));
  const toneClass = signal.direction === "raises risk" ? "signal-meter-risk" : "signal-meter-safe";
  return `
    <div class="signal-meter signal-meter-split ${signal.direction === "raises risk" ? "signal-meter-right" : "signal-meter-left"}">
      <div class="signal-meter-center"></div>
      <div class="signal-meter-fill ${toneClass}" style="width: ${width}%"></div>
    </div>
  `;
}

function buildImportanceBar(signal) {
  const width = Math.max(6, Math.min(Number(signal.strength_pct || 0), 100));
  return `
    <div class="signal-meter">
      <div class="signal-meter-fill signal-meter-neutral" style="width: ${width}%"></div>
    </div>
  `;
}

function buildEvaluationGrid(evaluation) {
  if (!evaluation || typeof evaluation !== "object" || !Object.keys(evaluation).length) {
    return '<p class="factor-impact">No evaluation summary is available in this interpreter.</p>';
  }

  return `
    <div class="ml-evaluation-grid">
      <div class="fact-item">
        <p class="fact-label">Accuracy</p>
        <p class="fact-value">${formatMetric(evaluation.accuracy)}</p>
      </div>
      <div class="fact-item">
        <p class="fact-label">Precision</p>
        <p class="fact-value">${formatMetric(evaluation.precision)}</p>
      </div>
      <div class="fact-item">
        <p class="fact-label">Recall</p>
        <p class="fact-value">${formatMetric(evaluation.recall)}</p>
      </div>
      <div class="fact-item">
        <p class="fact-label">F1 Score</p>
        <p class="fact-value">${formatMetric(evaluation.f1_score)}</p>
      </div>
      <div class="fact-item">
        <p class="fact-label">ROC AUC</p>
        <p class="fact-value">${formatMetric(evaluation.roc_auc)}</p>
      </div>
      <div class="fact-item">
        <p class="fact-label">Avg Precision</p>
        <p class="fact-value">${formatMetric(evaluation.average_precision)}</p>
      </div>
    </div>
  `;
}

function buildConfusionMatrix(evaluation) {
  const matrix = evaluation && Array.isArray(evaluation.confusion_matrix)
    ? evaluation.confusion_matrix
    : null;

  if (!matrix || matrix.length < 2 || !Array.isArray(matrix[0]) || !Array.isArray(matrix[1])) {
    return '<p class="factor-impact">Confusion matrix unavailable in this interpreter.</p>';
  }

  return `
    <div class="confusion-matrix-card">
      <p class="section-kicker">Confusion Matrix</p>
      <div class="confusion-matrix">
        <div class="matrix-cell matrix-label"></div>
        <div class="matrix-cell matrix-label">Predicted Safe</div>
        <div class="matrix-cell matrix-label">Predicted Risky</div>
        <div class="matrix-cell matrix-label">Actual Safe</div>
        <div class="matrix-cell">${matrix[0][0] ?? 0}</div>
        <div class="matrix-cell">${matrix[0][1] ?? 0}</div>
        <div class="matrix-cell matrix-label">Actual Risky</div>
        <div class="matrix-cell">${matrix[1][0] ?? 0}</div>
        <div class="matrix-cell">${matrix[1][1] ?? 0}</div>
      </div>
    </div>
  `;
}

function formatMetric(value) {
  if (value === undefined || value === null || Number.isNaN(Number(value))) {
    return "Unknown";
  }
  return Number(value).toFixed(4);
}

function buildSplitLabel(trainRows, testRows) {
  const total = trainRows + testRows;
  if (!total) {
    return "Unknown split";
  }

  const trainPct = Math.round((trainRows / total) * 100);
  const testPct = Math.round((testRows / total) * 100);
  return `${trainPct}/${testPct} (${trainRows.toLocaleString()} train, ${testRows.toLocaleString()} test)`;
}

function formatThresholds(thresholds) {
  if (!thresholds || typeof thresholds !== "object") {
    return "Unknown";
  }
  const safe = Number(thresholds.safe);
  const phishing = Number(thresholds.phishing);
  if (Number.isNaN(safe) || Number.isNaN(phishing)) {
    return "Unknown";
  }
  return `${safe.toFixed(2)} / ${phishing.toFixed(2)}`;
}

function bindBatchControls() {
  const filter = document.getElementById("batch-filter");
  const sort = document.getElementById("batch-sort");
  const exportButton = document.getElementById("batch-export-button");

  if (filter) {
    filter.value = batchFilterValue;
    filter.addEventListener("change", () => {
      batchFilterValue = filter.value;
      renderBatchWorkspace();
    });
  }

  if (sort) {
    sort.value = batchSortValue;
    sort.addEventListener("change", () => {
      batchSortValue = sort.value;
      renderBatchWorkspace();
    });
  }

  if (exportButton) {
    exportButton.addEventListener("click", downloadBatchCsv);
  }
}

function getFilteredBatchResults() {
  if (!currentBatchData) {
    return [];
  }

  let results = currentBatchData.results.slice();

  if (batchFilterValue !== "all") {
    results = results.filter((item) => item.classification === batchFilterValue);
  }

  results.sort((left, right) => {
    if (batchSortValue === "score_asc") {
      return left.risk_score - right.risk_score;
    }
    if (batchSortValue === "model_desc") {
      return getModelProbability(right.ml_analysis) - getModelProbability(left.ml_analysis);
    }
    if (batchSortValue === "url_asc") {
      return left.url.localeCompare(right.url);
    }
    return right.risk_score - left.risk_score;
  });

  return results;
}

function buildBatchSummaryCards(summary) {
  const items = [
    ["Total links", summary.total_urls || 0],
    ["Likely phishing", summary.phishing || 0],
    ["Use caution", summary.suspicious || 0],
    ["Looks safe", summary.safe || 0],
  ];

  return items
    .map(
      ([label, value]) => `
        <div class="batch-summary-card">
          <p class="fact-label">${label}</p>
          <p class="batch-summary-value">${value}</p>
        </div>
      `
    )
    .join("");
}

function buildBatchInsights(results) {
  if (!results.length) {
    return "";
  }

  const highestRisk = results.reduce(
    (best, item) => (item.risk_score > best.risk_score ? item : best),
    results[0]
  );
  const averageModelRisk =
    results.reduce((total, item) => total + getModelProbability(item.ml_analysis), 0) /
    results.length;
  const topReason = topRepeatedRuleReason(results);

  const insights = [
    ["Highest score", `${highestRisk.risk_score}/100`, highestRisk.url],
    ["Average model risk", `${averageModelRisk.toFixed(1)}%`, "Across the visible rows"],
    ["Most repeated signal", topReason, "Across the visible rows"],
  ];

  return insights
    .map(
      ([label, value, detail]) => `
        <div class="batch-insight-card">
          <p class="fact-label">${label}</p>
          <p class="batch-insight-value">${value}</p>
          <p class="factor-impact">${detail}</p>
        </div>
      `
    )
    .join("");
}

function humanBatchFilter(filterValue) {
  if (filterValue === "phishing") {
    return "Likely phishing";
  }
  if (filterValue === "suspicious") {
    return "Use caution";
  }
  if (filterValue === "safe") {
    return "Looks safe";
  }
  return "All results";
}

function topRepeatedRuleReason(results) {
  const counts = new Map();

  results.forEach((item) => {
    const reason = topRuleReason(item.score_breakdown);
    counts.set(reason, (counts.get(reason) || 0) + 1);
  });

  let bestReason = "No major rule signals";
  let bestCount = -1;
  counts.forEach((count, reason) => {
    if (count > bestCount) {
      bestReason = reason;
      bestCount = count;
    }
  });

  return bestReason;
}

function getModelProbability(mlAnalysis) {
  if (!mlAnalysis || mlAnalysis.status !== "available") {
    return -1;
  }
  return Number(mlAnalysis.prediction_probability || 0);
}

function downloadBatchCsv() {
  if (!currentBatchData) {
    return;
  }

  const rows = [
    ["url", "classification", "risk_score", "model_risk", "pattern_matches", "top_rule_reason"],
    ...getFilteredBatchResults().map((item) => [
      item.url,
      item.classification,
      item.risk_score,
      formatModelRisk(item.ml_analysis),
      item.similar_group_size,
      topRuleReason(item.score_breakdown),
    ]),
  ];
  const csv = rows
    .map((row) =>
      row
        .map((value) => `"${String(value).replaceAll('"', '""')}"`)
        .join(",")
    )
    .join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = "nexus-sentinel-batch-results.csv";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(downloadUrl);
}

function downloadSingleResult() {
  if (!currentSingleResult) {
    return;
  }

  const blob = new Blob([JSON.stringify(currentSingleResult, null, 2)], {
    type: "application/json",
  });
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = "nexus-sentinel-single-result.json";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(downloadUrl);
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

function formatShortDate(value) {
  if (!value) {
    return "Unknown date";
  }

  const date = new Date(value.length <= 10 ? `${value}T00:00:00Z` : value);
  if (Number.isNaN(date.getTime())) {
    return "Unknown date";
  }

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  }).format(date);
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
