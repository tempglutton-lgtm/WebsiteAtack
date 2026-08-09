const form = document.getElementById("scan-form");
const statusPanel = document.getElementById("status-panel");
const resultsPanel = document.getElementById("results-panel");
const statusTarget = document.getElementById("status-target");
const statusModule = document.getElementById("status-module");
const statusCurrentUrl = document.getElementById("status-current-url");
const statusRequests = document.getElementById("status-requests");
const statusEndpoints = document.getElementById("status-endpoints");
const progressRecon = document.getElementById("progress-reconnaissance");
const progressCrawl = document.getElementById("progress-crawling");
const progressEndpoints = document.getElementById("progress-endpoints");
const progressTesting = document.getElementById("progress-testing");
const cancelButton = document.getElementById("cancel-button");
const startButton = document.getElementById("start-button");
const resultsState = document.getElementById("results-state");

let polling = null;

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const targetUrl = document.getElementById("target-url").value.trim();
  const agree = document.getElementById("agree-checkbox").checked;
  if (!agree) {
    alert("Please confirm authorization before scanning.");
    return;
  }
  try {
    startButton.disabled = true;
    startButton.textContent = "SCANNING...";
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_url: targetUrl,
        agree_to_authorization: agree,
      }),
    });
    if (!response.ok) {
      const detail = await response.text();
      alert(`Scan could not start: ${detail}`);
      startButton.disabled = false;
      startButton.textContent = "START SCAN";
      return;
    }
    statusPanel.classList.remove("hidden");
    resultsPanel.classList.add("hidden");
    statusTarget.textContent = targetUrl;
    statusModule.textContent = "starting";
    resultsState.textContent = "Scanning";
    startPolling();
  } catch (error) {
    alert("Failed to start scan. Check the target URL and authorization confirmation.");
    startButton.disabled = false;
    startButton.textContent = "START SCAN";
  }
});

cancelButton.addEventListener("click", async () => {
  try {
    await fetch("/api/cancel", { method: "POST" });
  } catch (error) {
    console.warn("Cancel request failed", error);
  }
  stopPolling();
  startButton.disabled = false;
  startButton.textContent = "START SCAN";
  resultsState.textContent = "Cancelled";
  resultsPanel.classList.remove("hidden");
});

function renderProgress(progress) {
  statusModule.textContent = progress.module || "pending";
  statusCurrentUrl.textContent = progress.current_url || "-";
  statusRequests.textContent = progress.requests || 0;
  statusEndpoints.textContent = progress.discovered_endpoints || 0;
  const value = Math.min(100, Math.round((progress.discovered_endpoints || 0) / 10) * 10);
  progressRecon.style.width = `${value}%`;
  progressCrawl.style.width = `${Math.min(100, value + 10)}%`;
  progressEndpoints.style.width = `${Math.min(100, value + 20)}%`;
  progressTesting.style.width = `${progress.completed ? 100 : Math.min(100, value + 30)}%`;
}

function startPolling() {
  if (polling) return;
  polling = setInterval(async () => {
    try {
      const resp = await fetch("/api/progress");
      if (!resp.ok) {
        throw new Error(`Progress request failed: ${resp.status}`);
      }
      const progress = await resp.json();
      renderProgress(progress);
      if (progress.completed) {
        stopPolling();
        const results = await fetch("/api/results");
        if (!results.ok) {
          throw new Error(`Results request failed: ${results.status}`);
        }
        const scanResults = await results.json();
        showResults(scanResults);
      }
    } catch (error) {
      console.error(error);
      stopPolling();
      startButton.disabled = false;
      startButton.textContent = "START SCAN";
      alert("An error occurred while fetching scan progress. Refresh the page and try again.");
    }
  }, 1000);
}

function showResults(scanResults) {
  const resultsSummary = document.getElementById("results-summary");
  const findingsList = document.getElementById("findings-list");

  resultsPanel.classList.remove("hidden");
  startButton.disabled = false;
  startButton.textContent = "START SCAN";
  statusModule.textContent = "complete";
  resultsState.textContent = "Complete";

  const findings = scanResults.findings || [];
  const categoryCounts = findings.reduce((counts, finding) => {
    counts[finding.category] = (counts[finding.category] || 0) + 1;
    return counts;
  }, {});

  resultsSummary.innerHTML = `
    <div><strong>Endpoints discovered:</strong> ${scanResults.endpoints.length}</div>
    <div><strong>Total findings:</strong> ${findings.length}</div>
    <div><strong>Client-side findings:</strong> ${categoryCounts["Client-side"] || 0}</div>
    <div><strong>Injection findings:</strong> ${categoryCounts["Injection"] || 0}</div>
    <div><strong>Other findings:</strong> ${findings.length - ((categoryCounts["Client-side"] || 0) + (categoryCounts["Injection"] || 0))}</div>
  `;

  if (!findings.length) {
    findingsList.innerHTML = `<div class="finding-card"><p>No potential findings were detected by the automated scan.</p></div>`;
    return;
  }

  findingsList.innerHTML = findings.map((finding) => `
    <div class="finding-card">
      <div class="finding-header">
        <span class="severity ${finding.severity.toLowerCase()}">${finding.severity}</span>
        <h3>${finding.title}</h3>
      </div>
      <div class="finding-meta">
        <span>${finding.category}</span>
        <span>${finding.url || "N/A"}</span>
      </div>
      <p class="finding-text">${finding.explanation}</p>
      <p><strong>Confidence:</strong> ${finding.confidence}%</p>
      <p><strong>Status:</strong> ${finding.status}</p>
      <details class="finding-details">
        <summary>Evidence & verification</summary>
        <p><strong>Evidence:</strong> ${finding.evidence}</p>
        <p><strong>Verification:</strong> ${finding.verification_guidance}</p>
        <p><strong>Impact:</strong> ${finding.impact}</p>
        <p><strong>Remediation:</strong> ${finding.remediation}</p>
      </details>
    </div>
  `).join("");
}

function stopPolling() {
  if (!polling) return;
  clearInterval(polling);
  polling = null;
}
