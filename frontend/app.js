const form = document.getElementById("scan-form");
const statusPanel = document.getElementById("status-panel");
const resultsPanel = document.getElementById("results-panel");
const statusTarget = document.getElementById("status-target");
const statusModule = document.getElementById("status-module");
const statusCurrentUrl = document.getElementById("status-current-url");
const statusRequests = document.getElementById("status-requests");
const statusEndpoints = document.getElementById("status-endpoints");
const statusErrors = document.getElementById("status-errors");
const statusTests = document.getElementById("status-tests");
const progressRecon = document.getElementById("progress-reconnaissance");
const progressCrawl = document.getElementById("progress-crawling");
const progressEndpoints = document.getElementById("progress-endpoints");
const progressTesting = document.getElementById("progress-testing");
const cancelButton = document.getElementById("cancel-button");
const startButton = document.getElementById("start-button");
const exportJsonButton = document.getElementById("export-json");
const exportCsvButton = document.getElementById("export-csv");
const exportPdfButton = document.getElementById("export-pdf");
const severityFilter = document.getElementById("severity-filter");
const resultsState = document.getElementById("results-state");
const findingSearch = document.getElementById("finding-search");
const findingsCount = document.getElementById("findings-count");
const emptyState = document.getElementById("empty-state");
const findingsList = document.getElementById("findings-list");

let polling = null;
let currentResults = null;

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[character]);
}

findingsList.addEventListener("click", async (event) => {
  const button = event.target.closest(".save-review");
  if (!button || !currentResults) return;
  const card = button.closest("[data-review-card]");
  const feedback = card.querySelector(".review-feedback");
  const reviewer = card.querySelector(".review-reviewer").value.trim();
  const note = card.querySelector(".review-note").value;
  if (!reviewer) {
    feedback.textContent = "Indique o revisor.";
    return;
  }
  button.disabled = true;
  feedback.textContent = "A guardar no relatório local...";
  try {
    const response = await fetch(`/api/findings/${encodeURIComponent(button.dataset.reviewId)}/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: card.querySelector(".review-status").value,
        reviewer,
        note,
      }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
    const finding = currentResults.findings.find((item) => item.review_id === payload.review_id);
    if (finding) {
      finding.review_status = payload.review_status;
      finding.reviewer = payload.reviewer;
      finding.review_note = payload.review_note;
      finding.verification_status = payload.verification_status;
    }
    renderFindings();
    const updatedCard = Array.from(findingsList.querySelectorAll("[data-review-card]"))
      .find((item) => item.dataset.reviewCard === payload.review_id);
    if (updatedCard) updatedCard.querySelector(".review-feedback").textContent = "Triagem guardada e incluída nas próximas exportações.";
  } catch (error) {
    console.error(error);
    feedback.textContent = `Não foi possível guardar a triagem: ${error.message}`;
    button.disabled = false;
  }
});

function redactUrlQuery(value) {
  try {
    const url = new URL(value);
    for (const key of url.searchParams.keys()) {
      url.searchParams.set(key, "[redacted]");
    }
    return url.toString();
  } catch (error) {
    return String(value || "").split("?", 1)[0];
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const targetUrl = document.getElementById("target-url").value.trim();
  const agree = document.getElementById("agree-checkbox").checked;
  if (!agree) {
    alert("Confirme a autorização antes de iniciar a varredura.");
    return;
  }
  try {
    startButton.disabled = true;
    startButton.textContent = "A INICIAR...";
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_url: targetUrl,
        agree_to_authorization: agree,
      }),
    });
    if (!response.ok) {
      let detail = await response.text();
      try {
        const body = JSON.parse(detail);
        detail = body.detail || detail;
      } catch (error) {
        console.warn("Resposta de erro não estava em JSON", error);
      }
      alert(`Não foi possível iniciar a varredura: ${detail}`);
      startButton.disabled = false;
      startButton.textContent = "▶ INICIAR ANÁLISE";
      return;
    }
    statusPanel.classList.remove("hidden");
    resultsPanel.classList.add("hidden");
    emptyState.classList.add("hidden");
    statusTarget.textContent = redactUrlQuery(targetUrl);
    statusModule.textContent = "iniciando";
    statusErrors.textContent = "0";
    cancelButton.disabled = false;
    currentResults = null;
    resultsState.textContent = "A escanear";
    startPolling();
  } catch (error) {
    alert("Falha ao iniciar a varredura. Verifique a URL do alvo e a confirmação de autorização.");
    startButton.disabled = false;
    startButton.textContent = "▶ INICIAR ANÁLISE";
  }
});

cancelButton.addEventListener("click", async () => {
  try {
    const response = await fetch("/api/cancel", { method: "POST" });
    if (!response.ok) {
      throw new Error(`Pedido de cancelamento falhou: ${response.status}`);
    }
  } catch (error) {
    console.error(error);
    alert("Não foi possível confirmar o cancelamento da varredura.");
    return;
  }
  cancelButton.disabled = true;
  resultsState.textContent = "A cancelar";
});

function renderProgress(progress) {
  statusModule.textContent = progress.module || "pendente";
  statusCurrentUrl.textContent = progress.current_url ? redactUrlQuery(progress.current_url) : "À espera da execução";
  statusRequests.textContent = progress.requests || 0;
  statusEndpoints.textContent = progress.discovered_endpoints || 0;
  statusErrors.textContent = progress.error_count || 0;
  statusTests.textContent = `${progress.tests_performed || 0} / ${progress.tests_total || 0}`;
  const crawlPercent = progress.pages_limit
    ? Math.min(100, Math.round((progress.discovered_endpoints / progress.pages_limit) * 100))
    : 0;
  const testPercent = progress.tests_total
    ? Math.min(100, Math.round((progress.tests_performed / progress.tests_total) * 100))
    : 0;
  progressRecon.style.width = `${progress.requests ? 100 : 0}%`;
  progressCrawl.style.width = `${progress.crawl_completed ? 100 : crawlPercent}%`;
  progressEndpoints.style.width = `${progress.crawl_completed ? 100 : crawlPercent}%`;
  progressTesting.style.width = `${progress.completed ? 100 : testPercent}%`;
}

function startPolling() {
  if (polling) return;
  pollProgress();
}

async function pollProgress() {
  try {
    const resp = await fetch("/api/progress");
    if (!resp.ok) {
      throw new Error(`Pedido de progresso falhou: ${resp.status}`);
    }
    const progress = await resp.json();
    renderProgress(progress);
    if (progress.completed) {
      stopPolling();
      const results = await fetch("/api/results");
      if (!results.ok) {
        throw new Error(`Pedido de resultados falhou: ${results.status}`);
      }
      const scanResults = await results.json();
      showResults(scanResults);
      return;
    }
    polling = setTimeout(pollProgress, 1000);
  } catch (error) {
    console.error(error);
    stopPolling();
    startButton.disabled = false;
    startButton.textContent = "▶ INICIAR ANÁLISE";
    cancelButton.disabled = true;
    alert("Ocorreu um erro ao obter o progresso da varredura. Atualize a página e tente novamente.");
  }
}

function normalizeSeverity(value) {
  return String(value || "informational").trim().toLowerCase();
}

function getFilteredFindings() {
  const selected = normalizeSeverity(severityFilter.value);
  const query = findingSearch.value.trim().toLocaleLowerCase();
  const findings = currentResults?.findings || [];
  return findings.filter((finding) => {
    const matchesSeverity = !selected || selected === "all"
      || normalizeSeverity(finding.severity) === selected;
    const searchableText = [
      finding.title,
      finding.category,
      finding.url,
      finding.evidence,
      finding.explanation,
      finding.impact,
      finding.impact_pt,
      finding.remediation,
    ].join(" ").toLocaleLowerCase();
    return matchesSeverity && (!query || searchableText.includes(query));
  });
}

function renderFindings() {
  const findings = getFilteredFindings();
  findingsCount.textContent = currentResults
    ? `${findings.length}${findings.length !== currentResults.findings.length ? ` / ${currentResults.findings.length}` : ""}`
    : "0";

  if (!findings.length) {
    const emptyMessage = currentResults?.findings?.length
      ? "Não existem ocorrências que correspondam aos filtros selecionados."
      : "Nenhuma ocorrência foi apresentada nesta execução. Isto não prova que o sistema é seguro.";
    findingsList.innerHTML = `<div class="finding-card"><p>${escapeHTML(emptyMessage)}</p></div>`;
    return;
  }

  findingsList.innerHTML = findings.map((finding) => {
    const severity = String(finding.severity || "Informacional").trim();
    const severityClass = severity.toLowerCase().replace(/\s+/g, "");
    const explanation = finding.explanation || finding.impact_pt || finding.impact || "Sem descrição detalhada.";
    const playbook = finding.verification_playbook || {};
    const verificationSteps = Array.isArray(playbook.steps) ? playbook.steps : [];
    const reviewStatus = finding.review_status || "pending";

    return `
      <div class="finding-card" data-review-card="${escapeHTML(finding.review_id || "")}">
        <div class="finding-header">
          <span class="severity ${escapeHTML(severityClass)}">${escapeHTML(severity)}</span>
          <h3>${escapeHTML(finding.title)}</h3>
        </div>
        <div class="finding-meta">
          <span>${escapeHTML(finding.category)}</span>
          <span>${escapeHTML(finding.url || "N/D")}</span>
        </div>
        <p class="assessment-type">${escapeHTML(finding.assessment_type || "Indicador heurístico não confirmado.")}</p>
        <p class="finding-text">${escapeHTML(explanation)}</p>
        <p><strong>Pontuação heurística do scanner:</strong> ${escapeHTML(finding.confidence)}%</p>
        <p><strong>Scanner:</strong> ${escapeHTML(finding.scanner || "N/D")}</p>
        <p><strong>Estado:</strong> ${escapeHTML(finding.status)}</p>
        <p><strong>Validação:</strong> ${escapeHTML(finding.verification_status || "Requer verificação manual")}</p>
        <p><strong>Revisão humana:</strong> ${escapeHTML(reviewStatus)}${finding.reviewer ? ` · ${escapeHTML(finding.reviewer)}` : ""}</p>
        ${finding.review_note ? `<p><strong>Nota da revisão:</strong> ${escapeHTML(finding.review_note)}</p>` : ""}
        <details class="finding-details">
          <summary>Como verificar e confirmar</summary>
          <p><strong>Reprodução:</strong> ${escapeHTML(finding.reproduction?.instructions || "Repita apenas em ambiente autorizado e compare a evidência observada.")}</p>
          <p><strong>Evidência:</strong> ${escapeHTML(finding.evidence)}</p>
          <p><strong>Nota do scanner:</strong> ${escapeHTML(finding.verification_guidance)}</p>
          <p><strong>Ferramentas de apoio (não confirmam sozinhas):</strong> ${escapeHTML(playbook.tools || finding.verification_tool || "OWASP ZAP passivo e DevTools do browser")}</p>
          ${verificationSteps.length ? `<ol class="verification-steps">${verificationSteps.map((step) => `<li>${escapeHTML(step)}</li>`).join("")}</ol>` : ""}
          ${playbook.confirmation_criteria ? `<p><strong>Critério para confirmar:</strong> ${escapeHTML(playbook.confirmation_criteria)}</p>` : ""}
          ${playbook.false_positive_checks ? `<p><strong>Verifique também falsos positivos:</strong> ${escapeHTML(playbook.false_positive_checks)}</p>` : ""}
          <p><strong>Impacto no site:</strong> ${escapeHTML(finding.impact_pt || finding.impact || "A falha pode permitir abuso de dados, sessão ou funcionalidades do sistema.")}</p>
          <p><strong>Remediação:</strong> ${escapeHTML(finding.remediation)}</p>
          <div class="review-controls">
            <label class="label" for="review-status-${escapeHTML(finding.review_id)}">Registar triagem humana</label>
            <select id="review-status-${escapeHTML(finding.review_id)}" class="filter-select review-status">
              <option value="needs_review" ${reviewStatus === "needs_review" ? "selected" : ""}>Precisa de revisão</option>
              <option value="confirmed" ${reviewStatus === "confirmed" ? "selected" : ""}>Confirmado pelo revisor</option>
              <option value="false_positive" ${reviewStatus === "false_positive" ? "selected" : ""}>Falso positivo</option>
              <option value="not_reproducible" ${reviewStatus === "not_reproducible" ? "selected" : ""}>Não reproduzível</option>
              <option value="accepted_risk" ${reviewStatus === "accepted_risk" ? "selected" : ""}>Risco aceite</option>
            </select>
            <input class="filter-input review-reviewer" type="text" maxlength="100" placeholder="Nome do revisor" value="${escapeHTML(finding.reviewer || "")}" />
            <textarea class="filter-input review-note" maxlength="2000" rows="3" placeholder="Evidência manual, passos, impacto e limitações; não inclua segredos">${escapeHTML(finding.review_note || "")}</textarea>
            <button class="export-button save-review" type="button" data-review-id="${escapeHTML(finding.review_id || "")}">GUARDAR TRIAGEM</button>
            <span class="review-feedback" role="status"></span>
          </div>
        </details>
      </div>
    `;
  }).join("");
}

function renderScanErrors() {
  const errorsPanel = document.getElementById("scan-errors");
  const errors = currentResults.errors || [];
  const errorCount = Number(currentResults.error_count || errors.length);
  errorsPanel.replaceChildren();
  if (!errorCount) {
    errorsPanel.classList.add("hidden");
    return;
  }

  errorsPanel.classList.remove("hidden");
  const heading = document.createElement("strong");
  heading.textContent = `${errorCount} falha(s) ou aviso(s) durante a varredura. Os resultados podem estar incompletos.`;
  errorsPanel.appendChild(heading);
  if (errors.length) {
    const list = document.createElement("ul");
    for (const error of errors) {
      const item = document.createElement("li");
      item.textContent = `${error.stage || "varredura"} — ${error.component || "componente"} (${error.error_type || "erro"})`;
      list.appendChild(item);
    }
    if (errorCount > errors.length) {
      const item = document.createElement("li");
      item.textContent = `${errorCount - errors.length} falha(s) adicional(is) não exibida(s).`;
      list.appendChild(item);
    }
    errorsPanel.appendChild(list);
  }
}

function showResults(scanResults) {
  const resultsSummary = document.getElementById("results-summary");
  currentResults = scanResults || { endpoints: [], findings: [] };

  resultsPanel.classList.remove("hidden");
  emptyState.classList.add("hidden");
  startButton.disabled = false;
  startButton.textContent = "▶ INICIAR ANÁLISE";
  cancelButton.disabled = true;
  const status = currentResults.status || "completed";
  statusModule.textContent = status === "failed" ? "falhou" : status === "cancelled" ? "cancelada" : "concluído";

  const findings = currentResults.findings || [];
  const report = currentResults.report || {};
  const completeness = report.completeness || "desconhecida";
  resultsState.textContent = status === "failed"
    ? "Falha"
    : status === "cancelled"
      ? "Cancelada"
      : completeness === "execution_complete"
        ? "Execução concluída · cobertura não certificada"
        : "Execução parcial — rever avisos";
  const counts = report.counts || {};
  const limitations = Array.isArray(report.limitations) ? report.limitations : [];
  const scannerValidation = report.scanner_validation || {};
  const scannerCoverage = Array.isArray(report.scanner_coverage) ? report.scanner_coverage : [];
  const categoryCounts = findings.reduce((counts, finding) => {
    counts[finding.category] = (counts[finding.category] || 0) + 1;
    return counts;
  }, {});
  const clientSummary = status !== "completed"
    ? "A análise não terminou normalmente. Não use estes dados para tirar conclusões sobre a segurança do site."
    : completeness !== "execution_complete"
      ? `A execução foi parcial ou teve avisos. Os ${findings.length} indicadores observados requerem revisão e não demonstram que o site é inseguro.`
      : findings.length
        ? `Foram observados ${findings.length} indicadores automáticos. Isto não demonstra que o site é inseguro; valide cada indicador antes de comunicar conclusões.`
        : "Não foram observados indicadores nos controlos executados. Isto não demonstra que o site é seguro nem que todas as falhas foram detetadas.";

  resultsSummary.innerHTML = `
    <div class="client-summary"><strong>Resumo para partilha:</strong> ${escapeHTML(clientSummary)}</div>
    <div><strong>Autorização:</strong> ${report.authorization?.user_confirmation ? "declarada pelo utilizador, não verificada independentemente" : "não registada"}</div>
    <div><strong>Endpoints descobertos:</strong> ${currentResults.endpoints.length}</div>
    <div><strong>Indicadores (não confirmados):</strong> ${findings.length}</div>
    <div><strong>Falhas/avisos:</strong> ${Number(currentResults.error_count || 0)}</div>
    <div><strong>Estado da execução:</strong> ${escapeHTML(completeness)}</div>
    <div><strong>ID da varredura:</strong> ${escapeHTML(report.run_id || "N/D")}</div>
    <div><strong>Versão:</strong> ${escapeHTML(report.tool_version || "N/D")} (Python ${escapeHTML(report.python_version || "N/D")})</div>
    <div><strong>Modo dos scanners:</strong> ${escapeHTML(report.settings?.scanner_mode || "N/D")}</div>
    <div><strong>Requisições:</strong> ${Number(counts.requests || 0)}</div>
    <div><strong>Verificações:</strong> ${Number(counts.checks_completed || 0)} / ${Number(counts.checks_total || 0)}</div>
    <div><strong>Scanners executados:</strong> ${escapeHTML((report.scanner_selection || []).join(", ") || "N/D")}</div>
    <details><summary>Mapa de verificações (${scannerCoverage.length})</summary><ul>${scannerCoverage.map((item) => `<li><strong>${escapeHTML(item.name)}</strong> — ${escapeHTML(item.selected ? "selecionado" : "não executado")} (${escapeHTML(item.mode)}). ${escapeHTML(item.description)} ${item.selected ? `Aplicável a ${Number(item.applicable_endpoints || 0)} de ${Number(item.endpoints_considered || 0)} endpoints.` : escapeHTML(item.exclusion_reason || "")} Limite: ${escapeHTML(item.what_is_not_verified || item.coverage_note || "")} Validação: ${escapeHTML(item.validation_status)}. Alinhamento WSTG: ${escapeHTML(item.wstg_alignment)}</li>`).join("")}</ul><p>Aplicabilidade não comprova cobertura integral. As ligações a WSTG são apenas por família e não representam execução de casos WSTG.</p></details>
    <div><strong>Referência de metodologia:</strong> OWASP WSTG (alinhamento por família; não certifica os testes executados).</div>
    <div><strong>Validação independente:</strong> não realizada. Fixtures sintéticas: ${Number(scannerValidation.fixture_observations || 0)} casos em ${(scannerValidation.scanners_covered || []).length}/${Number(scannerValidation.registered_scanners || 0)} scanners; não representam desempenho geral.</div>
    <div><strong>Ocorrências do lado do cliente:</strong> ${categoryCounts["Client-side"] || 0}</div>
    <div><strong>Ocorrências de injeção:</strong> ${categoryCounts["Injection"] || 0}</div>
    <div><strong>Outras ocorrências:</strong> ${Math.max(0, findings.length - ((categoryCounts["Client-side"] || 0) + (categoryCounts["Injection"] || 0)))}</div>
    <div><strong>Nota:</strong> estes indicadores não confirmam vulnerabilidades. A confirmação exige reprodução e validação independente.</div>
    ${limitations.length ? `<details><summary>Limitações da execução</summary><ul>${limitations.map((item) => `<li>${escapeHTML(item)}</li>`).join("")}</ul></details>` : ""}
  `;

  renderScanErrors();
  renderFindings();
}

severityFilter.addEventListener("change", renderFindings);
findingSearch.addEventListener("input", renderFindings);

async function downloadReport(format, extension) {
  if (!currentResults) {
    alert("Não há relatório para exportar.");
    return;
  }

  try {
    const response = await fetch(`/api/export?output_format=${format}`);
    if (!response.ok) {
      throw new Error(`Falha ao gerar relatório: ${response.status}`);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `websiteattack-${currentResults.report?.run_id || "relatorio"}.${extension}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    console.error(error);
    alert("Não foi possível exportar o relatório.");
  }
}

exportJsonButton.addEventListener("click", () => downloadReport("json", "json"));
exportCsvButton.addEventListener("click", () => downloadReport("csv", "csv"));
exportPdfButton.addEventListener("click", () => downloadReport("pdf", "pdf"));

function stopPolling() {
  if (!polling) return;
  clearTimeout(polling);
  polling = null;
}
