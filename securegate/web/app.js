/**
 * SecureGate dashboard client.
 * The activity panel reports actual UI actions and API responses; it is not a
 * simulated network scanner or packet-capture feed.
 */
document.addEventListener('DOMContentLoaded', () => {
  const $ = (id) => document.getElementById(id);
  const navTabs = [...document.querySelectorAll('.nav-tab')];
  const tabViews = [...document.querySelectorAll('.tab-view')];

  // Existing assessment workbench controls (IDs retained for compatibility).
  const manifestEditor = $('manifestEditor');
  const selectReportFile = $('selectReportFile');
  const selectPolicyFile = $('selectPolicyFile');
  const btnRunAssessment = $('btnRunAssessment');
  const btnSaveBaseline = $('btnSaveBaseline');
  const resultTimestamp = $('resultTimestamp');
  const btnPresetEnterprise = $('btnPresetEnterprise');
  const btnPresetWeakened = $('btnPresetWeakened');
  const btnPresetInsecure = $('btnPresetInsecure');

  // Decision and finding controls.
  const decisionBanner = $('decisionBanner');
  const decisionIcon = $('decisionIcon');
  const decisionHeading = $('decisionHeading');
  const decisionSummary = $('decisionSummary');
  const valArtifactRisk = $('valArtifactRisk');
  const valDeploymentRisk = $('valDeploymentRisk');
  const valDriftRisk = $('valDriftRisk');
  const valTotalRisk = $('valTotalRisk');
  const valRiskLevel = $('valRiskLevel');
  const countBlocking = $('countBlocking');
  const countWarnings = $('countWarnings');
  const countIgnored = $('countIgnored');
  const findingsList = $('findingsList');
  const findingTabs = [...document.querySelectorAll('.findings-tab')];

  // CI/CD report controls.
  const btnRefreshReports = $('btnRefreshReports');
  const reportFileList = $('reportFileList');
  const activeReportName = $('activeReportName');
  const activeReportMeta = $('activeReportMeta');
  const reportContentArea = $('reportContentArea');

  // Drift controls.
  const selectBaselineFile = $('selectBaselineFile');
  const driftManifestEditor = $('driftManifestEditor');
  const btnRunDriftCheck = $('btnRunDriftCheck');
  const driftDecisionBanner = $('driftDecisionBanner');
  const driftDecisionIcon = $('driftDecisionIcon');
  const driftDecisionHeading = $('driftDecisionHeading');
  const driftDecisionSummary = $('driftDecisionSummary');
  const driftEventsContainer = $('driftEventsContainer');

  // Dashboard-only controls and metrics.
  const activityLog = $('activityLog');
  const activityLogList = $('activityLogList');
  const btnClearActivity = $('btnClearActivity');
  const btnOpenTargetScan = $('btnOpenTargetScan');
  const btnQuickOpenResults = $('btnQuickOpenResults');
  const btnQuickAssessment = $('btnQuickAssessment');
  const quickPreset = $('quickPreset');
  const quickPolicyFile = $('quickPolicyFile');
  const dashActiveThreats = $('dashActiveThreats');
  const dashScansCompleted = $('dashScansCompleted');
  const dashApiStatus = $('dashApiStatus');
  const dashApiMeta = $('dashApiMeta');
  const dashBaselineCount = $('dashBaselineCount');
  const engineStatusText = $('engineStatusText');
  const engineStatusDot = $('engineStatusDot');
  const appVersion = $('appVersion');
  const pageTitle = $('pageTitle');
  const sectionEyebrow = $('sectionEyebrow');

  let currentAssessmentResult = null;
  let activeFindingsFilter = 'blocking';
  let sampleManifests = {};
  let completedAssessments = 0;
  let savedBaselineCount = null;
  let apiIsOnline = false;

  const viewNames = {
    viewDashboard: ['Dashboard', 'OVERVIEW'],
    viewWorkbench: ['Target Scan', 'ASSESSMENT WORKBENCH'],
    viewPipeline: ['Logs & Events', 'CI/CD ARTIFACTS'],
    viewDrift: ['Drift & Baseline', 'POSTURE COMPARISON'],
    viewPolicy: ['Settings & Policy', 'POLICY CONFIGURATION'],
  };

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[char]);
  }

  function safeExternalUrl(value) {
    if (!value) return '';
    try {
      const url = new URL(String(value));
      return ['http:', 'https:'].includes(url.protocol) ? url.href : '';
    } catch {
      return '';
    }
  }

  function logActivity(level, message) {
    if (!activityLogList) return;
    const time = new Date().toLocaleTimeString([], { hour12: false });
    const line = document.createElement('div');
    line.className = 'log-line';
    const timeEl = document.createElement('time');
    timeEl.textContent = time;
    const levelEl = document.createElement('span');
    levelEl.className = `log-level ${({ INFO: 'log-info', WARN: 'log-warn', ALERT: 'log-alert', SUCCESS: 'log-success' })[level] || 'log-info'}`;
    levelEl.textContent = level;
    const messageEl = document.createElement('span');
    messageEl.className = 'log-message';
    messageEl.textContent = message;
    line.append(timeEl, levelEl, messageEl);
    activityLogList.appendChild(line);

    // Keep the activity pane small and responsive on long sessions.
    while (activityLogList.children.length > 100) activityLogList.removeChild(activityLogList.firstElementChild);
    if (activityLog) activityLog.scrollTop = activityLog.scrollHeight;
  }

  function updateDashboardMetrics() {
    if (dashScansCompleted) dashScansCompleted.textContent = String(completedAssessments);
    if (dashBaselineCount) dashBaselineCount.textContent = savedBaselineCount === null ? '—' : String(savedBaselineCount);
    if (dashActiveThreats) {
      dashActiveThreats.textContent = currentAssessmentResult?.summary
        ? String(currentAssessmentResult.summary.blocking ?? 0)
        : '—';
    }
    if (dashApiStatus) {
      dashApiStatus.textContent = apiIsOnline ? 'Online' : 'Offline';
      dashApiStatus.style.color = apiIsOnline ? 'var(--success)' : 'var(--danger)';
    }
    if (dashApiMeta) dashApiMeta.textContent = apiIsOnline ? 'SecureGate REST API responding' : 'API connection unavailable';
    if (engineStatusText) engineStatusText.textContent = apiIsOnline ? 'Connected' : 'API offline';
    if (engineStatusDot) {
      engineStatusDot.classList.toggle('is-online', apiIsOnline);
      engineStatusDot.classList.toggle('is-offline', !apiIsOnline);
    }
    const apiFoot = document.querySelector('.dashboard-metric-card:nth-child(3) .metric-foot');
    const apiSymbol = document.querySelector('.dashboard-metric-card:nth-child(3) .metric-symbol');
    if (apiSymbol) {
      apiSymbol.classList.toggle('metric-symbol-success', apiIsOnline);
      apiSymbol.classList.toggle('metric-symbol-danger', !apiIsOnline);
      apiSymbol.textContent = apiIsOnline ? '●' : '!';
    }
    if (apiFoot) {
      apiFoot.innerHTML = `<span class="tiny-status ${apiIsOnline ? 'tiny-status-online' : 'tiny-status-offline'}"></span>${apiIsOnline ? 'Service reachable' : 'Check local server'} `;
    }
  }

  async function checkApiHealth() {
    try {
      const response = await fetch('/api/status', { cache: 'no-store' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      apiIsOnline = data.status === 'ok';
      if (appVersion && data.version) appVersion.textContent = `v${data.version}`;
      updateDashboardMetrics();
      if (apiIsOnline) logActivity('SUCCESS', `REST API connected (${data.version || 'version unavailable'}).`);
      else logActivity('WARN', 'REST API responded, but did not report a healthy status.');
    } catch (error) {
      apiIsOnline = false;
      updateDashboardMetrics();
      logActivity('ALERT', `Cannot reach SecureGate API: ${error.message}. Start the dashboard server and reload.`);
    }
  }

  function navigateTo(targetId) {
    const targetView = document.getElementById(targetId);
    if (!targetView) return;
    navTabs.forEach((tab) => {
      const active = tab.getAttribute('data-target') === targetId;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', String(active));
    });
    tabViews.forEach((view) => view.classList.toggle('active', view.id === targetId));
    const names = viewNames[targetId] || ['SecureGate', 'WORKSPACE'];
    if (pageTitle) pageTitle.textContent = names[0];
    if (sectionEyebrow) sectionEyebrow.textContent = names[1];
    if (targetId === 'viewPipeline') loadPipelineReports();
    if (targetId === 'viewDrift') loadBaselinesList();
    logActivity('INFO', `View opened: ${names[0]}.`);
  }

  navTabs.forEach((tab) => tab.addEventListener('click', () => navigateTo(tab.getAttribute('data-target'))));
  if (btnOpenTargetScan) btnOpenTargetScan.addEventListener('click', () => navigateTo('viewWorkbench'));
  if (btnQuickOpenResults) btnQuickOpenResults.addEventListener('click', () => navigateTo('viewWorkbench'));
  const btnViewPolicy = $('btnViewPolicy');
  if (btnViewPolicy) btnViewPolicy.addEventListener('click', () => navigateTo('viewPolicy'));
  const btnViewDrift = $('btnViewDrift');
  if (btnViewDrift) btnViewDrift.addEventListener('click', () => navigateTo('viewDrift'));

  if (btnClearActivity) {
    btnClearActivity.addEventListener('click', () => {
      if (activityLogList) activityLogList.replaceChildren();
      logActivity('INFO', 'Activity stream cleared by user.');
    });
  }

  function weakenedManifest() {
    let weakened = sampleManifests.hardened_sample || sampleManifests.enterprise_sample || '';
    weakened = weakened.replace('privileged: false', 'privileged: true');
    weakened = weakened.replace('runAsUser: 10001', 'runAsUser: 0');
    return weakened;
  }

  function getPresetManifest(type) {
    if (type === 'weakened') return weakenedManifest();
    if (type === 'insecure') return sampleManifests.insecure_sample || '';
    return sampleManifests.hardened_sample || sampleManifests.enterprise_sample || '';
  }

  async function loadSamples() {
    try {
      const response = await fetch('/api/samples');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      sampleManifests = await response.json();
      if (!sampleManifests.hardened_sample && !sampleManifests.enterprise_sample && !sampleManifests.insecure_sample) {
        throw new Error('The API returned no sample manifests.');
      }
      if (quickPreset) quickPreset.value = 'enterprise';
      if (btnQuickAssessment) btnQuickAssessment.disabled = false;
      setPreset('enterprise', false);
      if (driftManifestEditor && !driftManifestEditor.value.trim()) {
        driftManifestEditor.value = weakenedManifest();
      }
      logActivity('INFO', 'Sample Kubernetes manifests loaded.');
    } catch (error) {
      if (btnQuickAssessment) btnQuickAssessment.disabled = true;
      logActivity('WARN', `Could not load sample manifests: ${error.message}`);
      console.error('Failed to load sample manifests:', error);
    }
  }

  function setPreset(type, shouldLog = true) {
    document.querySelectorAll('.pill-btn').forEach((button) => button.classList.remove('active'));
    const map = {
      enterprise: btnPresetEnterprise,
      weakened: btnPresetWeakened,
      insecure: btnPresetInsecure,
    };
    if (map[type]) map[type].classList.add('active');
    if (manifestEditor) manifestEditor.value = getPresetManifest(type);
    if (shouldLog) logActivity('INFO', `Loaded ${type} manifest preset into Target Scan.`);
  }

  if (btnPresetEnterprise) btnPresetEnterprise.addEventListener('click', () => setPreset('enterprise'));
  if (btnPresetWeakened) btnPresetWeakened.addEventListener('click', () => setPreset('weakened'));
  if (btnPresetInsecure) btnPresetInsecure.addEventListener('click', () => setPreset('insecure'));

  async function postJson(url, payload) {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    let data;
    try { data = await response.json(); }
    catch { throw new Error(`The server returned an unreadable response (HTTP ${response.status}).`); }
    if (!response.ok) throw new Error(data.error || `Request failed (HTTP ${response.status})`);
    return data;
  }

  // Quick action performs a real SecureGate Kubernetes inspection via /api/inspect.
  if (btnQuickAssessment) {
    btnQuickAssessment.addEventListener('click', async () => {
      const type = quickPreset?.value || 'enterprise';
      const yamlContent = getPresetManifest(type);
      const policyFile = quickPolicyFile?.value || 'config/policy.yaml';
      if (!yamlContent.trim()) {
        alert('Sample manifests are not available yet. Confirm the SecureGate server is running, then reload.');
        return;
      }
      btnQuickAssessment.disabled = true;
      btnQuickAssessment.textContent = 'Inspecting manifest…';
      logActivity('INFO', `Starting Kubernetes inspection (${type} preset, ${policyFile}).`);
      try {
        const data = await postJson('/api/inspect', { manifest_yaml: yamlContent, policy_file: policyFile });
        currentAssessmentResult = data;
        completedAssessments += 1;
        if (manifestEditor) manifestEditor.value = yamlContent;
        if (selectPolicyFile) selectPolicyFile.value = policyFile;
        if (selectReportFile) selectReportFile.value = 'none';
        renderAssessmentResults(data);
        updateDashboardMetrics();
        const level = data.decision === 'BLOCK' ? 'ALERT' : (data.decision === 'WARN' ? 'WARN' : 'SUCCESS');
        logActivity(level, `Manifest inspection finished: ${data.decision || 'NO DECISION'}; ${data.summary?.blocking ?? 0} blocking, ${data.summary?.warnings ?? 0} warnings.`);
      } catch (error) {
        logActivity('ALERT', `Manifest inspection failed: ${error.message}`);
        alert(`Assessment Error: ${error.message}`);
      } finally {
        btnQuickAssessment.disabled = false;
        btnQuickAssessment.innerHTML = '<span aria-hidden="true">▶</span> Run sample assessment';
      }
    });
  }

  if (btnRunAssessment) {
    btnRunAssessment.addEventListener('click', async () => {
      const yamlContent = manifestEditor?.value || '';
      if (!yamlContent.trim()) {
        alert('Please enter or select a Kubernetes YAML manifest.');
        return;
      }
      btnRunAssessment.disabled = true;
      btnRunAssessment.textContent = 'Evaluating…';
      const payload = {
        manifest_yaml: yamlContent,
        report_file: selectReportFile.value === 'none' ? '' : selectReportFile.value,
        policy_file: selectPolicyFile.value,
      };
      logActivity('INFO', `Starting combined assessment (policy ${payload.policy_file}; Trivy report ${payload.report_file || 'not attached'}).`);
      try {
        const data = await postJson('/api/assess', payload);
        currentAssessmentResult = data;
        completedAssessments += 1;
        renderAssessmentResults(data);
        updateDashboardMetrics();
        const level = data.decision === 'BLOCK' ? 'ALERT' : (data.decision === 'WARN' ? 'WARN' : 'SUCCESS');
        logActivity(level, `Assessment finished: ${data.decision || 'NO DECISION'}; ${data.summary?.blocking ?? 0} blocking, ${data.summary?.warnings ?? 0} warnings.`);
      } catch (error) {
        logActivity('ALERT', `Assessment failed: ${error.message}`);
        alert(`Assessment Error: ${error.message}`);
      } finally {
        btnRunAssessment.disabled = false;
        btnRunAssessment.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run Security Assessment';
      }
    });
  }

  function renderAssessmentResults(data) {
    if (resultTimestamp) {
      const timestamp = data.timestamp ? new Date(data.timestamp) : new Date();
      resultTimestamp.textContent = `Evaluated ${timestamp.toLocaleTimeString()}`;
    }
    const summary = data.summary || {};
    decisionBanner.className = 'decision-banner';
    if (data.decision === 'BLOCK') {
      decisionBanner.classList.add('banner-block');
      decisionIcon.textContent = '×';
      decisionHeading.textContent = 'DEPLOYMENT BLOCKED';
      decisionSummary.textContent = `${summary.blocking ?? 0} mandatory security policy violation(s) detected. Pipeline must halt.`;
      btnSaveBaseline.disabled = true;
    } else if (data.decision === 'WARN') {
      decisionBanner.classList.add('banner-warn');
      decisionIcon.textContent = '!';
      decisionHeading.textContent = 'PASSED WITH WARNINGS';
      decisionSummary.textContent = `No blocking violations. ${summary.warnings ?? 0} advisory warning(s) should be reviewed.`;
      btnSaveBaseline.disabled = false;
    } else {
      decisionBanner.classList.add('banner-pass');
      decisionIcon.textContent = '✓';
      decisionHeading.textContent = 'DEPLOYMENT APPROVED';
      decisionSummary.textContent = 'All evaluated security controls satisfied the active policy.';
      btnSaveBaseline.disabled = false;
    }

    if (data.risk) {
      valArtifactRisk.textContent = `${data.risk.artifact_risk ?? 0} pts`;
      valDeploymentRisk.textContent = `${data.risk.deployment_risk ?? 0} pts`;
      valDriftRisk.textContent = `${data.risk.drift_risk ?? 0} pts`;
      valTotalRisk.textContent = `${data.risk.total_risk ?? 0}/100`;
      valRiskLevel.textContent = `Level: ${data.risk.level ?? 'UNKNOWN'}`;
    }
    countBlocking.textContent = summary.blocking ?? 0;
    countWarnings.textContent = summary.warnings ?? 0;
    countIgnored.textContent = summary.ignored ?? 0;
    activeFindingsFilter = (summary.blocking ?? 0) > 0 ? 'blocking' : ((summary.warnings ?? 0) > 0 ? 'warnings' : 'ignored');
    updateFindingsTabUI();
    renderFindingsList();
  }

  findingTabs.forEach((tab) => tab.addEventListener('click', () => {
    activeFindingsFilter = tab.getAttribute('data-type');
    updateFindingsTabUI();
    renderFindingsList();
  }));

  function updateFindingsTabUI() {
    findingTabs.forEach((tab) => tab.classList.toggle('active', tab.getAttribute('data-type') === activeFindingsFilter));
  }

  function renderFindingsList() {
    if (!currentAssessmentResult || !findingsList) return;
    let items = [];
    if (activeFindingsFilter === 'blocking') items = currentAssessmentResult.blocking_findings || [];
    else if (activeFindingsFilter === 'warnings') items = currentAssessmentResult.warning_findings || [];
    else items = currentAssessmentResult.ignored_findings || [];

    if (!items.length) {
      findingsList.innerHTML = `<div class="empty-state"><p>No ${escapeHtml(activeFindingsFilter)} findings present in this assessment.</p></div>`;
      return;
    }
    findingsList.innerHTML = items.map((finding) => {
      const severity = String(finding.severity || 'UNKNOWN').toUpperCase();
      const badgeClass = ['CRITICAL', 'HIGH'].includes(severity) ? 'badge-block' : (severity === 'LOW' ? 'badge-allow' : 'badge-warn');
      const categoryTag = finding.category ? `<span class="badge badge-warn">${escapeHtml(finding.category)}</span>` : '';
      const fixedInfo = finding.fixed_version ? `<span style="color:#75dcb2;font-size:10px;">Fix available: ${escapeHtml(finding.fixed_version)}</span>` : '';
      const cveUrl = finding.category === 'vulnerability' ? safeExternalUrl(finding.primary_url) : '';
      const findingLabel = cveUrl
        ? `<a class="finding-cve-link" href="${escapeHtml(cveUrl)}" target="_blank" rel="noopener noreferrer" title="${escapeHtml(finding.description || finding.title || 'Open vulnerability details')}">${escapeHtml(finding.id || 'FINDING')}<span aria-hidden="true"> ↗</span></a>`
        : `<span class="finding-id"${finding.description ? ` title="${escapeHtml(finding.description)}"` : ''}>${escapeHtml(finding.id || 'FINDING')}</span>`;
      return `<div class="finding-item">
        <div class="finding-top-row">${findingLabel}
          <div>${categoryTag}<span class="badge ${badgeClass}">${escapeHtml(severity)}</span></div>
        </div>
        <div class="finding-message">${escapeHtml(finding.message || 'Security control violation')}</div>
        <div class="finding-resource">Resource: ${escapeHtml(finding.resource || 'N/A')} ${fixedInfo ? ' · ' + fixedInfo : ''}</div>
      </div>`;
    }).join('');
  }

  // Baselines are only saved after an assessment passes the policy gate.
  if (btnSaveBaseline) {
    btnSaveBaseline.addEventListener('click', async () => {
      const yamlContent = manifestEditor?.value || '';
      const name = prompt('Enter a filename for this approved security baseline:', 'production-baseline.json');
      if (!name) return;
      if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*\.json$/i.test(name) || name.includes('..')) {
        alert('Use a simple .json filename containing letters, numbers, dots, underscores, or hyphens.');
        return;
      }
      try {
        logActivity('INFO', `Saving approved baseline ${name}.`);
        const data = await postJson('/api/baseline/save', { manifest_yaml: yamlContent, name });
        alert(`Approved security baseline saved successfully: ${data.filename}`);
        logActivity('SUCCESS', `Baseline saved: ${data.filename}.`);
        await loadBaselinesList();
      } catch (error) {
        logActivity('ALERT', `Baseline save failed: ${error.message}`);
        alert(`Baseline Error: ${error.message}`);
      }
    });
  }

  async function loadPipelineReports() {
    if (!reportFileList) return;
    reportFileList.innerHTML = '<div class="loading-state">Loading reports…</div>';
    try {
      const response = await fetch('/api/reports', { cache: 'no-store' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const reports = Array.isArray(data.reports) ? data.reports : [];
      if (!reports.length) {
        reportFileList.innerHTML = '<div class="empty-state"><p>No JSON reports found in the project reports directory.</p></div>';
        logActivity('INFO', 'Report list loaded; no report files found.');
        return;
      }
      reportFileList.innerHTML = reports.map((report, index) => `
        <button type="button" class="report-file-item ${index === 0 ? 'active' : ''}" data-file="${escapeHtml(report.filename)}">
          <span class="report-file-name">${escapeHtml(report.filename)}</span>
          <span class="report-file-size">${((report.size_bytes || 0) / 1024).toFixed(1)} KB · ${new Date((report.modified_at || 0) * 1000).toLocaleString()}</span>
        </button>`).join('');
      reportFileList.querySelectorAll('.report-file-item').forEach((item) => item.addEventListener('click', () => {
        reportFileList.querySelectorAll('.report-file-item').forEach((entry) => entry.classList.remove('active'));
        item.classList.add('active');
        inspectReport(item.getAttribute('data-file'));
      }));
      logActivity('INFO', `Loaded ${reports.length} report file(s).`);
      await inspectReport(reports[0].filename);
    } catch (error) {
      reportFileList.innerHTML = `<div class="empty-state"><p>Error loading reports: ${escapeHtml(error.message)}</p></div>`;
      logActivity('WARN', `Could not load reports: ${error.message}`);
    }
  }

  async function inspectReport(filename) {
    if (!filename || !reportContentArea) return;
    activeReportName.textContent = filename;
    reportContentArea.textContent = 'Loading payload…';
    try {
      const response = await fetch(`/api/reports/${encodeURIComponent(filename)}`);
      const json = await response.json();
      if (!response.ok) throw new Error(json.error || `HTTP ${response.status}`);
      reportContentArea.textContent = JSON.stringify(json, null, 2);
      activeReportMeta.textContent = json.decision ? `Decision: ${json.decision}` : '';
      logActivity('INFO', `Opened report: ${filename}.`);
    } catch (error) {
      reportContentArea.textContent = `Failed to load report: ${error.message}`;
      activeReportMeta.textContent = 'Read failed';
      logActivity('WARN', `Could not open report ${filename}: ${error.message}`);
    }
  }

  if (btnRefreshReports) btnRefreshReports.addEventListener('click', loadPipelineReports);

  async function loadBaselinesList() {
    if (!selectBaselineFile) return;
    try {
      const response = await fetch('/api/baselines', { cache: 'no-store' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const baselines = Array.isArray(data.baselines) ? data.baselines : [];
      savedBaselineCount = baselines.length;
      updateDashboardMetrics();
      if (!baselines.length) {
        selectBaselineFile.innerHTML = '<option value="">(No baselines found)</option>';
        logActivity('INFO', 'Baseline inventory loaded; no saved baselines found.');
        return;
      }
      selectBaselineFile.innerHTML = baselines.map((baseline) =>
        `<option value="${escapeHtml(baseline.filename)}">${escapeHtml(baseline.filename)} (${((baseline.size_bytes || 0) / 1024).toFixed(1)} KB)</option>`
      ).join('');
      if (driftManifestEditor && !driftManifestEditor.value.trim() && sampleManifests.enterprise_sample) {
        driftManifestEditor.value = weakenedManifest();
      }
      logActivity('INFO', `Loaded ${baselines.length} saved baseline(s).`);
    } catch (error) {
      console.error('Failed to load baselines:', error);
      logActivity('WARN', `Could not load baselines: ${error.message}`);
    }
  }

  if (btnRunDriftCheck) {
    btnRunDriftCheck.addEventListener('click', async () => {
      const baselineFile = selectBaselineFile.value;
      const manifestYaml = driftManifestEditor.value;
      if (!baselineFile) {
        alert('Please select an approved baseline first. You can save one from the Target Scan tab after a passing assessment.');
        return;
      }
      if (!manifestYaml.trim()) {
        alert('Please enter a manifest to compare for configuration drift.');
        return;
      }
      btnRunDriftCheck.disabled = true;
      btnRunDriftCheck.textContent = 'Analyzing drift…';
      logActivity('INFO', `Comparing manifest with baseline ${baselineFile}.`);
      try {
        const data = await postJson('/api/drift', { baseline_file: baselineFile, manifest_yaml: manifestYaml });
        renderDriftResults(data);
        logActivity(data.drift_count > 0 ? 'WARN' : 'SUCCESS', `Drift check completed: ${data.drift_count ?? 0} change(s), decision ${data.decision || 'n/a'}.`);
      } catch (error) {
        logActivity('ALERT', `Drift check failed: ${error.message}`);
        alert(`Drift Error: ${error.message}`);
      } finally {
        btnRunDriftCheck.disabled = false;
        btnRunDriftCheck.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Compare &amp; Detect Drift';
      }
    });
  }

  function renderDriftResults(data) {
    driftDecisionBanner.className = 'decision-banner';
    const events = Array.isArray(data.drift_events) ? data.drift_events : [];
    if ((data.drift_count || 0) > 0) {
      driftDecisionBanner.classList.add(data.decision === 'BLOCK' ? 'banner-block' : 'banner-warn');
      driftDecisionIcon.textContent = '!';
      driftDecisionHeading.textContent = `SECURITY DRIFT DETECTED (${data.drift_count} changes)`;
      driftDecisionSummary.textContent = `Live posture differs from the approved baseline. Drift risk: ${data.risk?.drift_risk ?? 'n/a'} pts.`;
    } else {
      driftDecisionBanner.classList.add('banner-pass');
      driftDecisionIcon.textContent = '✓';
      driftDecisionHeading.textContent = 'ZERO DRIFT — NO CHANGES DETECTED';
      driftDecisionSummary.textContent = 'The inspected manifest matches the stored baseline for the fields checked.';
    }
    if (!events.length) {
      driftEventsContainer.innerHTML = '<div class="empty-state"><p>No security posture drift detected.</p></div>';
      return;
    }
    driftEventsContainer.innerHTML = events.map((event) => {
      const severity = String(event.severity || 'UNKNOWN').toUpperCase();
      const badgeClass = ['CRITICAL', 'HIGH'].includes(severity) ? 'badge-block' : 'badge-warn';
      return `<div class="drift-card">
        <div class="drift-header"><span class="drift-field">${escapeHtml(event.field)}</span><span class="badge ${badgeClass}">${escapeHtml(severity)}</span></div>
        <div class="finding-message">${escapeHtml(event.message)}</div>
        <div class="drift-diff-row"><div class="diff-approved">Approved: <code>${escapeHtml(JSON.stringify(event.approved))}</code></div><div class="diff-current">Current: <code>${escapeHtml(JSON.stringify(event.current))}</code></div></div>
      </div>`;
    }).join('');
  }

  // Initial API-backed state: no fabricated threat counts or uptime values.
  updateDashboardMetrics();
  checkApiHealth();
  loadSamples();
  loadBaselinesList();
});
