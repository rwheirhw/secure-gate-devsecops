/**
 * SecureGate Web Dashboard - Client Application Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  // Elements - Navigation
  const navTabs = document.querySelectorAll('.nav-tab');
  const tabViews = document.querySelectorAll('.tab-view');

  // Elements - Workbench
  const manifestEditor = document.getElementById('manifestEditor');
  const selectReportFile = document.getElementById('selectReportFile');
  const selectPolicyFile = document.getElementById('selectPolicyFile');
  const btnRunAssessment = document.getElementById('btnRunAssessment');
  const btnSaveBaseline = document.getElementById('btnSaveBaseline');
  const resultTimestamp = document.getElementById('resultTimestamp');

  // Elements - Presets
  const btnPresetEnterprise = document.getElementById('btnPresetEnterprise');
  const btnPresetWeakened = document.getElementById('btnPresetWeakened');
  const btnPresetInsecure = document.getElementById('btnPresetInsecure');

  // Elements - Decision & Metrics
  const decisionBanner = document.getElementById('decisionBanner');
  const decisionIcon = document.getElementById('decisionIcon');
  const decisionHeading = document.getElementById('decisionHeading');
  const decisionSummary = document.getElementById('decisionSummary');
  const valArtifactRisk = document.getElementById('valArtifactRisk');
  const valDeploymentRisk = document.getElementById('valDeploymentRisk');
  const valDriftRisk = document.getElementById('valDriftRisk');
  const valTotalRisk = document.getElementById('valTotalRisk');
  const valRiskLevel = document.getElementById('valRiskLevel');

  // Elements - Findings
  const countBlocking = document.getElementById('countBlocking');
  const countWarnings = document.getElementById('countWarnings');
  const countIgnored = document.getElementById('countIgnored');
  const findingsList = document.getElementById('findingsList');
  const findingTabs = document.querySelectorAll('.findings-tab');

  // Elements - CI/CD Reports
  const btnRefreshReports = document.getElementById('btnRefreshReports');
  const reportFileList = document.getElementById('reportFileList');
  const activeReportName = document.getElementById('activeReportName');
  const activeReportMeta = document.getElementById('activeReportMeta');
  const reportContentArea = document.getElementById('reportContentArea');

  // Elements - Drift
  const selectBaselineFile = document.getElementById('selectBaselineFile');
  const driftManifestEditor = document.getElementById('driftManifestEditor');
  const btnRunDriftCheck = document.getElementById('btnRunDriftCheck');
  const driftDecisionBanner = document.getElementById('driftDecisionBanner');
  const driftDecisionIcon = document.getElementById('driftDecisionIcon');
  const driftDecisionHeading = document.getElementById('driftDecisionHeading');
  const driftDecisionSummary = document.getElementById('driftDecisionSummary');
  const driftEventsContainer = document.getElementById('driftEventsContainer');

  // State
  let currentAssessmentResult = null;
  let activeFindingsFilter = 'blocking';
  let sampleManifests = {};

  // -------------------------------------------------------------------------
  // 1. Navigation Tab Switching
  // -------------------------------------------------------------------------
  navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      navTabs.forEach(t => t.classList.remove('active'));
      tabViews.forEach(v => v.classList.remove('active'));

      tab.classList.add('active');
      const targetId = tab.getAttribute('data-target');
      const targetView = document.getElementById(targetId);
      if (targetView) targetView.classList.add('active');

      if (targetId === 'viewPipeline') loadPipelineReports();
      if (targetId === 'viewDrift') loadBaselinesList();
    });
  });

  // -------------------------------------------------------------------------
  // 2. Load Preset Samples from API
  // -------------------------------------------------------------------------
  async function loadSamples() {
    try {
      const res = await fetch('/api/samples');
      if (res.ok) {
        sampleManifests = await res.json();
        // Default to Enterprise Hardened
        setPreset('enterprise');
      }
    } catch (err) {
      console.error('Failed to load sample manifests:', err);
    }
  }

  function setPreset(type) {
    document.querySelectorAll('.pill-btn').forEach(b => b.classList.remove('active'));

    if (type === 'enterprise') {
      btnPresetEnterprise.classList.add('active');
      manifestEditor.value = sampleManifests.enterprise_sample || '';
    } else if (type === 'weakened') {
      btnPresetWeakened.classList.add('active');
      // Produce a weakened version with privileged: true and root user
      let weakened = sampleManifests.enterprise_sample || '';
      weakened = weakened.replace('privileged: false', 'privileged: true');
      weakened = weakened.replace('runAsUser: 10001', 'runAsUser: 0');
      manifestEditor.value = weakened;
    } else if (type === 'insecure') {
      btnPresetInsecure.classList.add('active');
      manifestEditor.value = sampleManifests.insecure_sample || '';
    }
  }

  btnPresetEnterprise.addEventListener('click', () => setPreset('enterprise'));
  btnPresetWeakened.addEventListener('click', () => setPreset('weakened'));
  btnPresetInsecure.addEventListener('click', () => setPreset('insecure'));

  // -------------------------------------------------------------------------
  // 3. Run Security Assessment
  // -------------------------------------------------------------------------
  btnRunAssessment.addEventListener('click', async () => {
    const yamlContent = manifestEditor.value;
    if (!yamlContent.trim()) {
      alert('Please enter or select a Kubernetes YAML manifest.');
      return;
    }

    btnRunAssessment.disabled = true;
    btnRunAssessment.innerText = 'Evaluating...';

    const payload = {
      manifest_yaml: yamlContent,
      report_file: selectReportFile.value === 'none' ? '' : selectReportFile.value,
      policy_file: selectPolicyFile.value,
    };

    try {
      const res = await fetch('/api/assess', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Assessment request failed');
      }

      currentAssessmentResult = data;
      renderAssessmentResults(data);

    } catch (err) {
      alert(`Assessment Error: ${err.message}`);
    } finally {
      btnRunAssessment.disabled = false;
      btnRunAssessment.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="5 3 19 12 5 21 5 3"/>
        </svg>
        Run Security Assessment`;
    }
  });

  // -------------------------------------------------------------------------
  // 4. Render Assessment Results
  // -------------------------------------------------------------------------
  function renderAssessmentResults(data) {
    resultTimestamp.innerText = `Evaluated at ${new Date(data.timestamp).toLocaleTimeString()}`;

    // Update Decision Banner
    decisionBanner.className = 'decision-banner';
    if (data.decision === 'BLOCK') {
      decisionBanner.classList.add('banner-block');
      decisionIcon.innerText = '⛔';
      decisionHeading.innerText = 'DEPLOYMENT BLOCKED';
      decisionSummary.innerText = `${data.summary.blocking} mandatory security policy violation(s) detected. Pipeline must halt.`;
      btnSaveBaseline.disabled = true;
    } else if (data.decision === 'WARN') {
      decisionBanner.classList.add('banner-warn');
      decisionIcon.innerText = '⚠️';
      decisionHeading.innerText = 'PASSED WITH WARNINGS';
      decisionSummary.innerText = `No blocking violations. ${data.summary.warnings} advisory warning(s) should be reviewed.`;
      btnSaveBaseline.disabled = false;
    } else {
      decisionBanner.classList.add('banner-pass');
      decisionIcon.innerText = '✅';
      decisionHeading.innerText = 'DEPLOYMENT APPROVED';
      decisionSummary.innerText = 'All deployment security controls and artifact policies fully satisfied.';
      btnSaveBaseline.disabled = false;
    }

    // Advisory Posture Metrics
    if (data.risk) {
      valArtifactRisk.innerText = `${data.risk.artifact_risk} pts`;
      valDeploymentRisk.innerText = `${data.risk.deployment_risk} pts`;
      valDriftRisk.innerText = `${data.risk.drift_risk || 0} pts`;
      valTotalRisk.innerText = `${data.risk.total_risk}/100`;
      valRiskLevel.innerText = `Level: ${data.risk.level}`;
    }

    // Counts
    countBlocking.innerText = data.summary.blocking;
    countWarnings.innerText = data.summary.warnings;
    countIgnored.innerText = data.summary.ignored;

    // Default to blocking if violations exist, else warnings
    activeFindingsFilter = data.summary.blocking > 0 ? 'blocking' : (data.summary.warnings > 0 ? 'warnings' : 'ignored');
    updateFindingsTabUI();
    renderFindingsList();
  }

  // Findings Tabs
  findingTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      activeFindingsFilter = tab.getAttribute('data-type');
      updateFindingsTabUI();
      renderFindingsList();
    });
  });

  function updateFindingsTabUI() {
    findingTabs.forEach(t => {
      t.classList.toggle('active', t.getAttribute('data-type') === activeFindingsFilter);
    });
  }

  function renderFindingsList() {
    if (!currentAssessmentResult) return;

    let items = [];
    if (activeFindingsFilter === 'blocking') {
      items = currentAssessmentResult.blocking_findings || [];
    } else if (activeFindingsFilter === 'warnings') {
      items = currentAssessmentResult.warning_findings || [];
    } else {
      items = currentAssessmentResult.ignored_findings || [];
    }

    if (items.length === 0) {
      findingsList.innerHTML = `
        <div class="empty-state">
          <p>No ${activeFindingsFilter} findings present in this assessment.</p>
        </div>`;
      return;
    }

    findingsList.innerHTML = items.map(f => {
      const badgeClass = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'badge-block' : 'badge-warn';
      const categoryTag = f.category ? `<span class="badge badge-warn">${f.category}</span>` : '';
      const fixedInfo = f.fixed_version ? `<span style="color:#86efac; font-size:0.72rem;">Fix available: ${f.fixed_version}</span>` : '';

      return `
        <div class="finding-item">
          <div class="finding-top-row">
            <span class="finding-id">${f.id}</span>
            <div>
              ${categoryTag}
              <span class="badge ${badgeClass}">${f.severity}</span>
            </div>
          </div>
          <div class="finding-message">${f.message || 'Security control violation'}</div>
          <div class="finding-resource">Resource: ${f.resource || 'N/A'} ${fixedInfo ? '• ' + fixedInfo : ''}</div>
        </div>`;
    }).join('');
  }

  // -------------------------------------------------------------------------
  // 5. Save Baseline
  // -------------------------------------------------------------------------
  btnSaveBaseline.addEventListener('click', async () => {
    const yamlContent = manifestEditor.value;
    const name = prompt('Enter a filename for this approved security baseline:', 'production-baseline.json');
    if (!name) return;

    try {
      const res = await fetch('/api/baseline/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ manifest_yaml: yamlContent, name: name }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to save baseline');

      alert(`Approved security baseline saved successfully: ${data.filename}`);
      loadBaselinesList();
    } catch (err) {
      alert(`Baseline Error: ${err.message}`);
    }
  });

  // -------------------------------------------------------------------------
  // 6. CI/CD Audit Reports (Jenkins inspection)
  // -------------------------------------------------------------------------
  async function loadPipelineReports() {
    reportFileList.innerHTML = '<div class="loading-state">Loading reports...</div>';
    try {
      const res = await fetch('/api/reports');
      const data = await res.json();

      if (!data.reports || data.reports.length === 0) {
        reportFileList.innerHTML = '<div class="empty-state"><p>No CI/CD reports found in reports/ directory.</p></div>';
        return;
      }

      reportFileList.innerHTML = data.reports.map((r, idx) => `
        <div class="report-file-item ${idx === 0 ? 'active' : ''}" data-file="${r.filename}">
          <span class="report-file-name">${r.filename}</span>
          <span class="report-file-size">${(r.size_bytes / 1024).toFixed(1)} KB • ${new Date(r.modified_at * 1000).toLocaleString()}</span>
        </div>
      `).join('');

      document.querySelectorAll('.report-file-item').forEach(item => {
        item.addEventListener('click', () => {
          document.querySelectorAll('.report-file-item').forEach(i => i.classList.remove('active'));
          item.classList.add('active');
          inspectReport(item.getAttribute('data-file'));
        });
      });

      if (data.reports.length > 0) {
        inspectReport(data.reports[0].filename);
      }
    } catch (err) {
      reportFileList.innerHTML = `<div class="empty-state"><p>Error loading reports: ${err.message}</p></div>`;
    }
  }

  async function inspectReport(filename) {
    activeReportName.innerText = filename;
    reportContentArea.innerText = 'Loading payload...';
    try {
      const res = await fetch(`/api/reports/${encodeURIComponent(filename)}`);
      const json = await res.json();
      reportContentArea.innerText = JSON.stringify(json, null, 2);
      activeReportMeta.innerText = json.decision ? `Decision: ${json.decision}` : '';
    } catch (err) {
      reportContentArea.innerText = `Failed to load report: ${err.message}`;
    }
  }

  btnRefreshReports.addEventListener('click', loadPipelineReports);

  // -------------------------------------------------------------------------
  // 7. Drift & Baseline Inspector
  // -------------------------------------------------------------------------
  async function loadBaselinesList() {
    try {
      const res = await fetch('/api/baselines');
      const data = await res.json();

      if (!data.baselines || data.baselines.length === 0) {
        selectBaselineFile.innerHTML = '<option value="">(No baselines found in baselines/)</option>';
        return;
      }

      selectBaselineFile.innerHTML = data.baselines.map(b => `
        <option value="${b.filename}">${b.filename} (${(b.size_bytes / 1024).toFixed(1)} KB)</option>
      `).join('');

      if (!driftManifestEditor.value.trim() && sampleManifests.enterprise_sample) {
        // Set sample in drift editor with an intentional drift toggle (e.g. privileged: true)
        driftManifestEditor.value = sampleManifests.enterprise_sample.replace('privileged: false', 'privileged: true');
      }
    } catch (err) {
      console.error('Failed to load baselines:', err);
    }
  }

  btnRunDriftCheck.addEventListener('click', async () => {
    const baselineFile = selectBaselineFile.value;
    const manifestYaml = driftManifestEditor.value;

    if (!baselineFile) {
      alert('Please select an approved baseline first. (You can save one from the Workbench tab).');
      return;
    }
    if (!manifestYaml.trim()) {
      alert('Please enter a manifest to compare for configuration drift.');
      return;
    }

    btnRunDriftCheck.disabled = true;
    btnRunDriftCheck.innerText = 'Analyzing Drift...';

    try {
      const res = await fetch('/api/drift', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baseline_file: baselineFile, manifest_yaml: manifestYaml }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Drift check failed');

      renderDriftResults(data);
    } catch (err) {
      alert(`Drift Error: ${err.message}`);
    } finally {
      btnRunDriftCheck.disabled = false;
      btnRunDriftCheck.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="23 4 23 10 17 10"/>
          <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
        </svg>
        Compare & Detect Drift`;
    }
  });

  function renderDriftResults(data) {
    driftDecisionBanner.className = 'decision-banner';

    if (data.drift_count > 0) {
      driftDecisionBanner.classList.add(data.decision === 'BLOCK' ? 'banner-block' : 'banner-warn');
      driftDecisionIcon.innerText = '🚨';
      driftDecisionHeading.innerText = `SECURITY DRIFT DETECTED (${data.drift_count} changes)`;
      driftDecisionSummary.innerText = `Live posture deviates from approved baseline. Recalculated Drift Risk: ${data.risk.drift_risk} pts.`;
    } else {
      driftDecisionBanner.classList.add('banner-pass');
      driftDecisionIcon.innerText = '✅';
      driftDecisionHeading.innerText = 'ZERO DRIFT - FULLY COMPLIANT';
      driftDecisionSummary.innerText = 'Live deployment matches the approved security posture exactly.';
    }

    if (data.drift_events.length === 0) {
      driftEventsContainer.innerHTML = '<div class="empty-state"><p>No security posture drift detected. Everything matches the approved baseline.</p></div>';
      return;
    }

    driftEventsContainer.innerHTML = data.drift_events.map(ev => `
      <div class="drift-card">
        <div class="drift-header">
          <span class="drift-field">${ev.field}</span>
          <span class="badge ${ev.severity === 'CRITICAL' || ev.severity === 'HIGH' ? 'badge-block' : 'badge-warn'}">${ev.severity}</span>
        </div>
        <div class="finding-message">${ev.message}</div>
        <div class="drift-diff-row">
          <div class="diff-approved">Approved: <code>${JSON.stringify(ev.approved)}</code></div>
          <div class="diff-current">Current: <code>${JSON.stringify(ev.current)}</code></div>
        </div>
      </div>
    `).join('');
  }

  // Initial Load
  loadSamples();
});
