/* ============================================================
   SecretScanner Web UI — Application Logic
   ============================================================ */

// ─── State ───────────────────────────────────────────────────
const State = {
  currentScanId: null,
  findings: [],
  filteredFindings: [],
  charts: {},
  mode: 'path',   // 'path' | 'upload'
  uploadedFile: null,
};

// ─── DOM helpers ─────────────────────────────────────────────
const $ = id => document.getElementById(id);
const qs = sel => document.querySelector(sel);
const qsa = sel => [...document.querySelectorAll(sel)];

// ─── Toast ───────────────────────────────────────────────────
function toast(msg, type = 'info', duration = 4000) {
  const c = $('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), duration);
}

// ─── Tab switching ───────────────────────────────────────────
function initTabs() {
  qsa('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      qsa('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      qsa('.panel').forEach(p => p.classList.remove('active'));
      const panel = $(`panel-${target}`);
      if (panel) panel.classList.add('active');
    });
  });
}

function switchToPanel(name) {
  qsa('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  qsa('.panel').forEach(p => p.classList.remove('active'));
  const panel = $(`panel-${name}`);
  if (panel) panel.classList.add('active');
}

// ─── Mode toggle (Path / Upload) ─────────────────────────────
function initModeToggle() {
  qsa('[data-mode]').forEach(btn => {
    btn.addEventListener('click', () => {
      State.mode = btn.dataset.mode;
      qsa('[data-mode]').forEach(b => b.classList.toggle('active', b.dataset.mode === State.mode));
      $('path-section').style.display  = State.mode === 'path'   ? 'block' : 'none';
      $('upload-section').style.display = State.mode === 'upload' ? 'block' : 'none';
    });
  });
}

// ─── Drop zone ───────────────────────────────────────────────
function initDropZone() {
  const dz = $('drop-zone');
  const input = $('file-input');

  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', e => {
    e.preventDefault(); dz.classList.remove('drag-over');
    handleFile(e.dataTransfer.files[0]);
  });
  input.addEventListener('change', () => handleFile(input.files[0]));
}

function handleFile(file) {
  if (!file) return;
  if (!file.name.endsWith('.zip')) { toast('Please upload a .zip file', 'error'); return; }
  State.uploadedFile = file;
  $('drop-filename').textContent = `📦 ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
}

// ─── Start Scan ──────────────────────────────────────────────
async function startScan() {
  const btn = $('scan-btn');
  btn.disabled = true;

  // Clear previous results
  State.currentScanId = null;
  State.findings = [];
  clearTerminal();

  try {
    let scanId;

    if (State.mode === 'path') {
      const path = $('scan-path').value.trim();
      if (!path) { toast('Please enter a directory path', 'error'); btn.disabled = false; return; }

      const body = {
        path,
        scan_history:  $('toggle-history').checked,
        history_only:  $('toggle-history-only').checked,
        max_commits:   $('max-commits').value ? parseInt($('max-commits').value) : null,
        min_severity:  $('min-severity').value,
        min_confidence: $('min-confidence').value,
      };

      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      scanId = data.scan_id;

    } else {
      if (!State.uploadedFile) { toast('Please select a ZIP file first', 'error'); btn.disabled = false; return; }
      const fd = new FormData();
      fd.append('file', State.uploadedFile);
      fd.append('scan_history', $('toggle-history').checked);
      fd.append('min_severity',  $('min-severity').value);
      fd.append('min_confidence', $('min-confidence').value);

      const res = await fetch('/api/scan/upload', { method: 'POST', body: fd });
      const data = await res.json();
      scanId = data.scan_id;
    }

    State.currentScanId = scanId;
    switchToPanel('progress');
    listenToScan(scanId);

  } catch (err) {
    toast(`Failed to start scan: ${err.message}`, 'error');
    btn.disabled = false;
  }
}

// ─── SSE Progress listener ───────────────────────────────────
function listenToScan(scanId) {
  const bar = $('progress-fill');
  const progressSteps = ['queued', 'scanning tree', 'scanning history', 'filtering', 'done'];
  let stepIdx = 0;

  appendTerminalLine('🚀 Scan started…', 'info');

  const source = new EventSource(`/api/scan/${scanId}/stream`);

  source.onmessage = (e) => {
    const data = JSON.parse(e.data);

    if (data.message) {
      const cls = data.message.includes('✅') ? 'done'
                : data.message.includes('❌') ? 'error'
                : data.message.includes('📜') ? 'warn'
                : 'info';
      appendTerminalLine(data.message, cls);

      // Animate progress bar roughly
      stepIdx = Math.min(stepIdx + 1, 7);
      bar.style.width = `${Math.min(stepIdx * 13, 88)}%`;
    }

    if (data.status === 'done') {
      source.close();
      bar.style.width = '100%';
      appendTerminalLine('', '');
      setTimeout(() => loadResults(scanId), 600);
    }

    if (data.status === 'error') {
      source.close();
      appendTerminalLine(`❌ ${data.error}`, 'error');
      toast('Scan failed. See terminal for details.', 'error');
      $('scan-btn').disabled = false;
    }
  };

  source.onerror = () => {
    source.close();
    appendTerminalLine('⚠ Connection to server lost.', 'warn');
    toast('Lost connection to scan stream.', 'error');
  };
}

// ─── Load Results ────────────────────────────────────────────
async function loadResults(scanId) {
  try {
    const res = await fetch(`/api/scan/${scanId}/results`);
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();

    State.findings = data.findings;
    State.filteredFindings = [...data.findings];

    renderSummaryCards(data);
    renderCharts(data);
    renderDangerLocations();
    renderTable();

    switchToPanel('results');
    toast(`Scan complete — ${data.total} findings`, data.total > 0 ? 'error' : 'success');
    $('scan-btn').disabled = false;
  } catch (err) {
    toast(`Could not load results: ${err.message}`, 'error');
    $('scan-btn').disabled = false;
  }
}

// ─── Terminal helpers ─────────────────────────────────────────
function clearTerminal() {
  $('terminal-output').innerHTML = '';
  $('progress-fill').style.width = '0%';
}

function appendTerminalLine(text, cls) {
  const el = document.createElement('div');
  el.className = `terminal-line${cls ? ' ' + cls : ''}`;
  el.textContent = text || '\u00A0';
  const out = $('terminal-output');
  out.appendChild(el);
  out.scrollTop = out.scrollHeight;
}

// ─── Summary Cards ───────────────────────────────────────────
function renderSummaryCards(data) {
  $('stat-total').textContent    = data.total;
  $('stat-critical').textContent = data.severity_counts.critical || 0;
  $('stat-high').textContent     = data.severity_counts.high     || 0;
  $('stat-medium').textContent   = data.severity_counts.medium   || 0;
  $('stat-low').textContent      = data.severity_counts.low      || 0;
  $('stat-confirmed').textContent= data.confidence_counts.confirmed || 0;
}

// ─── Charts ──────────────────────────────────────────────────
function renderCharts(data) {
  // Destroy old charts
  Object.values(State.charts).forEach(c => c.destroy());
  State.charts = {};

  const chartDefaults = {
    plugins: { legend: { labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } } } },
  };

  // Severity Doughnut
  const ctx1 = $('chart-severity').getContext('2d');
  State.charts.severity = new Chart(ctx1, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [
          data.severity_counts.critical || 0,
          data.severity_counts.high     || 0,
          data.severity_counts.medium   || 0,
          data.severity_counts.low      || 0,
        ],
        backgroundColor: ['rgba(248,113,113,0.8)', 'rgba(251,146,60,0.8)', 'rgba(251,191,36,0.8)', 'rgba(96,165,250,0.8)'],
        borderColor: ['#f87171', '#fb923c', '#fbbf24', '#60a5fa'],
        borderWidth: 2,
      }],
    },
    options: {
      ...chartDefaults,
      cutout: '68%',
      plugins: {
        ...chartDefaults.plugins,
        legend: { ...chartDefaults.plugins.legend, position: 'bottom' },
      },
    },
  });

  // Detector Bar Chart (top 8)
  const detEntries = Object.entries(data.detector_counts)
    .sort((a, b) => b[1] - a[1]).slice(0, 8);
  const ctx2 = $('chart-detectors').getContext('2d');
  State.charts.detectors = new Chart(ctx2, {
    type: 'bar',
    data: {
      labels: detEntries.map(([k]) => k.replace(/-/g, ' ')),
      datasets: [{
        label: 'Findings',
        data: detEntries.map(([, v]) => v),
        backgroundColor: 'rgba(168,85,247,0.5)',
        borderColor: '#a855f7',
        borderWidth: 1.5,
        borderRadius: 5,
      }],
    },
    options: {
      ...chartDefaults,
      indexAxis: 'y',
      scales: {
        x: { ticks: { color: '#475569' }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { ticks: { color: '#94a3b8', font: { size: 11 } }, grid: { display: false } },
      },
    },
  });

  // Confidence Doughnut
  const ctx3 = $('chart-confidence').getContext('2d');
  State.charts.confidence = new Chart(ctx3, {
    type: 'doughnut',
    data: {
      labels: ['Confirmed', 'Likely', 'Possible'],
      datasets: [{
        data: [
          data.confidence_counts.confirmed || 0,
          data.confidence_counts.likely    || 0,
          data.confidence_counts.possible  || 0,
        ],
        backgroundColor: ['rgba(74,222,128,0.7)', 'rgba(34,211,238,0.7)', 'rgba(168,85,247,0.7)'],
        borderColor: ['#4ade80', '#22d3ee', '#a855f7'],
        borderWidth: 2,
      }],
    },
    options: {
      ...chartDefaults,
      cutout: '68%',
      plugins: { ...chartDefaults.plugins, legend: { ...chartDefaults.plugins.legend, position: 'bottom' } },
    },
  });
}

// ─── High-Risk Locations ────────────────────────────────────
function renderDangerLocations() {
  const container = $('danger-locations');
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
  const confidenceRank = { confirmed: 0, likely: 1, possible: 2 };

  const dangerous = State.findings
    .filter(f => ['critical', 'high'].includes((f.severity || '').toLowerCase()) && ['confirmed', 'likely'].includes((f.confidence || '').toLowerCase()))
    .sort((a, b) => {
      const sevDiff = severityRank[(a.severity || '').toLowerCase()] - severityRank[(b.severity || '').toLowerCase()];
      if (sevDiff !== 0) return sevDiff;
      return confidenceRank[(a.confidence || '').toLowerCase()] - confidenceRank[(b.confidence || '').toLowerCase()];
    })
    .slice(0, 8);

  if (!dangerous.length) {
    container.innerHTML = '<div class="danger-empty">No critical or high-risk locations detected.</div>';
    return;
  }

  container.innerHTML = dangerous.map(f => `
    <div class="danger-item">
      <div>
        <div class="danger-location">${escHtml(relPath(f.file_path))}<span class="danger-line">:${f.line_number}</span></div>
        <div class="danger-detector">${escHtml(f.detector_name)}</div>
      </div>
      <span class="badge badge-${(f.severity || 'low').toLowerCase()}">${(f.severity || 'low').toUpperCase()}</span>
    </div>
  `).join('');
}

// ─── Findings Table ──────────────────────────────────────────
function renderTable() {
  const tbody = $('findings-tbody');
  tbody.innerHTML = '';

  if (!State.filteredFindings.length) {
    $('empty-state').style.display = 'block';
    $('findings-table-wrap').style.display = 'none';
    return;
  }
  $('empty-state').style.display = 'none';
  $('findings-table-wrap').style.display = 'block';

  State.filteredFindings.forEach((f, idx) => {
    const commit = f.commit_hash ? `<span class="badge badge-entropy">${f.commit_hash.slice(0,8)}</span>` : '';
    const row = document.createElement('tr');
    row.innerHTML = `
      <td><span class="badge badge-${f.severity}">${f.severity.toUpperCase()}</span></td>
      <td><span class="badge badge-${f.confidence}">${f.confidence}</span></td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(f.detector_name)}">${escHtml(f.detector_name)}</td>
      <td class="file-path">${escHtml(relPath(f.file_path))}<span class="line-num">:${f.line_number}</span></td>
      <td><code class="mono-val">${escHtml(f.redacted_value)}</code></td>
      <td>${commit}</td>
      <td>▶</td>
    `;
    row.addEventListener('click', () => toggleExpand(row, f, idx));
    tbody.appendChild(row);
  });
}

function toggleExpand(row, f, idx) {
  const existing = row.nextSibling;
  if (existing && existing.classList && existing.classList.contains('expand-row')) {
    existing.remove();
    row.classList.remove('expanded');
    row.lastElementChild.textContent = '▶';
    return;
  }
  qsa('.expand-row').forEach(r => r.remove());
  qsa('.findings-table tr.expanded').forEach(r => {
    r.classList.remove('expanded');
    r.lastElementChild.textContent = '▶';
  });
  row.classList.add('expanded');
  row.lastElementChild.textContent = '▼';

  const expand = document.createElement('tr');
  expand.className = 'expand-row';
  const td = document.createElement('td');
  td.colSpan = 7;
  td.innerHTML = `
    <div class="expand-content">
      <div class="expand-grid">
        <div class="expand-field">
          <label>File Path</label>
          <p>${escHtml(f.file_path)}</p>
        </div>
        <div class="expand-field">
          <label>Redacted Value</label>
          <p>${escHtml(f.redacted_value)}</p>
        </div>
        <div class="expand-field">
          <label>Line Preview</label>
          <p>${escHtml(f.line_content)}</p>
        </div>
        ${f.commit_hash ? `<div class="expand-field"><label>Commit</label><p>${escHtml(f.commit_hash)}</p></div>` : ''}
      </div>
      <div class="mt-3">
        <label>Detection Reasons</label>
        <ul class="reasons-list mt-1">
          ${f.reasons.map(r => `<li>${escHtml(r)}</li>`).join('')}
        </ul>
      </div>
    </div>`;
  expand.appendChild(td);
  row.after(expand);
}

// ─── Filtering / Search ───────────────────────────────────────
function applyFilters() {
  const search = ($('search-box').value || '').toLowerCase();
  const sev    = $('filter-severity').value;
  const conf   = $('filter-confidence').value;

  State.filteredFindings = State.findings.filter(f => {
    if (sev  && f.severity   !== sev)  return false;
    if (conf && f.confidence !== conf)  return false;
    if (search) {
      const hay = `${f.detector_name} ${f.file_path} ${f.redacted_value} ${f.line_content}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });
  renderTable();
  $('filter-count').textContent = `${State.filteredFindings.length} / ${State.findings.length}`;
}

// ─── Export ───────────────────────────────────────────────────
async function exportResults(fmt) {
  if (!State.currentScanId) { toast('No active scan to export.', 'error'); return; }
  const url = `/api/scan/${State.currentScanId}/export/${fmt}`;
  const a = document.createElement('a');
  a.href = url; a.download = ''; a.click();
  toast(`Downloading ${fmt.toUpperCase()} report…`, 'success');
}

// ─── Baseline ─────────────────────────────────────────────────
async function saveBaseline() {
  if (!State.currentScanId) { toast('No active scan.', 'error'); return; }
  try {
    const res = await fetch(`/api/scan/${State.currentScanId}/baseline`, { method: 'POST' });
    const data = await res.json();
    toast(`✅ Baseline saved — ${data.count} findings hashed`, 'success');
  } catch (err) {
    toast('Failed to save baseline.', 'error');
  }
}

// ─── Utils ───────────────────────────────────────────────────
function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function relPath(full) {
  // Show just the last 2-3 path segments
  const parts = full.replace(/\\/g, '/').split('/');
  return parts.slice(-3).join('/');
}

// ─── Sample path filler ───────────────────────────────────────
function useSampleRepo() {
  $('scan-path').value = 'E:/ss/sample_target_repo';
  toast('Sample local repo path loaded!', 'info');
}

function useGithubSample() {
  $('scan-path').value = 'https://github.com/varunraj-2005/SMARTCITY-COMPLAINT-SYSTEM';
  toast('GitHub URL loaded — click Start Scan to clone and scan it!', 'info');
}

// ─── Init ────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initModeToggle();
  initDropZone();

  $('scan-btn').addEventListener('click', startScan);
  $('search-box').addEventListener('input', applyFilters);
  $('filter-severity').addEventListener('change', applyFilters);
  $('filter-confidence').addEventListener('change', applyFilters);

  $('btn-export-json').addEventListener('click', () => exportResults('json'));
  $('btn-export-sarif').addEventListener('click', () => exportResults('sarif'));
  $('btn-save-baseline').addEventListener('click', saveBaseline);
  $('btn-new-scan').addEventListener('click', () => { switchToPanel('scan'); $('scan-btn').disabled = false; });

  const sampleBtn = $('btn-sample');
  if (sampleBtn) sampleBtn.addEventListener('click', useSampleRepo);

  const ghBtn = $('btn-github-sample');
  if (ghBtn) ghBtn.addEventListener('click', useGithubSample);

  // Toggle history-only disables history when selected
  $('toggle-history-only').addEventListener('change', function() {
    $('toggle-history').disabled = this.checked;
    if (this.checked) $('toggle-history').checked = false;
  });
});
