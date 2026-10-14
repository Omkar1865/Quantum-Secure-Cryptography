let currentTab = 'dashboard';
let authToken = localStorage.getItem('jwt_token') || null;
let selectedTransferFile = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  checkAuth();
  setupDropzone();
});

// ==========================================
// AUTHENTICATION LOGIC
// ==========================================
async function checkAuth() {
  if (!authToken) {
    showAuthView();
    return;
  }
  try {
    const res = await fetch('/api/auth/me', {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    if (res.ok) {
      const data = await res.json();
      document.getElementById('userNameDisplay').textContent = data.user.username;
      document.getElementById('userRoleDisplay').textContent = data.user.role.toUpperCase();
      document.getElementById('userAvatar').textContent = data.user.username.charAt(0).toUpperCase();
      showAppView();
      loadDashboardData();
    } else {
      logoutClean();
    }
  } catch (err) {
    console.error('Auth verification failed', err);
    showAuthView();
  }
}

function showAuthView() {
  document.getElementById('authView').style.display = 'flex';
  document.getElementById('appView').style.display = 'none';
}

function showAppView() {
  document.getElementById('authView').style.display = 'none';
  document.getElementById('appView').style.display = 'flex';
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;
  const errorDiv = document.getElementById('authError');
  errorDiv.style.display = 'none';

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (res.ok && data.token) {
      authToken = data.token;
      localStorage.setItem('jwt_token', data.token);
      checkAuth();
    } else {
      errorDiv.textContent = data.detail || 'Authentication failed.';
      errorDiv.style.display = 'block';
    }
  } catch (err) {
    errorDiv.textContent = 'Connection error. Check backend server.';
    errorDiv.style.display = 'block';
  }
}

async function handleLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } catch (e) {}
  logoutClean();
}

function logoutClean() {
  authToken = null;
  localStorage.removeItem('jwt_token');
  showAuthView();
}

function getAuthHeaders() {
  return {
    'Authorization': `Bearer ${authToken}`
  };
}

// ==========================================
// NAVIGATION & TABS
// ==========================================
function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll('.tab-pane').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

  const activePane = document.getElementById(`tab-${tabId}`);
  const activeNav = document.getElementById(`nav-${tabId}`);
  if (activePane) activePane.style.display = 'block';
  if (activeNav) activeNav.classList.add('active');

  const titles = {
    dashboard: 'Security Overview Dashboard',
    transfer: 'Quantum-Encrypted File Transfer',
    qkd: 'BB84 Quantum Key Distribution Lab',
    keys: 'Adaptive Key Manager & Policies',
    analytics: 'Security Analytics & Benchmarks',
    docs: 'System Architecture & Documentation'
  };
  document.getElementById('pageTitle').textContent = titles[tabId] || 'Dashboard';

  refreshCurrentTab();
}

function refreshCurrentTab() {
  if (currentTab === 'dashboard') loadDashboardData();
  else if (currentTab === 'transfer') { loadTransfersList(); loadAvailableKeysDropdown(); }
  else if (currentTab === 'qkd') loadQkdHistory();
  else if (currentTab === 'keys') loadKeysData();
}

// ==========================================
// DASHBOARD VIEW
// ==========================================
async function loadDashboardData() {
  try {
    const res = await fetch('/api/dashboard', { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    const stats = data.stats;

    document.getElementById('dashTotalTransfers').textContent = stats.total_transfers;
    const rate = stats.total_transfers > 0
      ? Math.round((stats.successful_transfers / stats.total_transfers) * 100)
      : 100;
    document.getElementById('dashSuccessRate').textContent = `${rate}%`;
    document.getElementById('dashSuccessCounts').textContent = `${stats.successful_transfers} verified / ${stats.failed_transfers} failed`;
    document.getElementById('dashTotalQkd').textContent = stats.total_qkd_rounds;
    document.getElementById('dashQkdRate').textContent = `${stats.qkd_acceptance_rate_pct}% accepted`;
    document.getElementById('dashActiveKeys').textContent = stats.active_keys;

    // Transfers Table
    const txBody = document.getElementById('dashTransfersTable');
    if (data.recent_transfers && data.recent_transfers.length > 0) {
      txBody.innerHTML = data.recent_transfers.map(t => `
        <tr>
          <td><strong>${escapeHtml(t.filename)}</strong></td>
          <td><span class="badge ${t.status === 'VERIFIED' ? 'badge-success' : 'badge-danger'}">${t.status}</span></td>
          <td><code>${t.key_id}</code></td>
          <td>${t.transfer_duration_ms} ms</td>
        </tr>
      `).join('');
    } else {
      txBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No transfers recorded yet.</td></tr>`;
    }

    // Key Audit Log
    const auditBody = document.getElementById('dashAuditTable');
    if (data.recent_activity && data.recent_activity.length > 0) {
      auditBody.innerHTML = data.recent_activity.slice().reverse().map(e => `
        <tr>
          <td><span class="badge ${e.level === 'WARN' ? 'badge-warning' : 'badge-info'}">${e.action}</span></td>
          <td><code>${e.key_id}</code></td>
          <td style="font-size: 12px; color: var(--text-muted);">${escapeHtml(e.details)}</td>
        </tr>
      `).join('');
    } else {
      auditBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No key events yet.</td></tr>`;
    }
  } catch (err) {
    console.error('Failed to load dashboard', err);
  }
}

// ==========================================
// FILE TRANSFER WORKFLOW
// ==========================================
function setupDropzone() {
  const dropzone = document.getElementById('fileDropzone');
  if (!dropzone) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
    }, false);
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt.files && dt.files.length > 0) {
      selectedTransferFile = dt.files[0];
      updateDropzoneLabel();
    }
  });
}

function handleFileSelected(input) {
  if (input.files && input.files.length > 0) {
    selectedTransferFile = input.files[0];
    updateDropzoneLabel();
  }
}

function updateDropzoneLabel() {
  if (selectedTransferFile) {
    const sizeKb = (selectedTransferFile.size / 1024).toFixed(1);
    document.getElementById('dropzoneText').textContent = `Selected: ${selectedTransferFile.name} (${sizeKb} KB)`;
  } else {
    document.getElementById('dropzoneText').textContent = 'Click or Drag & Drop File Here';
  }
}

function toggleKeySelectMode(mode) {
  document.getElementById('manualKeyGroup').style.display = mode === 'manual' ? 'block' : 'none';
}

async function loadAvailableKeysDropdown() {
  try {
    const res = await fetch('/api/keys', { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    const select = document.getElementById('transferKeyId');
    const usableKeys = data.keys.filter(k => k.is_usable);

    if (usableKeys.length === 0) {
      select.innerHTML = `<option value="">-- No active keys available (BB84 will generate new) --</option>`;
    } else {
      select.innerHTML = usableKeys.map(k => `
        <option value="${k.key_id}">${k.key_id} (Uses: ${k.use_count}/${k.max_uses}, Rem: ${k.remaining_seconds}s)</option>
      `).join('');
    }
  } catch (err) {
    console.error('Error fetching keys dropdown', err);
  }
}

async function handleTransferSubmit(e) {
  e.preventDefault();
  if (!selectedTransferFile) {
    alert('Please select or drop a file first.');
    return;
  }

  const receiver = document.getElementById('receiverName').value.trim();
  const mode = document.getElementById('keySelectMode').value;
  const keyId = mode === 'manual' ? document.getElementById('transferKeyId').value : '';

  const btn = document.getElementById('btnTransferSubmit');
  btn.disabled = true;
  btn.textContent = 'Encrypting & Transferring...';

  const progressArea = document.getElementById('transferProgressArea');
  const emptyPrompt = document.getElementById('transferEmptyPrompt');
  const statusBox = document.getElementById('transferStepStatus');
  progressArea.style.display = 'block';
  emptyPrompt.style.display = 'none';
  statusBox.className = 'alert alert-info';
  statusBox.textContent = '1. Acquiring/Simulating QKD Key & Encrypting AES-256-GCM...';

  const formData = new FormData();
  formData.append('file', selectedTransferFile);
  formData.append('receiver', receiver);
  formData.append('key_id', keyId);
  formData.append('auto_generate_key', mode === 'auto');

  try {
    const res = await fetch('/api/transfers', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: formData
    });
    const data = await res.json();

    if (res.ok && data.status === 'VERIFIED') {
      statusBox.className = 'alert alert-info';
      statusBox.style.backgroundColor = 'var(--success-light)';
      statusBox.style.color = 'var(--success)';
      statusBox.textContent = '✓ Transfer Complete: Payload Decrypted & SHA-256 Integrity Verified';

      document.getElementById('resTransferId').textContent = data.transfer_id;
      document.getElementById('resKeyId').textContent = data.key_id;
      document.getElementById('resEncTime').textContent = data.encryption_time_ms;
      document.getElementById('resDecTime').textContent = data.decryption_time_ms;
      document.getElementById('resIntegrity').textContent = 'PASSED (Origin and Decrypted hashes match)';

      const downloadArea = document.getElementById('downloadActionArea');
      const downloadBtn = document.getElementById('btnDownloadFile');
      downloadBtn.href = `/api/transfers/${data.transfer_id}/download`;
      downloadArea.style.display = 'block';

      loadTransfersList();
      loadAvailableKeysDropdown();
    } else {
      statusBox.className = 'alert alert-warning';
      statusBox.textContent = `Transfer Failed: ${data.detail || data.error_message || 'Decryption/Verification error'}`;
    }
  } catch (err) {
    statusBox.className = 'alert alert-warning';
    statusBox.textContent = `Network / transfer failure: ${err.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = '🚀 Encrypt, Transfer & Verify';
  }
}

async function loadTransfersList() {
  try {
    const res = await fetch('/api/transfers', { headers: getAuthHeaders() });
    if (!res.ok) return;
    const transfers = await res.json();
    const tbody = document.getElementById('transferHistoryTable');

    if (transfers.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No transfers completed yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = transfers.map(t => `
      <tr>
        <td><code>${t.transfer_id}</code></td>
        <td><strong>${escapeHtml(t.filename)}</strong></td>
        <td>${(t.file_size / 1024).toFixed(1)} KB</td>
        <td><code>${t.key_id}</code></td>
        <td>${escapeHtml(t.sender)} &rarr; ${escapeHtml(t.receiver)}</td>
        <td><small title="${t.content_hash_original}">${t.content_hash_original ? t.content_hash_original.substring(0, 12) + '...' : '-'}</small></td>
        <td><span class="badge ${t.status === 'VERIFIED' ? 'badge-success' : 'badge-danger'}">${t.status}</span></td>
        <td>
          ${t.download_available ? `<a href="/api/transfers/${t.transfer_id}/download" class="btn btn-secondary" style="padding: 3px 8px; font-size: 11px;">Download</a>` : '-'}
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load transfers', err);
  }
}

// ==========================================
// QKD LAB SIMULATION
// ==========================================
async function handleRunQKD(e) {
  e.preventDefault();
  const num_qubits = parseInt(document.getElementById('qkdQubits').value);
  const noise_level = parseFloat(document.getElementById('qkdNoise').value);
  const qber_threshold = parseFloat(document.getElementById('qkdThreshold').value);
  const eve_present = document.getElementById('qkdEve').checked;

  const btn = document.getElementById('btnRunQKD');
  btn.disabled = true;
  btn.textContent = 'Simulating Quantum Circuit...';

  try {
    const res = await fetch('/api/qkd/rounds', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeaders()
      },
      body: JSON.stringify({
        num_qubits,
        noise_level,
        qber_threshold,
        eve_present,
        sample_ratio: 0.33
      })
    });
    const data = await res.json();
    if (res.ok) {
      displayQkdResult(data);
      loadQkdHistory();
    } else {
      alert(data.detail || 'QKD simulation failed');
    }
  } catch (err) {
    alert('Failed to run simulation: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '⚛ Execute BB84 Simulation Round';
  }
}

function displayQkdResult(data) {
  document.getElementById('qkdResultArea').style.display = 'block';
  document.getElementById('qkdEmptyArea').style.display = 'none';

  const badge = document.getElementById('qkdDecisionBadge');
  const accepted = data.decision.accepted;
  badge.className = `alert ${accepted ? 'alert-info' : 'alert-warning'}`;
  badge.innerHTML = `<strong>${accepted ? '✓ ACCEPTED ROUND' : '⚠ REJECTED ROUND'}:</strong> ${data.decision.reasons.join(' ')}`;

  const stats = data.statistics;
  document.getElementById('resQber').textContent = `${stats.measured_qber_pct}% (Threshold: ${(data.parameters.qber_threshold * 100).toFixed(1)}%)`;
  document.getElementById('resSiftedCount').textContent = `${stats.sifted_bits_count} bits (${stats.sifted_yield_pct}% yield)`;
  document.getElementById('resSampleTested').textContent = `${stats.sample_bits_tested} bits`;
  document.getElementById('resSampleErrors').textContent = `${stats.sample_errors_found} errors`;
  document.getElementById('resRetainedBits').textContent = `${stats.retained_secret_bits_count} bits`;
  document.getElementById('resKeyFp').textContent = data.key_fingerprint || 'N/A (Rejected)';

  // Render Bit Matrix comparison
  const matrix = document.getElementById('qkdBitMatrix');
  const maxDisplay = Math.min(24, data.parameters.num_qubits);
  let chips = '';
  for (let i = 0; i < maxDisplay; i++) {
    const aBase = data.alice.bases[i];
    const bBase = data.bob.bases[i];
    const match = (aBase === bBase);
    chips += `
      <div class="bit-chip ${match ? 'match' : 'mismatch'}">
        <span style="font-weight: 700;">${data.alice.bits[i]}</span>
        <span class="basis-tag">${aBase}/${bBase}</span>
      </div>
    `;
  }
  matrix.innerHTML = chips;
}

async function loadQkdHistory() {
  try {
    const res = await fetch('/api/qkd/rounds', { headers: getAuthHeaders() });
    if (!res.ok) return;
    const rounds = await res.json();
    const tbody = document.getElementById('qkdHistoryTable');
    if (rounds.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No rounds run yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = rounds.map(r => `
      <tr>
        <td><code>${r.round_id}</code></td>
        <td>${r.parameters.num_qubits}</td>
        <td>${(r.parameters.noise_level * 100).toFixed(0)}%</td>
        <td>${r.parameters.eve_present ? '<span class="badge badge-warning">Eve Active</span>' : 'None'}</td>
        <td><strong>${r.statistics.measured_qber_pct}%</strong></td>
        <td><span class="badge ${r.decision.accepted ? 'badge-success' : 'badge-danger'}">${r.decision.accepted ? 'ACCEPTED' : 'REJECTED'}</span></td>
        <td style="font-size: 12px; color: var(--text-muted);">${escapeHtml(r.decision.reasons[0] || '')}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load QKD history', err);
  }
}

// ==========================================
// KEY MANAGER VIEW
// ==========================================
async function loadKeysData() {
  try {
    const res = await fetch('/api/keys', { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById('policyTtl').value = data.policy.default_ttl_seconds;
    document.getElementById('policyMaxUses').value = data.policy.default_max_uses;

    const tbody = document.getElementById('keysTableBody');
    if (data.keys.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No keys generated yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.keys.map(k => `
      <tr>
        <td><code>${k.key_id}</code></td>
        <td><small><code>${k.fingerprint}...</code></small></td>
        <td><span class="badge ${k.status === 'ACTIVE' ? 'badge-success' : 'badge-warning'}">${k.status}</span></td>
        <td>${k.use_count} / ${k.max_uses}</td>
        <td>${k.remaining_seconds}s</td>
        <td>${(k.qber_at_generation * 100).toFixed(1)}%</td>
        <td>
          ${k.status === 'ACTIVE' ? `<button class="btn btn-danger" style="padding: 2px 8px; font-size: 11px;" onclick="revokeKey('${k.key_id}')">Revoke</button>` : '-'}
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load keys', err);
  }
}

async function handleUpdatePolicy(e) {
  e.preventDefault();
  const default_ttl_seconds = parseInt(document.getElementById('policyTtl').value);
  const default_max_uses = parseInt(document.getElementById('policyMaxUses').value);

  try {
    const res = await fetch('/api/keys/policy', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeaders()
      },
      body: JSON.stringify({ default_ttl_seconds, default_max_uses })
    });
    if (res.ok) {
      alert('Key lifecycle policy successfully updated.');
      loadKeysData();
    }
  } catch (err) {
    alert('Failed to update policy: ' + err.message);
  }
}

async function revokeKey(keyId) {
  if (!confirm(`Are you sure you want to revoke key ${keyId}?`)) return;
  try {
    const res = await fetch(`/api/keys/${keyId}/revoke`, {
      method: 'POST',
      headers: getAuthHeaders()
    });
    if (res.ok) {
      loadKeysData();
    }
  } catch (err) {
    alert('Failed to revoke key: ' + err.message);
  }
}

// ==========================================
// SECURITY BENCHMARKS & EXPERIMENTS
// ==========================================
async function runNoiseBenchmark() {
  const out = document.getElementById('analyticsOutput');
  const btn = document.getElementById('btnNoiseExp');
  btn.disabled = true;
  out.innerHTML = '<em>Running empirical channel noise multi-trial simulations with Qiskit Aer...</em>';

  try {
    const res = await fetch('/api/experiments/noise', { method: 'POST', headers: getAuthHeaders() });
    const data = await res.json();
    let rows = data.data.map(d => `
      <tr>
        <td><strong>${d.noise_level_pct}</strong></td>
        <td>${d.avg_qber_pct}%</td>
        <td><span class="badge ${d.acceptance_rate_pct > 50 ? 'badge-success' : 'badge-danger'}">${d.acceptance_rate_pct}%</span></td>
        <td>${d.trials}</td>
      </tr>
    `).join('');

    out.innerHTML = `
      <h4 style="font-weight: 700; margin-bottom: 8px;">Channel Noise vs Measured QBER & Acceptance</h4>
      <table class="data-table" style="background: white; border-radius: 4px;">
        <thead>
          <tr>
            <th>Simulated Channel Noise</th>
            <th>Avg Measured QBER</th>
            <th>Round Acceptance Rate</th>
            <th>Repeated Trials</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      <div style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">
        Empirical observation: As channel noise approaches ~11%, QBER exceeds the security limit and the protocol reliably aborts key generation.
      </div>
    `;
  } catch (err) {
    out.textContent = 'Benchmark failed: ' + err.message;
  } finally {
    btn.disabled = false;
  }
}

async function runEavesdroppingBenchmark() {
  const out = document.getElementById('analyticsOutput');
  const btn = document.getElementById('btnEveExp');
  btn.disabled = true;
  out.innerHTML = '<em>Simulating repeated Eve Intercept-Resend attacks...</em>';

  try {
    const res = await fetch('/api/experiments/eavesdropping', { method: 'POST', headers: getAuthHeaders() });
    const data = await res.json();

    out.innerHTML = `
      <h4 style="font-weight: 700; margin-bottom: 8px;">Eavesdropping (Intercept-Resend) Detection Results</h4>
      <div style="line-height: 2.0; background: white; padding: 16px; border-radius: 4px; border: 1px solid var(--border-color);">
        <div><strong>Baseline Channel (No Eve) Average QBER:</strong> ${data.baseline_avg_qber_pct}%</div>
        <div><strong>Attack Channel (Eve Present) Average QBER:</strong> <span style="color: var(--danger); font-weight: 700;">${data.attack_avg_qber_pct}%</span></div>
        <div><strong>Theoretical BB84 Eavesdropping Disturbance:</strong> ~${data.theoretical_attack_qber_pct}%</div>
        <div><strong>Attack Detection Rate:</strong> <span class="badge badge-success" style="font-size: 13px;">${data.attack_detection_rate_pct}%</span></div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 6px;">
          Conclusion: Because Eve cannot measure in conjugate bases without causing quantum collapse, intercept-resend introduces an ~25% disturbance, triggering our QBER cutoff and successfully alerting the nodes.
        </div>
      </div>
    `;
  } catch (err) {
    out.textContent = 'Eavesdropping benchmark failed: ' + err.message;
  } finally {
    btn.disabled = false;
  }
}

async function runCryptoBenchmark() {
  const out = document.getElementById('analyticsOutput');
  const btn = document.getElementById('btnCryptoExp');
  btn.disabled = true;
  out.innerHTML = '<em>Benchmarking AES-256-GCM vs Fernet symmetric encryption throughput...</em>';

  try {
    const res = await fetch('/api/experiments/crypto', { method: 'POST', headers: getAuthHeaders() });
    const data = await res.json();
    let rows = data.benchmarks.map(b => `
      <tr>
        <td><strong>${b.size_kb} KB</strong></td>
        <td>${b.aes_gcm.enc_ms} ms / ${b.aes_gcm.dec_ms} ms</td>
        <td><strong>${b.aes_gcm.throughput_mb_s} MB/s</strong></td>
        <td>${b.fernet.enc_ms} ms / ${b.fernet.dec_ms} ms</td>
        <td>${b.fernet.throughput_mb_s} MB/s</td>
      </tr>
    `).join('');

    out.innerHTML = `
      <h4 style="font-weight: 700; margin-bottom: 8px;">Authenticated Encryption Performance Benchmark</h4>
      <table class="data-table" style="background: white; border-radius: 4px;">
        <thead>
          <tr>
            <th>Payload Size</th>
            <th>AES-256-GCM (Enc/Dec)</th>
            <th>AES-GCM Throughput</th>
            <th>Fernet (Enc/Dec)</th>
            <th>Fernet Throughput</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      <div style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">
        AES-256-GCM provides hardware-accelerated authenticated encryption with a per-file unique nonce and 128-bit integrity tag.
      </div>
    `;
  } catch (err) {
    out.textContent = 'Crypto benchmark failed: ' + err.message;
  } finally {
    btn.disabled = false;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, function(m) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[m];
  });
}
