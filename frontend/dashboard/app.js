'use strict';

const API_BASE = window.location.origin.includes(':8000') ? '/api/v1' : 'http://localhost:8000/api/v1';
const REFRESH_INTERVAL = 30000;
const state = { ledger: null, audit: null, publicKey: null, scopes: null, health: null, busy: false, noticeDismissed: false };

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const shortHash = value => value ? `${value.slice(0, 12)}…${value.slice(-8)}` : '—';
const formatDate = value => {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? escapeHtml(value) : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
};

async function request(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7000);
  try {
    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      signal: controller.signal,
      headers: { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) }
    });
    const type = response.headers.get('content-type') || '';
    const payload = type.includes('application/json') ? await response.json() : null;
    if (!response.ok) {
      const error = new Error(typeof payload?.detail === 'string' ? payload.detail : `Request failed (${response.status})`);
      error.status = response.status;
      throw error;
    }
    return payload;
  } finally {
    clearTimeout(timeout);
  }
}

function latestIdentities(records = []) {
  const latest = new Map();
  records.forEach(record => {
    if (!record.did || record.did === 'did:mesh:genesis') return;
    const previous = latest.get(record.did);
    if (!previous || Number(record.index) > Number(previous.index)) latest.set(record.did, record);
  });
  return [...latest.values()].sort((a, b) => Number(b.index) - Number(a.index));
}

function setConnection(isLive, message = '') {
  const chip = $('#connection-chip');
  chip.classList.toggle('offline', !isLive);
  $('#connection-label').textContent = isLive ? 'API connected' : 'API unavailable';
  $('#sidebar-status').textContent = isLive ? 'Mesh connected' : 'Mesh unavailable';
  $('#sidebar-status-dot').classList.toggle('offline', !isLive);
  $('#footer-api-status').textContent = isLive ? 'FastAPI connected' : 'FastAPI unavailable';
  const notice = $('#connection-notice');
  notice.hidden = isLive || state.noticeDismissed;
  if (message) $('#connection-message').textContent = message;
}

function renderMetrics() {
  const records = state.ledger;
  const identities = latestIdentities(records || []);
  $('#metric-records').textContent = records ? String(records.length) : '—';
  $('#metric-records-foot').textContent = records ? (records.length ? `Latest record #${records[0]?.index ?? '—'}` : 'No ledger records returned') : 'Waiting for API';
  $('#metric-identities').textContent = records ? String(identities.length) : '—';
  $('#metric-identities-foot').textContent = records ? `${identities.filter(item => item.operation !== 'DEACTIVATE').length} active · ${identities.filter(item => item.operation === 'DEACTIVATE').length} deactivated` : 'Derived from ledger history';
  const integrity = state.audit;
  const integrityText = !integrity ? 'Unknown' : integrity.valid ? 'Verified' : 'Failed';
  $('#metric-integrity').textContent = integrityText;
  $('#metric-integrity').className = `metric-value metric-status ${integrity?.valid ? 'text-success' : integrity ? 'text-danger' : ''}`;
  $('#metric-integrity-foot').textContent = integrity ? `${integrity.total_records} records checked` : 'Audit result unavailable';
  const key = state.publicKey;
  $('#metric-signing').textContent = key?.algorithm || '—';
  $('#metric-signing-foot').textContent = key ? `Issuer ${key.issuer}` : 'Public-key endpoint unavailable';

  const banner = $('#integrity-banner');
  banner.classList.toggle('integrity-good', Boolean(integrity?.valid));
  banner.classList.toggle('integrity-bad', Boolean(integrity && !integrity.valid));
  $('#integrity-symbol').textContent = integrity ? (integrity.valid ? '✓' : '!') : '…';
  $('#integrity-title').textContent = integrity ? (integrity.valid ? 'Ledger integrity verified' : 'Ledger integrity check failed') : 'Waiting for audit';
  $('#integrity-description').textContent = integrity ? (integrity.valid ? `All ${integrity.total_records} records passed the chain check.` : (integrity.error || 'The ledger reported an integrity failure.')) : 'The API will report the current chain status.';
}

function tableState(colspan, message, kind = 'empty') {
  return `<tr><td colspan="${colspan}"><div class="table-state ${kind === 'error' ? 'state-error' : ''}">${escapeHtml(message)}</div></td></tr>`;
}

function renderRecentLedger() {
  const body = $('#recent-ledger-body');
  if (!state.ledger) { body.innerHTML = tableState(4, 'Ledger data is unavailable.', 'error'); return; }
  if (!state.ledger.length) { body.innerHTML = tableState(4, 'No ledger records returned by the API.'); return; }
  body.innerHTML = state.ledger.slice(0, 6).map(record => `<tr><td class="mono">#${escapeHtml(record.index)}</td><td class="mono did-cell">${escapeHtml(record.did)}</td><td><span class="operation-chip">${escapeHtml(record.operation)}</span></td><td>${formatDate(record.timestamp)}</td></tr>`).join('');
}

function renderLedger() {
  const body = $('#ledger-table-body');
  if (!state.ledger) { body.innerHTML = tableState(6, 'Could not load ledger records. Check the API connection and refresh.', 'error'); $('#ledger-count').textContent = 'Data unavailable'; $('#export-ledger-button').disabled = true; return; }
  $('#ledger-count').textContent = `${state.ledger.length} record${state.ledger.length === 1 ? '' : 's'} returned by the API`;
  $('#export-ledger-button').disabled = !state.ledger.length;
  if (!state.ledger.length) { body.innerHTML = tableState(6, 'The ledger contains no records.'); return; }
  body.innerHTML = state.ledger.map(record => `<tr><td class="mono">${escapeHtml(record.index)}</td><td>${formatDate(record.timestamp)}</td><td class="mono did-cell">${escapeHtml(record.did)}</td><td><span class="operation-chip">${escapeHtml(record.operation)}</span></td><td class="mono" title="${escapeHtml(record.record_hash)}">${escapeHtml(shortHash(record.record_hash))}</td><td class="mono" title="${escapeHtml(record.previous_hash)}">${escapeHtml(shortHash(record.previous_hash))}</td></tr>`).join('');
  $('#tamper-index').innerHTML = state.ledger.map(record => `<option value="${escapeHtml(record.index)}">#${escapeHtml(record.index)} · ${escapeHtml(record.operation)} · ${escapeHtml(record.did)}</option>`).join('');
}

function renderIdentities() {
  const body = $('#identity-table-body');
  if (!state.ledger) { body.innerHTML = tableState(4, 'Identity records are unavailable because ledger data could not be loaded.', 'error'); $('#identity-count').textContent = 'Data unavailable'; return; }
  const identities = latestIdentities(state.ledger);
  const term = $('#identity-search').value.trim().toLowerCase();
  const shown = identities.filter(record => record.did.toLowerCase().includes(term));
  $('#identity-count').textContent = `${shown.length} of ${identities.length} ledger-derived identity record${identities.length === 1 ? '' : 's'}`;
  if (!shown.length) { body.innerHTML = tableState(4, term ? 'No DID matches this search.' : 'No identity records are present in the ledger.'); return; }
  body.innerHTML = shown.map(record => `<tr><td class="mono did-cell">${escapeHtml(record.did)}</td><td><span class="status-chip ${record.operation === 'DEACTIVATE' ? 'warning' : 'success'}">${record.operation === 'DEACTIVATE' ? 'Deactivated' : 'Active · ' + escapeHtml(record.operation)}</span></td><td>${formatDate(record.timestamp)}</td><td class="mono">#${escapeHtml(record.index)}</td></tr>`).join('');
}

function renderTokenInfo() {
  const key = state.publicKey;
  $('#key-status').textContent = key ? 'Live' : 'Unavailable';
  $('#key-status').className = `status-chip ${key ? 'success' : 'warning'}`;
  $('#key-algorithm').textContent = key ? `${key.algorithm} (Ed25519)` : '—';
  $('#key-issuer').textContent = key?.issuer || '—';
  $('#public-key').textContent = key?.public_key_pem || 'Public key is unavailable.';
  const scopeList = $('#scope-list');
  if (!state.scopes) scopeList.innerHTML = '<span class="muted">Allowed scopes are unavailable.</span>';
  else if (!state.scopes.length) scopeList.innerHTML = '<span class="muted">The API returned no scopes.</span>';
  else scopeList.innerHTML = state.scopes.map(scope => `<span class="scope-chip">${escapeHtml(scope)}</span>`).join('');
}

function healthItems() {
  if (!state.health) return [];
  return Object.entries(state.health.subsystems || {}).map(([key, value]) => [key, typeof value === 'object' && value !== null ? value : { status: String(value) }]);
}

function renderHealth() {
  const items = healthItems();
  const overview = $('#overview-health-list');
  const grid = $('#health-grid');
  if (!state.health) {
    overview.innerHTML = '<div class="table-state state-error">Health response unavailable.</div>';
    grid.innerHTML = '<div class="surface-card"><div class="table-state state-error">Could not load service health. Check the API connection and retry.</div></div>';
    return;
  }
  if (!items.length) {
    overview.innerHTML = '<div class="table-state">No subsystem details were returned.</div>';
    grid.innerHTML = '<div class="surface-card"><div class="table-state">The health response contains no subsystem details.</div></div>';
    return;
  }
  const overall = String(state.health.status || 'unknown');
  overview.innerHTML = `<div class="health-row"><span class="health-name">Application</span><span class="status-chip ${statusClass(overall)}">${escapeHtml(overall)}</span></div>` + items.slice(0, 4).map(([key, item]) => `<div class="health-row"><span class="health-name">${escapeHtml(item.name || key.replaceAll('_', ' '))}</span><span class="status-chip ${statusClass(item.status)}">${escapeHtml(item.status || 'unknown')}</span></div>`).join('');
  grid.innerHTML = `<article class="health-card"><div class="health-card-top"><span class="health-glyph">◎</span><span class="status-chip ${statusClass(overall)}">${escapeHtml(overall)}</span></div><h3>Application</h3><p>FastAPI composite health response</p><div class="health-detail">Version ${escapeHtml(state.health.version || 'not reported')}</div></article>` + items.map(([key, item]) => `<article class="health-card"><div class="health-card-top"><span class="health-glyph">${escapeHtml(key.slice(0, 1).toUpperCase())}</span><span class="status-chip ${statusClass(item.status)}">${escapeHtml(item.status || 'unknown')}</span></div><h3>${escapeHtml(item.name || key.replaceAll('_', ' '))}</h3><p>${escapeHtml(item.description || 'No description provided by the API.')}</p><div class="health-detail">${item.latency_ms == null ? 'Latency not reported' : `${escapeHtml(item.latency_ms)} ms`}</div></article>`).join('');
}

function statusClass(status) {
  const value = String(status || '').toLowerCase();
  if (['healthy', 'active', 'valid'].includes(value)) return 'success';
  if (['degraded', 'pending', 'unknown'].includes(value)) return 'warning';
  if (['compromised', 'unreachable', 'failed', 'unhealthy'].includes(value)) return 'danger';
  return 'neutral';
}

function showVerification(result) {
  const panel = $('#verify-result');
  panel.hidden = false;
  panel.className = `result-panel ${result.valid ? 'result-success' : 'result-error'}`;
  if (!result.valid) {
    panel.innerHTML = `<strong>Token rejected</strong><p>${escapeHtml(result.error || 'The API did not validate this token.')}</p>`;
    return;
  }
  const claims = result.claims || {};
  const expiry = claims.exp ? formatDate(Number(claims.exp) * 1000) : 'Not provided';
  const scopes = Array.isArray(claims.scope) ? claims.scope.join(', ') : (claims.scope || 'Not provided');
  panel.innerHTML = `<strong>Token verified</strong><dl class="verification-details"><div><dt>Subject</dt><dd>${escapeHtml(claims.sub || 'Not provided')}</dd></div><div><dt>Scopes</dt><dd>${escapeHtml(scopes)}</dd></div><div><dt>Expires</dt><dd>${escapeHtml(expiry)}</dd></div></dl>`;
}

async function refreshAll() {
  if (state.busy) return;
  state.busy = true;
  $('#refresh-button').disabled = true;
  $('#refresh-button').classList.add('is-loading');
  const results = await Promise.allSettled([
    request('/ledger'), request('/ledger/verify'), request('/tokens/public-key'), request('/tokens/policy/scopes'), request('/health')
  ]);
  state.ledger = results[0].status === 'fulfilled' && Array.isArray(results[0].value) ? results[0].value : null;
  state.audit = results[1].status === 'fulfilled' ? results[1].value : null;
  state.publicKey = results[2].status === 'fulfilled' ? results[2].value : null;
  state.scopes = results[3].status === 'fulfilled' && Array.isArray(results[3].value?.scopes) ? results[3].value.scopes : null;
  state.health = results[4].status === 'fulfilled' ? results[4].value : null;
  const live = results.some(result => result.status === 'fulfilled');
  const firstError = results.find(result => result.status === 'rejected')?.reason;
  setConnection(live, firstError?.name === 'AbortError' ? 'The API request timed out. Check that the backend is running.' : (firstError?.message || 'Could not reach the FastAPI service.'));
  renderMetrics(); renderRecentLedger(); renderLedger(); renderIdentities(); renderTokenInfo(); renderHealth();
  $('#last-updated').textContent = `Updated ${new Intl.DateTimeFormat(undefined, { timeStyle: 'short' }).format(new Date())}`;
  state.busy = false;
  $('#refresh-button').disabled = false;
  $('#refresh-button').classList.remove('is-loading');
}

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  $('#toast-region').append(toast);
  window.setTimeout(() => toast.remove(), 4200);
}

function navigate(section) {
  const valid = ['overview', 'identities', 'ledger', 'tokens', 'events', 'health'].includes(section) ? section : 'overview';
  $$('.page-section').forEach(page => { const active = page.id === `section-${valid}`; page.hidden = !active; page.classList.toggle('active', active); });
  $$('.nav-link').forEach(link => { const active = link.dataset.section === valid; link.classList.toggle('active', active); if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current'); });
  $('#page-title').textContent = ({ overview: 'Overview', identities: 'Identities', ledger: 'Ledger audit', tokens: 'Token security', events: 'Security events', health: 'Service health' })[valid];
  closeMenu();
}

function closeMenu() {
  $('#sidebar').classList.remove('open');
  $('#scrim').hidden = true;
  $('#menu-button').setAttribute('aria-expanded', 'false');
}

function exportLedger() {
  if (!state.ledger?.length) return;
  const headers = ['index', 'timestamp', 'did', 'operation', 'doc_hash', 'previous_hash', 'record_hash'];
  const quote = value => `"${String(value ?? '').replaceAll('"', '""')}"`;
  const csv = [headers.join(','), ...state.ledger.map(record => headers.map(header => quote(record[header])).join(','))].join('\r\n');
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url; link.download = `trustmesh-ledger-${new Date().toISOString().slice(0, 10)}.csv`; link.click();
  URL.revokeObjectURL(url);
}

async function simulateTamper(event) {
  event.preventDefault();
  const submit = $('#tamper-submit');
  submit.disabled = true;
  $('#tamper-error').hidden = true;
  const payload = {
    index: Number($('#tamper-index').value),
    field: $('#tamper-field').value,
    new_value: $('#tamper-value').value,
    recalculate_record_hash: false
  };
  try {
    await request('/ledger/simulate-tamper', { method: 'POST', body: JSON.stringify(payload) });
    $('#tamper-dialog').close();
    showToast('Simulation complete. Ledger integrity has been rechecked.', 'warning');
    await refreshAll();
    navigate('ledger');
  } catch (error) {
    const target = $('#tamper-error');
    target.hidden = false;
    target.textContent = `Simulation could not be completed: ${error.message}`;
  } finally {
    submit.disabled = false;
  }
}

function bindEvents() {
  $$('.nav-link').forEach(link => link.addEventListener('click', () => navigate(link.dataset.section)));
  window.addEventListener('hashchange', () => navigate(location.hash.slice(1)));
  $('#refresh-button').addEventListener('click', refreshAll);
  $('#audit-button').addEventListener('click', async () => { await refreshAll(); showToast(state.audit ? 'Integrity audit refreshed.' : 'Integrity audit is unavailable.', state.audit?.valid ? 'success' : 'warning'); });
  $('#health-refresh-button').addEventListener('click', refreshAll);
  $('#identity-search').addEventListener('input', renderIdentities);
  $('#export-ledger-button').addEventListener('click', exportLedger);
  $('#dismiss-notice').addEventListener('click', () => { state.noticeDismissed = true; $('#connection-notice').hidden = true; });
  $('#menu-button').addEventListener('click', () => {
    const open = $('#sidebar').classList.toggle('open');
    $('#scrim').hidden = !open;
    $('#menu-button').setAttribute('aria-expanded', String(open));
  });
  $('#scrim').addEventListener('click', closeMenu);
  $('#clear-token-button').addEventListener('click', () => { $('#verify-token').value = ''; $('#verify-result').hidden = true; $('#verify-token').focus(); });
  $('#verify-form').addEventListener('submit', async event => {
    event.preventDefault();
    const tokenField = $('#verify-token');
    const button = $('#verify-button');
    const submittedToken = tokenField.value.trim();
    if (!submittedToken) return;
    button.disabled = true;
    button.textContent = 'Verifying…';
    const panel = $('#verify-result');
    panel.hidden = false; panel.className = 'result-panel'; panel.textContent = 'Checking signature, claims, and revocation status…';
    try { showVerification(await request('/tokens/verify', { method: 'POST', body: JSON.stringify({ token: submittedToken }) })); }
    catch (error) {
      panel.hidden = false; panel.className = 'result-panel result-error';
      panel.innerHTML = `<strong>Verification request failed</strong><p>${escapeHtml(error.message)}</p>`;
    } finally {
      tokenField.value = '';
      button.disabled = false; button.textContent = 'Verify token';
    }
  });

  const dialog = $('#tamper-dialog');
  $('#open-tamper-dialog').addEventListener('click', () => {
    if (!state.ledger?.length) { showToast('Load ledger records before opening the simulation.', 'warning'); return; }
    dialog.showModal();
  });
  $('#tamper-close').addEventListener('click', () => dialog.close());
  $('#tamper-cancel').addEventListener('click', () => dialog.close());
  $('#tamper-form').addEventListener('submit', simulateTamper);
  dialog.addEventListener('click', event => { if (event.target === dialog) dialog.close(); });
}

bindEvents();
navigate(location.hash.slice(1) || 'overview');
refreshAll();
window.setInterval(refreshAll, REFRESH_INTERVAL);
