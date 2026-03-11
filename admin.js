'use strict';

// ── state ──────────────────────────────────────────────────────────────────
const API = window.location.pathname;   // same URL, same CGI
// Token is held in memory only -- never written to sessionStorage or
// localStorage, which are accessible to any JS running in the same origin.
let masterToken = '';

// per-host state: { loaded: bool, open: bool, tokens: [{token,label}] }
const hostState = {};

// ── api ────────────────────────────────────────────────────────────────────
async function api(params, body = null) {
  const qs = new URLSearchParams(params).toString();
  const opts = {
    headers: { 'Authorization': `Bearer ${masterToken}` }
  };
  if (body) {
    opts.method = 'POST';
    opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    opts.body = new URLSearchParams(body).toString();
  }
  const res = await fetch(`${API}?${qs}`, opts);
  const data = await res.json();
  if (data.error) throw new Error(data.error);
  return data;
}

// ── toast ──────────────────────────────────────────────────────────────────
let toastTimer;
function toast(msg, type = 'ok') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `show ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.className = '', 2400);
}

// ── auth ───────────────────────────────────────────────────────────────────
async function tryAuth() {
  const input = document.getElementById('master-input').value.trim();
  if (!input) return;
  masterToken = input;
  try {
    await api({ action: 'hosts' });
    showApp();
  } catch {
    document.getElementById('auth-err').style.display = 'block';
    masterToken = '';
  }
}

function showApp() {
  document.getElementById('auth-overlay').style.display = 'none';
  document.getElementById('app').style.display = '';
  const preview = masterToken.slice(0, 3) + '•••••••••••';
  document.getElementById('token-preview').textContent = preview;
  loadHosts();
}

document.getElementById('auth-btn').addEventListener('click', tryAuth);
document.getElementById('master-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') tryAuth();
});
document.getElementById('logout-btn').addEventListener('click', () => {
  masterToken = '';
  // Clear cached host/token state so a re-login always sees fresh data.
  Object.keys(hostState).forEach(k => delete hostState[k]);
  document.getElementById('auth-overlay').style.display = '';
  document.getElementById('app').style.display = 'none';
  document.getElementById('master-input').value = '';
  document.getElementById('auth-err').style.display = 'none';
});

// No auto-login: token is memory-only, re-enter on each page load.

// ── tree rendering ─────────────────────────────────────────────────────────

function arrowSvg() {
  return `<svg viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.8">
    <polyline points="3,2 7,5 3,8"/>
  </svg>`;
}

function renderHost(host) {
  const s = hostState[host];
  const count = s.loaded ? s.tokens.length : '?';
  const badgeClass = (s.loaded && s.tokens.length === 0) ? 'badge empty' : 'badge';

  const tr = document.createElement('tr');
  tr.className = 'row-host';
  tr.dataset.host = host;
  tr.innerHTML = `
    <td colspan="2">
      <div class="cell-inner" data-toggle="${escHtml(host)}">
        <span class="toggle-arrow ${s.open ? 'open' : ''}">${arrowSvg()}</span>
        <span class="host-name">${escHtml(host)}</span>
        <span class="${badgeClass}" id="badge-${cssId(host)}">${count}</span>
      </div>
    </td>
    <td>
      <div class="host-actions">
        <button class="btn-primary btn-sm" data-new-token="${escHtml(host)}">+ Token</button>
      </div>
    </td>`;
  return tr;
}

function renderTokenRow(host, tok, label) {
  const tr = document.createElement('tr');
  tr.className = 'row-token';
  tr.dataset.host = host;
  tr.dataset.token = tok;
  tr.innerHTML = `
    <td>
      <div class="cell-inner">
        <span class="token-value" title="${escHtml(tok)}">${escHtml(tok)}</span>
      </div>
    </td>
    <td>
      <div class="cell-inner" style="padding-left:0">
        <span class="token-label${label ? '' : ' none'}">${label ? escHtml(label) : 'no label'}</span>
      </div>
    </td>
    <td>
      <div class="host-actions">
        <button class="btn-danger btn-sm" data-revoke-host="${escHtml(host)}" data-revoke-token="${escHtml(tok)}">Revoke</button>
      </div>
    </td>`;
  return tr;
}

function renderNewTokenRow(host) {
  const tr = document.createElement('tr');
  tr.className = 'row-new-token';
  tr.id = `new-token-row-${cssId(host)}`;
  tr.dataset.host = host;
  tr.innerHTML = `
    <td colspan="2">
      <div class="cell-inner">
        <input type="text" placeholder="Token label (optional)" id="new-label-${cssId(host)}" />
      </div>
    </td>
    <td>
      <div class="host-actions">
        <button class="btn-primary btn-sm" data-confirm-create="${escHtml(host)}">Create</button>
        <button class="btn-ghost btn-sm" data-cancel-new="${escHtml(host)}">Cancel</button>
      </div>
    </td>`;
  return tr;
}

function renderEmptyRow(host, msg = 'No tokens') {
  const tr = document.createElement('tr');
  tr.className = 'row-empty';
  tr.dataset.host = host;
  tr.innerHTML = `<td colspan="3"><div class="cell-inner">${escHtml(msg)}</div></td>`;
  return tr;
}

function renderLoadingRow(host) {
  const tr = document.createElement('tr');
  tr.className = 'row-empty';
  tr.dataset.host = host;
  tr.innerHTML = `<td colspan="3"><div class="cell-inner"><span class="spinner"></span>&nbsp; Loading tokens…</div></td>`;
  return tr;
}

// Insert rows after the host row, removing any existing children first
function insertChildRows(host, rows) {
  const tbody = document.getElementById('tree-body');
  // remove existing children
  [...tbody.querySelectorAll(`tr[data-host="${CSS.escape(host)}"].row-token,
                              tr[data-host="${CSS.escape(host)}"].row-empty,
                              tr[data-host="${CSS.escape(host)}"].row-new-token`)].forEach(r => r.remove());

  const hostRow = tbody.querySelector(`tr.row-host[data-host="${CSS.escape(host)}"]`);
  let ref = hostRow.nextSibling;
  for (const row of rows) {
    tbody.insertBefore(row, ref);
    ref = row.nextSibling;
  }
}

function updateBadge(host) {
  const s = hostState[host];
  const el = document.getElementById(`badge-${cssId(host)}`);
  if (!el) return;
  el.textContent = s.loaded ? s.tokens.length : '?';
  el.className = (s.loaded && s.tokens.length === 0) ? 'badge empty' : 'badge';
}

function redrawChildren(host) {
  const s = hostState[host];
  if (!s.open) {
    insertChildRows(host, []);
    return;
  }
  const rows = [];
  if (!s.loaded) {
    rows.push(renderLoadingRow(host));
  } else {
    for (const { token, label } of s.tokens) {
      rows.push(renderTokenRow(host, token, label));
    }
    if (s.tokens.length === 0) rows.push(renderEmptyRow(host));
  }
  insertChildRows(host, rows);
}

// ── data loading ───────────────────────────────────────────────────────────

async function loadHosts() {
  const tbody = document.getElementById('tree-body');
  tbody.innerHTML = `<tr class="row-empty"><td colspan="3"><div class="cell-inner"><span class="spinner"></span>&nbsp; Loading…</div></td></tr>`;

  let hosts;
  try {
    const data = await api({ action: 'hosts' });
    hosts = data.hosts || [];
  } catch (e) {
    tbody.innerHTML = `<tr class="row-empty"><td colspan="3"><div class="cell-inner">Error: ${escHtml(e.message)}</div></td></tr>`;
    return;
  }

  // preserve open/loaded state for hosts already known
  for (const h of hosts) {
    if (!hostState[h]) hostState[h] = { open: false, loaded: false, tokens: [] };
  }

  tbody.innerHTML = '';
  if (hosts.length === 0) {
    tbody.innerHTML = `<tr class="row-empty"><td colspan="3"><div class="cell-inner">No virtual hosts found.</div></td></tr>`;
    return;
  }

  for (const h of hosts) {
    tbody.appendChild(renderHost(h));
    if (hostState[h].open) redrawChildren(h);
  }
}

async function loadTokens(host) {
  const s = hostState[host];
  s.loaded = false;
  redrawChildren(host);

  try {
    const data = await api({ action: 'tokens', host });
    s.tokens = data.tokens || [];
    s.loaded = true;
  } catch (e) {
    s.loaded = true;
    s.tokens = [];
    toast(`Failed to load tokens for ${host}: ${e.message}`, 'err');
  }

  updateBadge(host);
  redrawChildren(host);
}

// ── actions ────────────────────────────────────────────────────────────────

async function toggleHost(host) {
  const s = hostState[host];
  s.open = !s.open;

  // update arrow
  const row = document.querySelector(`tr.row-host[data-host="${CSS.escape(host)}"]`);
  if (row) {
    const arrow = row.querySelector('.toggle-arrow');
    if (arrow) arrow.classList.toggle('open', s.open);
  }

  if (s.open && !s.loaded) {
    await loadTokens(host);
  } else {
    redrawChildren(host);
  }
}

function showNewTokenRow(host) {
  const s = hostState[host];
  // open host if not already
  if (!s.open) {
    s.open = true;
    const row = document.querySelector(`tr.row-host[data-host="${CSS.escape(host)}"]`);
    if (row) row.querySelector('.toggle-arrow')?.classList.add('open');
    if (!s.loaded) {
      loadTokens(host).then(() => appendNewTokenRow(host));
      return;
    }
  }
  appendNewTokenRow(host);
}

function appendNewTokenRow(host) {
  // don't double-add
  if (document.getElementById(`new-token-row-${cssId(host)}`)) return;
  redrawChildren(host);
  const tbody = document.getElementById('tree-body');
  // find last child row for this host
  const children = [...tbody.querySelectorAll(
    `tr[data-host="${CSS.escape(host)}"].row-token, tr[data-host="${CSS.escape(host)}"].row-empty`
  )];
  const insertAfter = children[children.length - 1];
  const newRow = renderNewTokenRow(host);
  if (insertAfter) insertAfter.after(newRow);
  else {
    const hostRow = tbody.querySelector(`tr.row-host[data-host="${CSS.escape(host)}"]`);
    hostRow.after(newRow);
  }
  document.getElementById(`new-label-${cssId(host)}`)?.focus();
}

async function createToken(host) {
  const labelEl = document.getElementById(`new-label-${cssId(host)}`);
  const label = labelEl ? labelEl.value.trim() : '';
  try {
    const data = await api({ action: 'create' }, { host, label });
    const s = hostState[host];
    s.tokens.push({ token: data.token, label: data.label });
    updateBadge(host);
    redrawChildren(host);
    toast(`Token created for ${host}`);
  } catch (e) {
    toast(`Create failed: ${e.message}`, 'err');
  }
}

async function revokeToken(host, tok) {
  try {
    await api({ action: 'delete' }, { host, token: tok });
    const s = hostState[host];
    s.tokens = s.tokens.filter(t => t.token !== tok);
    updateBadge(host);
    redrawChildren(host);
    toast(`Token revoked`);
  } catch (e) {
    toast(`Revoke failed: ${e.message}`, 'err');
  }
}

// ── event delegation ───────────────────────────────────────────────────────
document.getElementById('tree-body').addEventListener('click', async e => {
  const btn = e.target.closest('button, [data-toggle]');
  if (!btn) return;

  if (btn.dataset.toggle)         return toggleHost(btn.dataset.toggle);
  if (btn.dataset.newToken)       return showNewTokenRow(btn.dataset.newToken);
  if (btn.dataset.confirmCreate)  return createToken(btn.dataset.confirmCreate);
  if (btn.dataset.cancelNew) {
    document.getElementById(`new-token-row-${cssId(btn.dataset.cancelNew)}`)?.remove();
    return;
  }
  if (btn.dataset.revokeToken)    return revokeToken(btn.dataset.revokeHost, btn.dataset.revokeToken);
});

document.getElementById('tree-body').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const row = e.target.closest('.row-new-token');
  if (!row) return;
  createToken(row.dataset.host);
});

document.getElementById('refresh-btn').addEventListener('click', loadHosts);

// ── utils ──────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// safe CSS id fragment from a hostname
function cssId(host) {
  return host.replace(/[^a-zA-Z0-9_-]/g, '_');
}
