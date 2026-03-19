'use strict';

// ── state ──────────────────────────────────────────────────────────────────
const API = window.location.pathname;   // same URL, same CGI
// Token is held in memory only -- never written to sessionStorage or
// localStorage, which are accessible to any JS running in the same origin.
let masterToken = '';

// per-host state: { loaded: bool, open: bool, credentials: [{type,value,label}], accessOpen: bool|null }
// open       — whether the host row is expanded in the UI
// accessOpen — true=open access, false=token required, null=unknown (not yet in token store)
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
const STORAGE_KEY = 'apache-auth-master-token';

async function tryAuth() {
  const input = document.getElementById('master-input').value.trim();
  if (!input) return;
  masterToken = input;
  try {
    await api({ action: 'hosts' });
    if (document.getElementById('remember-chk').checked)
      localStorage.setItem(STORAGE_KEY, masterToken);
    else
      localStorage.removeItem(STORAGE_KEY);
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
  localStorage.removeItem(STORAGE_KEY);
  Object.keys(hostState).forEach(k => delete hostState[k]);
  document.getElementById('auth-overlay').style.display = '';
  document.getElementById('app').style.display = 'none';
  document.getElementById('master-input').value = '';
  document.getElementById('remember-chk').checked = false;
  document.getElementById('auth-err').style.display = 'none';
});

// Auto-login from saved token if present.
const saved = localStorage.getItem(STORAGE_KEY);
if (saved) {
  document.getElementById('master-input').value = saved;
  document.getElementById('remember-chk').checked = true;
  tryAuth();
}

// ── tree rendering ─────────────────────────────────────────────────────────

function arrowSvg() {
  return `<svg viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.8">
    <polyline points="3,2 7,5 3,8"/>
  </svg>`;
}

function renderHost(host) {
  const s = hostState[host];
  const count = s.loaded ? s.credentials.length : '?';
  const badgeClass = (s.loaded && s.credentials.length === 0) ? 'badge empty' : 'badge';

  let pill = '';
  if (s.accessOpen === true)  pill = `<span class="pill pill-open">open</span>`;
  if (s.accessOpen === false) pill = `<span class="pill pill-protected">protected</span>`;

  const accessBtn = s.accessOpen === true
    ? `<button class="btn-ghost btn-sm" data-set-access="${escHtml(host)}" data-want-open="false">Protect</button>`
    : `<button class="btn-ghost btn-sm" data-set-access="${escHtml(host)}" data-want-open="true">Open</button>`;

  const tr = document.createElement('tr');
  tr.className = 'row-host';
  tr.dataset.host = host;
  tr.innerHTML = `
    <td colspan="2">
      <div class="cell-inner" data-toggle="${escHtml(host)}">
        <span class="toggle-arrow ${s.open ? 'open' : ''}">${arrowSvg()}</span>
        <span class="host-name">${escHtml(host)}</span>
        <span class="${badgeClass}" id="badge-${cssId(host)}">${count}</span>
        ${pill}
      </div>
    </td>
    <td>
      <div class="host-actions">
        ${accessBtn}
        <button class="btn-ghost btn-sm" data-new-ip="${escHtml(host)}">+ IP</button>
        <button class="btn-primary btn-sm" data-new-token="${escHtml(host)}">+ Token</button>
      </div>
    </td>`;
  return tr;
}

function updateHostRow(host) {
  const tbody = document.getElementById('tree-body');
  const old = tbody.querySelector(`tr.row-host[data-host="${CSS.escape(host)}"]`);
  if (old) old.replaceWith(renderHost(host));
}

function renderCredentialRow(host, type, value, label) {
  const tr = document.createElement('tr');
  tr.className = 'row-credential';
  tr.dataset.host = host;
  tr.dataset.credType = type;
  tr.dataset.credValue = value;
  const valueClass = type === 'ip' ? 'ip-value' : 'token-value';
  const typeBadge = type === 'ip'
    ? `<span class="cred-type cred-type-ip">IP</span>`
    : `<span class="cred-type cred-type-bearer">token</span>`;
  tr.innerHTML = `
    <td>
      <div class="cell-inner">
        ${typeBadge}
        <span class="${valueClass}" title="${escHtml(value)}">${escHtml(value)}</span>
      </div>
    </td>
    <td>
      <div class="cell-inner" style="padding-left:0">
        <span class="token-label${label ? '' : ' none'}">${label ? escHtml(label) : 'no label'}</span>
      </div>
    </td>
    <td>
      <div class="host-actions">
        <button class="btn-danger btn-sm"
          data-delete-host="${escHtml(host)}"
          data-delete-type="${escHtml(type)}"
          data-delete-value="${escHtml(value)}">Revoke</button>
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

function renderNewIPRow(host) {
  const tr = document.createElement('tr');
  tr.className = 'row-new-ip';
  tr.id = `new-ip-row-${cssId(host)}`;
  tr.dataset.host = host;
  tr.innerHTML = `
    <td>
      <div class="cell-inner">
        <input class="input-ip" type="text" placeholder="IP address" id="new-ip-addr-${cssId(host)}" />
      </div>
    </td>
    <td>
      <div class="cell-inner" style="padding-left:0">
        <input class="input-label" type="text" placeholder="Label (optional)" id="new-ip-label-${cssId(host)}" />
      </div>
    </td>
    <td>
      <div class="host-actions">
        <button class="btn-primary btn-sm" data-confirm-ip="${escHtml(host)}">Add</button>
        <button class="btn-ghost btn-sm" data-cancel-new-ip="${escHtml(host)}">Cancel</button>
      </div>
    </td>`;
  return tr;
}

function renderEmptyRow(host) {
  const tr = document.createElement('tr');
  tr.className = 'row-empty';
  tr.dataset.host = host;
  tr.innerHTML = `<td colspan="3"><div class="cell-inner">No credentials</div></td>`;
  return tr;
}

function renderLoadingRow(host) {
  const tr = document.createElement('tr');
  tr.className = 'row-empty';
  tr.dataset.host = host;
  tr.innerHTML = `<td colspan="3"><div class="cell-inner"><span class="spinner"></span>&nbsp; Loading…</div></td>`;
  return tr;
}

// Insert rows after the host row, removing any existing children first
function insertChildRows(host, rows) {
  const tbody = document.getElementById('tree-body');
  // remove existing children
  [...tbody.querySelectorAll(`tr[data-host="${CSS.escape(host)}"].row-credential,
                              tr[data-host="${CSS.escape(host)}"].row-empty,
                              tr[data-host="${CSS.escape(host)}"].row-new-token,
                              tr[data-host="${CSS.escape(host)}"].row-new-ip`)].forEach(r => r.remove());

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
  el.textContent = s.loaded ? s.credentials.length : '?';
  el.className = (s.loaded && s.credentials.length === 0) ? 'badge empty' : 'badge';
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
    for (const { type, value, label } of s.credentials) {
      rows.push(renderCredentialRow(host, type, value, label));
    }
    if (s.credentials.length === 0) rows.push(renderEmptyRow(host));
  }
  insertChildRows(host, rows);
}

// ── data loading ───────────────────────────────────────────────────────────

async function loadHosts() {
  const tbody = document.getElementById('tree-body');
  tbody.innerHTML = `<tr class="row-empty"><td colspan="3"><div class="cell-inner"><span class="spinner"></span>&nbsp; Loading…</div></td></tr>`;

  let hosts, managed;
  try {
    const [hostsData, listData] = await Promise.all([
      api({ action: 'hosts' }),
      api({ action: 'list' }),
    ]);
    hosts   = hostsData.hosts || [];
    managed = listData.hosts  || [];
  } catch (e) {
    tbody.innerHTML = `<tr class="row-empty"><td colspan="3"><div class="cell-inner">Error: ${escHtml(e.message)}</div></td></tr>`;
    return;
  }

  // Build map of managed hosts → open status
  const managedMap = {};
  for (const m of managed) managedMap[m.host] = m.open;

  // preserve open/loaded state for hosts already known; update accessOpen
  for (const h of hosts) {
    if (!hostState[h]) hostState[h] = { open: false, loaded: false, credentials: [], accessOpen: null };
    if (h in managedMap) hostState[h].accessOpen = managedMap[h];
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

async function loadCredentials(host) {
  const s = hostState[host];
  s.loaded = false;
  redrawChildren(host);

  try {
    const data = await api({ action: 'credentials', host });
    s.credentials = data.credentials || [];
    s.loaded = true;
    if (typeof data.open === 'boolean') s.accessOpen = data.open;
  } catch (e) {
    s.loaded = true;
    s.credentials = [];
    toast(`Failed to load credentials for ${host}: ${e.message}`, 'err');
  }

  updateHostRow(host);
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
    await loadCredentials(host);
  } else {
    redrawChildren(host);
  }
}

function showNewTokenRow(host) {
  const s = hostState[host];
  if (!s.open) {
    s.open = true;
    const row = document.querySelector(`tr.row-host[data-host="${CSS.escape(host)}"]`);
    if (row) row.querySelector('.toggle-arrow')?.classList.add('open');
    if (!s.loaded) {
      loadCredentials(host).then(() => appendNewTokenRow(host));
      return;
    }
  }
  appendNewTokenRow(host);
}

function appendNewTokenRow(host) {
  if (document.getElementById(`new-token-row-${cssId(host)}`)) return;
  redrawChildren(host);
  const tbody = document.getElementById('tree-body');
  const children = [...tbody.querySelectorAll(
    `tr[data-host="${CSS.escape(host)}"].row-credential, tr[data-host="${CSS.escape(host)}"].row-empty`
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

async function createBearer(host) {
  const labelEl = document.getElementById(`new-label-${cssId(host)}`);
  const label = labelEl ? labelEl.value.trim() : '';
  try {
    const data = await api({ action: 'create' }, { host, type: 'bearer', label });
    const s = hostState[host];
    s.credentials.push({ type: 'bearer', value: data.value, label: data.label });
    if (s.accessOpen === null) { s.accessOpen = false; updateHostRow(host); }
    updateBadge(host);
    redrawChildren(host);
    toast(`Token created for ${host}`);
  } catch (e) {
    toast(`Create failed: ${e.message}`, 'err');
  }
}

async function setAccess(host, wantOpen) {
  try {
    await api({ action: wantOpen ? 'open' : 'close' }, { host });
    if (!hostState[host]) hostState[host] = { open: false, loaded: false, credentials: [], accessOpen: null };
    hostState[host].accessOpen = wantOpen;
    updateHostRow(host);
    toast(wantOpen ? `${host}: open access` : `${host}: token required`);
  } catch (e) {
    toast(`Failed: ${e.message}`, 'err');
  }
}

async function deleteCredential(host, type, value) {
  try {
    await api({ action: 'delete' }, { host, type, value });
    const s = hostState[host];
    s.credentials = s.credentials.filter(c => !(c.type === type && c.value === value));
    updateBadge(host);
    redrawChildren(host);
    toast(type === 'ip' ? `IP ${value} removed` : `Token revoked`);
  } catch (e) {
    toast(`Delete failed: ${e.message}`, 'err');
  }
}

function showNewIPRow(host) {
  const s = hostState[host];
  if (!s.open) {
    s.open = true;
    const row = document.querySelector(`tr.row-host[data-host="${CSS.escape(host)}"]`);
    if (row) row.querySelector('.toggle-arrow')?.classList.add('open');
    if (!s.loaded) {
      loadCredentials(host).then(() => appendNewIPRow(host));
      return;
    }
  }
  appendNewIPRow(host);
}

function appendNewIPRow(host) {
  if (document.getElementById(`new-ip-row-${cssId(host)}`)) return;
  redrawChildren(host);
  const tbody = document.getElementById('tree-body');
  const children = [...tbody.querySelectorAll(
    `tr[data-host="${CSS.escape(host)}"].row-credential, tr[data-host="${CSS.escape(host)}"].row-empty`
  )];
  const insertAfter = children[children.length - 1];
  const newRow = renderNewIPRow(host);
  if (insertAfter) insertAfter.after(newRow);
  else {
    const hostRow = tbody.querySelector(`tr.row-host[data-host="${CSS.escape(host)}"]`);
    hostRow.after(newRow);
  }
  document.getElementById(`new-ip-addr-${cssId(host)}`)?.focus();
}

async function createIP(host) {
  const addrEl = document.getElementById(`new-ip-addr-${cssId(host)}`);
  const labelEl = document.getElementById(`new-ip-label-${cssId(host)}`);
  const value = addrEl ? addrEl.value.trim() : '';
  const label = labelEl ? labelEl.value.trim() : '';
  if (!value) { toast('IP address required', 'err'); return; }
  try {
    const data = await api({ action: 'create' }, { host, type: 'ip', value, label });
    const s = hostState[host];
    s.credentials = s.credentials.filter(c => !(c.type === 'ip' && c.value === data.value));
    s.credentials.push({ type: 'ip', value: data.value, label: data.label });
    if (s.accessOpen === null) { s.accessOpen = false; updateHostRow(host); }
    updateBadge(host);
    redrawChildren(host);
    toast(`IP ${data.value} added for ${host}`);
  } catch (e) {
    toast(`Add IP failed: ${e.message}`, 'err');
  }
}

// ── event delegation ───────────────────────────────────────────────────────
document.getElementById('tree-body').addEventListener('click', async e => {
  const btn = e.target.closest('button, [data-toggle]');
  if (!btn) return;

  if (btn.dataset.toggle)        return toggleHost(btn.dataset.toggle);
  if (btn.dataset.setAccess)     return setAccess(btn.dataset.setAccess, btn.dataset.wantOpen === 'true');
  if (btn.dataset.newToken)      return showNewTokenRow(btn.dataset.newToken);
  if (btn.dataset.confirmCreate) return createBearer(btn.dataset.confirmCreate);
  if (btn.dataset.cancelNew) {
    document.getElementById(`new-token-row-${cssId(btn.dataset.cancelNew)}`)?.remove();
    return;
  }
  if (btn.dataset.deleteValue)   return deleteCredential(btn.dataset.deleteHost, btn.dataset.deleteType, btn.dataset.deleteValue);
  if (btn.dataset.newIp)         return showNewIPRow(btn.dataset.newIp);
  if (btn.dataset.confirmIp)     return createIP(btn.dataset.confirmIp);
  if (btn.dataset.cancelNewIp) {
    document.getElementById(`new-ip-row-${cssId(btn.dataset.cancelNewIp)}`)?.remove();
    return;
  }
});

document.getElementById('tree-body').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const tokenRow = e.target.closest('.row-new-token');
  if (tokenRow) { createBearer(tokenRow.dataset.host); return; }
  const ipRow = e.target.closest('.row-new-ip');
  if (ipRow) createIP(ipRow.dataset.host);
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
