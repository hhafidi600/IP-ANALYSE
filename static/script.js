// ---- Port strip (signature element) ----
const portsEl = document.querySelector('.ports');
if (portsEl) {
  const PORT_COUNT = 12;
  for (let i = 0; i < PORT_COUNT; i++) {
    const p = document.createElement('div');
    p.className = 'port';
    portsEl.appendChild(p);
  }
}
const portEls = portsEl ? [...portsEl.children] : [];
function setPortsIdle() { portEls.forEach((p, i) => { p.className = 'port' + (i % 4 === 0 ? ' on-teal' : ''); }); }
function setPortsScanning() { portEls.forEach((p) => { p.className = 'port on-amber'; }); }
setPortsIdle();

// ---- Tab navigation ----
const navItems = document.querySelectorAll('.nav-item');
const tools = document.querySelectorAll('.tool');
function activateTool(toolId) {
  navItems.forEach(b => b.classList.toggle('is-active', b.dataset.tool === toolId));
  tools.forEach(t => t.classList.toggle('is-active', t.id === 'tool-' + toolId));
}
navItems.forEach(btn => {
  if (btn.dataset.tool) btn.addEventListener('click', () => activateTool(btn.dataset.tool));
});

// ---- Port scan mode switch ----
const modeSwitch = document.getElementById('scanModeSwitch');
const rangeFields = document.querySelectorAll('.range-field');
let scanMode = 'quick';
if (modeSwitch) {
  modeSwitch.querySelectorAll('.mode-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      modeSwitch.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('is-active'));
      btn.classList.add('is-active');
      scanMode = btn.dataset.mode;
      rangeFields.forEach(f => f.hidden = scanMode !== 'range');
    });
  });
}

// ---- Helpers ----
async function postJSON(url, body) {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (res.status === 401) { window.location.href = '/login'; return { ok: false, error: 'Session expired' }; }
  return res.json();
}
async function getJSON(url) {
  const res = await fetch(url);
  if (res.status === 401) { window.location.href = '/login'; return { ok: false }; }
  return res.json();
}
function row(k, v, cls) { return `<div class="row"><span class="k">${k}</span><span class="v ${cls || ''}">${v}</span></div>`; }
function spinner(label) { return `<div class="spinner">${label} <span class="dot"></span><span class="dot"></span><span class="dot"></span></div>`; }
function revealLines(container, lines) {
  container.innerHTML = '';
  lines.forEach((html, i) => {
    const div = document.createElement('div');
    div.innerHTML = html;
    const el = div.firstElementChild || div;
    el.style.animationDelay = (i * 0.02) + 's';
    container.appendChild(el);
  });
}
function escapeHtml(str) {
  return str.replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

// ---- History (server-backed, persists per account) ----
async function renderHistory() {
  const list = document.getElementById('historyList');
  if (!list) return;
  const data = await getJSON('/api/history');
  if (!data.ok || data.history.length === 0) {
    list.innerHTML = '<div class="terminal-hint">no runs yet</div>';
    return;
  }
  list.innerHTML = data.history.map(h => `
    <button class="history-item" data-tool="${h.tool}" data-target="${escapeHtml(h.target || '')}">
      <span class="h-tool">${h.tool}</span>
      <span class="h-time">${new Date(h.created_at).toLocaleString()}</span>
      ${escapeHtml(h.target || '')} — ${escapeHtml(h.summary || '')}
    </button>
  `).join('');
  list.querySelectorAll('.history-item').forEach(el => {
    el.addEventListener('click', () => {
      const tool = el.dataset.tool;
      const target = el.dataset.target;
      activateTool(tool);
      const form = document.getElementById('form-' + tool);
      if (form) {
        const firstInput = form.querySelector('input[type="text"]');
        if (firstInput) firstInput.value = target;
      }
      document.getElementById('historyDrawer').classList.remove('is-open');
    });
  });
}
const historyToggle = document.getElementById('historyToggle');
if (historyToggle) {
  historyToggle.addEventListener('click', () => {
    document.getElementById('historyDrawer').classList.toggle('is-open');
    renderHistory();
  });
}
const historyClear = document.getElementById('historyClear');
if (historyClear) {
  historyClear.addEventListener('click', async () => {
    await postJSON('/api/history/clear', {});
    renderHistory();
  });
}

// ---- PDF export (via browser print) ----
document.querySelectorAll('.export-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tool = btn.dataset.export;
    const out = document.getElementById('out-' + tool);
    const title = document.querySelector('#tool-' + tool + ' h1').textContent;
    const printArea = document.getElementById('printArea');
    printArea.innerHTML = `<h2>${title} — NETKIT Report</h2><div class="print-meta">Generated ${new Date().toLocaleString()}</div>${out.innerHTML}`;
    window.print();
  });
});
function enableExport(tool) {
  const btn = document.querySelector(`.export-btn[data-export="${tool}"]`);
  if (btn) btn.disabled = false;
}

// ---- Subnet Calculator ----
const formSubnet = document.getElementById('form-subnet');
if (formSubnet) formSubnet.addEventListener('submit', async (e) => {
  e.preventDefault();
  const cidr = e.target.cidr.value;
  const out = document.getElementById('out-subnet');
  out.innerHTML = spinner('calculating');
  const data = await postJSON('/api/subnet', { cidr });
  if (!data.ok) { out.innerHTML = `<div class="error">error: ${data.error}</div>`; return; }
  revealLines(out, [
    row('ip address', data.ip), row('subnet mask', data.netmask),
    row('network', data.network), row('broadcast', data.broadcast),
    '<div class="divider"></div>',
    row('total addresses', data.total), row('usable hosts', data.usable),
    row('first host', data.first_host), row('last host', data.last_host),
  ]);
  enableExport('subnet');
  renderHistory();
});

// ---- IP Classifier ----
const formIpcheck = document.getElementById('form-ipcheck');
if (formIpcheck) formIpcheck.addEventListener('submit', async (e) => {
  e.preventDefault();
  const ip = e.target.ip.value;
  const out = document.getElementById('out-ipcheck');
  out.innerHTML = spinner('checking');
  const data = await postJSON('/api/ip-check', { ip });
  if (!data.ok) { out.innerHTML = `<div class="error">error: ${data.error}</div>`; return; }
  const cls = data.category === 'Private' ? 'tag-private' : data.category === 'Public' ? 'tag-public' : 'tag-other';
  const lines = [row('ip', data.ip), row('category', data.category, cls), '<div class="divider"></div>'];
  data.ranges.forEach(r => lines.push(row(r.range, r.match ? 'match' : '—', r.match ? 'tag-private' : '')));
  revealLines(out, lines);
  enableExport('ipcheck');
  renderHistory();
});

// ---- Port Scanner ----
const formPortscan = document.getElementById('form-portscan');
if (formPortscan) formPortscan.addEventListener('submit', async (e) => {
  e.preventDefault();
  const target = e.target.target.value;
  const start = e.target.start.value;
  const end = e.target.end.value;
  const out = document.getElementById('out-portscan');
  out.innerHTML = spinner(scanMode === 'quick' ? 'scanning top ports' : 'scanning range');
  setPortsScanning();
  const data = await postJSON('/api/port-scan', { target, start, end, mode: scanMode });
  setPortsIdle();
  if (!data.ok) { out.innerHTML = `<div class="error">error: ${data.error}</div>`; return; }
  const meta = `<div class="meta">${data.scanned} ports scanned in ${data.elapsed}s</div>`;
  if (data.open_ports.length === 0) {
    out.innerHTML = meta + `<div class="terminal-hint">no open ports found on ${data.target_ip}</div>`;
  } else {
    revealLines(out, data.open_ports.map(p => `<div class="scan-line">${String(p.port).padEnd(6)} <span class="tag-private">open</span>  ${p.service}</div>`));
    out.insertAdjacentHTML('afterbegin', meta);
  }
  enableExport('portscan');
  renderHistory();
});

// ---- Ping Sweep ----
const formPingsweep = document.getElementById('form-pingsweep');
if (formPingsweep) formPingsweep.addEventListener('submit', async (e) => {
  e.preventDefault();
  const network = e.target.network.value;
  const out = document.getElementById('out-pingsweep');
  out.innerHTML = spinner('sweeping');
  setPortsScanning();
  const data = await postJSON('/api/ping-sweep', { network });
  setPortsIdle();
  if (!data.ok) { out.innerHTML = `<div class="error">error: ${data.error}</div>`; return; }
  const meta = `<div class="meta">${data.scanned} hosts checked in ${data.elapsed}s</div>`;
  if (data.alive.length === 0) {
    out.innerHTML = meta + `<div class="terminal-hint">no live hosts found</div>`;
  } else {
    revealLines(out, data.alive.map(ip => `<div class="scan-line">${ip} <span class="tag-private">up</span></div>`));
    out.insertAdjacentHTML('afterbegin', meta);
    out.insertAdjacentHTML('beforeend', `<div class="divider"></div>` + row('hosts up', `${data.alive.length} / ${data.total}`));
  }
  enableExport('pingsweep');
  renderHistory();
});

// ---- Traceroute ----
const formTraceroute = document.getElementById('form-traceroute');
if (formTraceroute) formTraceroute.addEventListener('submit', async (e) => {
  e.preventDefault();
  const target = e.target.target.value;
  const out = document.getElementById('out-traceroute');
  out.innerHTML = spinner('tracing route');
  setPortsScanning();
  const data = await postJSON('/api/traceroute', { target });
  setPortsIdle();
  if (!data.ok) { out.innerHTML = `<div class="error">error: ${data.error}</div>`; return; }
  out.innerHTML = `<pre>${escapeHtml(data.output || 'no output')}</pre>`;
  enableExport('traceroute');
  renderHistory();
});

// ---- DNS Lookup ----
const formDns = document.getElementById('form-dnslookup');
if (formDns) formDns.addEventListener('submit', async (e) => {
  e.preventDefault();
  const domain = e.target.domain.value;
  const out = document.getElementById('out-dnslookup');
  out.innerHTML = spinner('resolving');
  const data = await postJSON('/api/dns-lookup', { domain });
  if (!data.ok) { out.innerHTML = `<div class="error">error: ${data.error}</div>`; return; }
  const lines = [row('domain', data.domain)];
  if (data.a_records.length) lines.push(row('A records', data.a_records.join(', ')));
  if (data.aaaa_records.length) lines.push(row('AAAA records', data.aaaa_records.join(', ')));
  if (data.reverse) lines.push(row('reverse DNS', data.reverse));
  if (!data.a_records.length && !data.aaaa_records.length) lines.push('<div class="terminal-hint">no records found</div>');
  revealLines(out, lines);
  enableExport('dnslookup');
  renderHistory();
});

// ---- WHOIS ----
const formWhois = document.getElementById('form-whois');
if (formWhois) formWhois.addEventListener('submit', async (e) => {
  e.preventDefault();
  const domain = e.target.domain.value;
  const out = document.getElementById('out-whois');
  out.innerHTML = spinner('querying whois');
  const data = await postJSON('/api/whois', { domain });
  if (!data.ok) { out.innerHTML = `<div class="error">error: ${data.error}</div>`; return; }
  out.innerHTML = `<div class="meta">via ${data.server}</div><pre>${escapeHtml(data.raw || 'no data returned')}</pre>`;
  enableExport('whois');
  renderHistory();
});

// initial history load if the drawer exists
if (document.getElementById('historyList')) renderHistory();