// Front end for Email Header Analyzer. Kept out of index.html so the CSP can forbid inline scripts.
const $ = id => document.getElementById(id);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
let pendingFile = null;

$('analyzeBtn').onclick = () => pendingFile ? analyzeFile(pendingFile) : analyzeText();
$('fileBtn').onclick = () => $('fileInput').click();
$('fileInput').onchange = e => { if (e.target.files[0]) useFile(e.target.files[0]); e.target.value = ''; };
$('clearBtn').onclick = () => { $('headers').value = ''; setFile(null); $('results').innerHTML = ''; $('headers').focus(); };
$('headers').addEventListener('input', () => setFile(null));
$('headers').addEventListener('keydown', e => { if (e.key === 'Enter' && e.ctrlKey) $('analyzeBtn').click(); });

// Drag and drop: the input box is the target; dropping elsewhere must not navigate away.
const drop = $('drop');
['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('hover'); }));
['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('hover'); }));
drop.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) useFile(f); });
window.addEventListener('dragover', e => e.preventDefault());
window.addEventListener('drop', e => e.preventDefault());

function setFile(f) {
  pendingFile = f;
  $('fileChip').innerHTML = f ? `<span class="file-chip">📎 ${esc(f.name)} (${(f.size / 1024).toFixed(1)} KB)</span>` : '';
}
function useFile(f) {
  $('headers').value = '';
  setFile(f);
  analyzeFile(f);
}

async function run(request) {
  const btn = $('analyzeBtn');
  btn.disabled = true;
  $('results').innerHTML = `<div class="spinner">⏳ Analyzing${$('live').checked ? ' and running live DNS checks' : ''}...</div>`;
  try {
    const res = await request();
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    render(data);
  } catch (err) {
    $('results').innerHTML = `<div class="results"><div class="card error">⚠️ ${esc(err.message)}</div></div>`;
  } finally {
    btn.disabled = false;
  }
}
function analyzeText() {
  const text = $('headers').value;
  if (!text.trim()) return $('headers').focus();
  run(() => fetch('/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text, live: $('live').checked }) }));
}
function analyzeFile(f) {
  run(() => fetch(`/analyze-file?live=${$('live').checked ? 1 : 0}`, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: f }));
}

// ------------------------------------------------------------------ helpers
const pillClass = r => ({ pass: 'pill-pass', 'pass-headers': 'pill-pass', ok: 'pill-pass', none: 'pill-muted', neutral: 'pill-muted',
  softfail: 'pill-warn', 'body-mismatch': 'pill-warn', temperror: 'pill-warn', medium: 'pill-warn', low: 'pill-info', info: 'pill-muted' }[r] || 'pill-fail');
const pill = (text, result) => `<span class="summary-pill ${pillClass(result)}">${esc(text)}</span>`;
const row = (label, value, cls = '') => value || value === 0 ? `<div class="info-row ${cls}"><span class="info-label">${esc(label)}</span><span class="info-value">${value}</span></div>` : '';
const addr = a => a ? (a.name ? `${esc(a.name)} <span class="muted">&lt;${esc(a.address)}&gt;</span>` : esc(a.address)) : '';
const time = iso => iso ? `${esc(new Date(iso).toLocaleString())}` : '';
function delay(s) {
  if (s == null) return '';
  const neg = s < 0, a = Math.abs(s);
  const txt = a < 60 ? `${a}s` : a < 3600 ? `${Math.floor(a / 60)}m ${String(a % 60).padStart(2, '0')}s` : `${Math.floor(a / 3600)}h ${String(Math.floor(a % 3600 / 60)).padStart(2, '0')}m`;
  return neg ? `<span class="fail">−${txt}</span>` : a > 3600 ? `<span class="warn">+${txt}</span>` : `+${txt}`;
}
const notes = list => list && list.length ? `<ul class="notes">${list.map(n => `<li>${esc(n)}</li>`).join('')}</ul>` : '';

// ------------------------------------------------------------------ render
function render(r) {
  $('results').innerHTML = `<div class="results">${[renderVerdict(r), renderFlags(r), renderMessage(r), renderAuth(r), renderPath(r),
    renderSenderIp(r), renderVendors(r), renderHeaders(r)].join('')}</div>`;
  const f = $('hdrFilter');
  if (f) f.oninput = () => {
    const q = f.value.toLowerCase();
    document.querySelectorAll('#hdrTable tr[data-s]').forEach(tr => { tr.style.display = tr.dataset.s.includes(q) ? '' : 'none'; });
  };
}

function renderVerdict(r) {
  const counts = ['high', 'medium', 'low'].map(l => [l, r.flags.filter(f => f.level === l).length]).filter(([, n]) => n);
  const top = r.authResults.find(a => a.trusted);
  const reported = top ? top.results.filter(x => ['spf', 'dkim', 'dmarc', 'compauth', 'arc'].includes(x.method)).map(x => pill(`${x.method.toUpperCase()}: ${x.result}`, x.result)).join('') : pill('No receiver auth results', 'none');
  let checked = '';
  if (r.live) {
    const d = r.live.dkim;
    const dk = d.length ? (d.some(x => x.result.startsWith('pass')) ? 'pass' : d[0].result) : 'none';
    checked = [pill(`DKIM: ${dk}`, dk), pill(`SPF: ${r.live.spf.result}`, r.live.spf.result), pill(`DMARC: ${r.live.dmarc.result}`, r.live.dmarc.result),
      r.live.bimi.found ? (r.live.dmarc.result === 'pass' ? pill('BIMI', r.live.bimi.logo?.dataUri ? 'pass' : 'softfail') : pill('BIMI: logo not earned (DMARC failed)', 'fail')) : ''].join('');
  }
  const src = { paste: 'Pasted headers', eml: '.eml file', msg: 'Outlook .msg file' }[r.source.kind] + (r.source.hasBody ? ' (full message)' : ' (headers only)');
  return `<div class="card"><div class="verdict"><span class="verdict-badge verdict-${r.verdict.level}">${esc(r.verdict.label)}</span>
    <div class="summary-bar">${counts.map(([l, n]) => pill(`${n} ${l}`, l === 'high' ? 'fail' : l)).join('') || pill('0 issues', 'pass')}</div></div>
    <div class="sub-title">Reported by receiving server${top ? ` (${esc(top.authserv)})` : ''}</div><div class="summary-bar">${reported}</div>
    ${r.live ? `<div class="sub-title">Re-checked now</div><div class="summary-bar">${checked}</div>${compliance(r)}` : ''}
    <p class="notes" style="margin-top:12px">${esc(src)} · ${r.source.headerCount} headers · ${r.hops.length} hops${r.totalSeconds != null ? ` · delivered in ${delay(r.totalSeconds).replace(/^\+/, '')}` : ''}</p></div>`;
}

// DMARC needs SPF or DKIM to both pass (authenticated) and match the From domain (aligned).
function compliance(r) {
  const c = r.live.dmarc.checks;
  const cell = (label, ok, hint) => `<div class="check ${ok ? 'ok' : 'bad'}" title="${esc(hint)}"><span>${ok ? '✅' : '❌'}</span>${esc(label)}</div>`;
  const dm = r.live.dmarc.result;
  return `<div class="sub-title">DMARC compliance</div><div class="check-grid">
    ${cell(`DMARC ${dm === 'pass' ? 'compliant' : dm === 'none' ? 'not published' : 'not compliant'}`, dm === 'pass', r.live.dmarc.detail)}
    ${cell('SPF authenticated', c.spfAuthenticated, 'The sending IP is allowed by the envelope domain\'s SPF record')}
    ${cell('SPF aligned', c.spfAligned, 'The envelope (Return-Path) domain matches the From domain')}
    ${cell('DKIM authenticated', c.dkimAuthenticated, 'At least one DKIM signature verifies')}
    ${cell('DKIM aligned', c.dkimAligned, 'A DKIM signature\'s d= domain matches the From domain')}</div>`;
}

function renderFlags(r) {
  if (!r.flags.length) return `<div class="card"><div class="card-title">Red flags</div><p class="muted" style="margin-top:10px">Nothing suspicious found in these headers. That doesn't prove the message is safe - check links and attachments too.</p></div>`;
  return `<div class="card"><div class="card-header"><span class="card-title">Red flags</span></div>${r.flags.map(f =>
    `<div class="flag ${f.level}"><div class="flag-title"><span class="flag-level ${f.level}">${esc(f.level)}</span>${esc(f.title)}</div><div class="flag-detail">${esc(f.detail)}</div></div>`).join('')}</div>`;
}

function renderMessage(r) {
  const s = r.summary;
  return `<div class="card"><div class="card-header"><span class="card-title">Message</span></div><div class="info-grid">
    ${row('From', addr(s.from), 'full-width')}
    ${row('Subject', esc(s.subject), 'full-width')}
    ${row('To', s.to.map(addr).join(', '))}
    ${row('Cc', s.cc.map(addr).join(', '))}
    ${row('Reply-To', s.replyTo.map(addr).join(', '))}
    ${row('Return-Path (envelope sender)', esc(r.envelopeFrom))}
    ${row('Date', s.date ? `${time(s.date)} <span class="muted">(${esc(s.dateRaw)})</span>` : esc(s.dateRaw))}
    ${row('Message-ID', `<span class="mono">${esc(s.messageId)}</span>`)}
    ${row('Sender IP', r.senderIp ? `${esc(r.senderIp)} <span class="muted">- from ${esc(r.senderIpSource)}</span>` : '')}
    ${row('HELO name', esc(r.helo))}
    ${row("Sender's client IP (X-Originating-IP)", esc(s.originatingIp))}
    ${row('Mail software', esc(s.mailer))}
    ${row('Sender header', addr(s.sender))}
    ${row('List-Unsubscribe', esc(s.listUnsubscribe), 'full-width')}
  </div></div>`;
}

function authBlock(a) {
  return a.results.map(x => `<div class="auth-row"><span class="auth-method">${esc(x.method)}</span><span>${pill(x.result, x.result)}</span>
    <span class="muted">${Object.entries(x.props).map(([k, v]) => `${esc(k)}=<span style="color:#e6edf3">${esc(v)}</span>`).join(' · ')}${x.comment ? `<br>${esc(x.comment)}` : ''}</span></div>`).join('');
}

function renderAuth(r) {
  let html = `<div class="card"><div class="card-header"><span class="card-title">Authentication</span></div>`;
  html += `<div class="sub-title">Reported by receiving servers</div>`;
  html += r.authResults.length ? r.authResults.map(a => `<div class="muted" style="font-size:0.8rem;margin:8px 0 6px">${esc(a.authserv)}${a.trusted ? ''
    : ' <span class="summary-pill pill-fail">forged by the sender - ignored</span>'}</div>${authBlock(a)}`).join('') : '<p class="muted">No Authentication-Results header.</p>';
  if (r.arc) html += `<p class="notes">ARC chain: ${r.arc.sets} set(s) - ${r.arc.chain.map(c => `i=${esc(c.i)} ${esc(c.domain)} cv=${esc(c.cv)}`).join(', ')}</p>`;

  if (!r.live) {
    html += `<div class="sub-title">Re-checked now</div><p class="muted">Live DNS checks are off - tick "Live DNS checks" to verify DKIM, SPF, DMARC and BIMI yourself.</p>`;
    if (r.dkimSignatures.length) html += `<div class="sub-title">DKIM signatures</div>${r.dkimSignatures.map(d => `<div class="auth-row"><span class="auth-method">DKIM</span><span>${pill('not checked', 'none')}</span><span class="muted">d=${esc(d.domain)} · s=${esc(d.selector)} · a=${esc(d.algorithm)}</span></div>`).join('')}`;
    return html + renderBimi(r) + '</div>';
  }
  const L = r.live;
  html += `<div class="sub-title">Re-checked now (current DNS)</div>`;
  html += L.dkim.length ? L.dkim.map(d => `<div class="auth-row"><span class="auth-method">DKIM</span><span>${pill(d.result, d.result)}</span><span>
      <span class="muted">d=</span>${esc(d.domain)} <span class="muted">· s=</span>${esc(d.selector)} <span class="muted">· a=</span>${esc(d.algorithm)} <span class="muted">· c=</span>${esc(d.canonicalization)}${d.keyBits ? ` <span class="muted">· key</span> ${d.keyBits} bits` : ''}
      <div class="notes">${esc(d.detail)}</div>${notes(d.notes)}
      <div class="notes">Signed headers: ${esc(d.signedHeaders.join(', '))}</div></span></div>`).join('')
    : `<div class="auth-row"><span class="auth-method">DKIM</span><span>${pill('none', 'none')}</span><span class="muted">The message has no DKIM signature.</span></div>`;
  html += `<div class="auth-row"><span class="auth-method">SPF</span><span>${pill(L.spf.result, L.spf.result)}</span><span>
    ${L.spf.ip ? `${esc(L.spf.ip)} <span class="muted">sending for</span> ${esc(L.spf.domain)}` : ''}<div class="notes">${esc(L.spf.comment || '')}</div>
    ${L.spf.record ? `<div class="record-box">${esc(L.spf.record)}</div>` : ''}</span></div>`;
  const dm = L.dmarcRecord;
  html += `<div class="auth-row"><span class="auth-method">DMARC</span><span>${pill(L.dmarc.result, L.dmarc.result)}</span><span>
    ${dm.found ? `<span class="muted">policy</span> ${esc(dm.policy)} <span class="muted">· pct</span> ${esc(dm.pct)} <span class="muted">· alignment</span> dkim=${dm.adkim === 's' ? 'strict' : 'relaxed'}, spf=${dm.aspf === 's' ? 'strict' : 'relaxed'}${dm.at !== r.summary.from?.domain ? ` <span class="muted">(record inherited from ${esc(dm.at)})</span>` : ''}` : ''}
    <div class="notes">${esc(L.dmarc.detail)}${L.dmarc.headersOnlyDkim ? ' (DKIM verified on headers only)' : ''}</div>
    ${dm.found ? `<div class="record-box">${esc(dm.record)}</div>` : ''}</span></div>`;
  return html + renderBimi(r) + '</div>';
}

function renderBimi(r) {
  const b = r.live?.bimi;
  const indicator = r.bimiIndicator;
  if (!b && !indicator) return '';
  let html = `<div class="sub-title">BIMI (brand logo)</div>`;
  if (b && !b.found && !indicator) return html + `<p class="muted">${esc(b.error)}.</p>`;
  const src = indicator || b?.logo?.dataUri;
  const logo = src ? `<img src="${esc(src)}" alt="BIMI logo">` : `<div class="no-logo">${esc(b?.logo?.error || 'no logo')}</div>`;
  // The logo belongs to the domain the message *claims* to be from - only meaningful if DMARC passed.
  if (r.live && r.live.dmarc.result !== 'pass' && b?.found && !indicator) {
    html += `<div class="flag high" style="margin-bottom:10px"><div class="flag-title">⚠️ This logo does not vouch for this message</div>
      <div class="flag-detail">The logo below belongs to ${esc(b.at)}, the domain in the From address. This message failed DMARC, so real mail clients would not show it - it may be impersonating ${esc(b.at)}.</div></div>`;
  }
  html += `<div class="bimi">${logo}<div style="min-width:0;flex:1">`;
  if (indicator) html += `<p>${pill('Logo validated by receiving server', 'pass')} <span class="muted" style="font-size:0.8rem">(from the BIMI-Indicator header)</span></p>`;
  if (b?.found) {
    html += `<div class="info-grid" style="margin-top:8px">${row('Record', `<span class="mono">${esc(b.selector)}._bimi.${esc(b.at)}</span>`)}
      ${row('Eligible (DMARC enforced)', b.dmarcEligible ? '<span class="pass">Yes</span>' : '<span class="fail">No</span>')}
      ${row('Logo URL (l=)', esc(b.logoUrl || 'not set'), 'full-width')}
      ${row('Certificate (a=)', esc(b.authorityUrl || 'not set'), 'full-width')}</div>${notes(b.notes)}
      <div class="record-box">${esc(b.record)}</div>`;
  } else if (b) html += `<p class="muted">${esc(b.error)}.</p>`;
  return html + '</div></div>';
}

function hopRbl(r, ip) {
  const list = r.live?.hopRbl?.[ip];
  if (!list) return '<span class="muted">-</span>';
  const listed = list.filter(x => x.status === 'listed');
  if (listed.length) return `<span class="fail" title="${esc(listed.map(x => x.zone).join(', '))}">LISTED (${listed.length})</span>`;
  return list.some(x => x.status === 'clean') ? '<span class="pass">Clean</span>' : '<span class="warn" title="Lookups were refused or failed">Unknown</span>';
}

function renderPath(r) {
  if (!r.hops.length) return '';
  const maxDelay = Math.max(1, ...r.hops.map(h => Math.abs(h.delaySeconds || 0)));
  const bar = s => s == null ? '' : `<div class="delay-bar ${s < 0 ? 'neg' : s > 3600 ? 'slow' : ''}" style="width:${Math.max(3, Math.round(Math.abs(s) / maxDelay * 100))}%"></div>`;
  const rows = r.hops.map(h => {
    const tags = [h.senderIp ? '<span class="tag sender">sender IP</span>' : '', h.privateIp ? '<span class="tag">private</span>' : '',
      h.authenticated ? '<span class="tag auth">authenticated</span>' : '',
      h.entry ? '<span class="tag" title="Everything below this hop was written before the message reached the recipient\'s mail system">entered recipient\'s system</span>' : '',
      h.crossTenant ? '<span class="tag" title="Handed from the sending Microsoft 365 tenant to the recipient\'s tenant">Microsoft cross-tenant</span>' : ''].join('');
    const from = [h.helo && `<span class="mono">${esc(h.helo)}</span>`, h.rdns && h.rdns !== h.helo && `<span class="muted">rDNS</span> ${esc(h.rdns)}`, h.ip && `<span class="mono">${esc(h.ip)}</span>`].filter(Boolean).join('<br>');
    const proto = h.protocol ? esc(h.protocol) : '';
    const tls = h.ip || h.protocol ? (h.tls ? `<span class="tag tls">🔒 ${esc(h.tlsVersion || 'TLS')}</span>` : (h.ip && !h.privateIp ? '<span class="tag notls">no TLS shown</span>' : '')) : '';
    return `<tr class="${h.senderIp ? 'sender-row' : ''}" title="${esc(h.raw)}"><td>${h.number}</td><td>${time(h.date) || `<span class="muted">${esc(h.dateRaw)}</span>`}</td><td style="min-width:70px">${delay(h.delaySeconds)}${bar(h.delaySeconds)}</td>
      <td>${from || '<span class="muted">-</span>'}${tags ? '<br>' + tags : ''}</td><td class="mono">${esc(h.by || '')}</td><td>${proto}${proto && tls ? '<br>' : ''}${tls}</td>
      ${r.live ? `<td>${h.ip && !h.privateIp ? hopRbl(r, h.ip) : '<span class="muted">-</span>'}</td>` : ''}</tr>`;
  }).join('');
  return `<div class="card"><div class="card-header"><span class="card-title">Delivery path</span><span class="muted" style="font-size:0.8rem">oldest first · hover a row for the raw header</span></div>
    <table><tr><th>#</th><th>Time</th><th>Delay</th><th>From</th><th>By</th><th>With</th>${r.live ? '<th>Blocklist</th>' : ''}</tr>${rows}</table></div>`;
}

function renderSenderIp(r) {
  const s = r.live?.senderIp;
  if (!s) return '';
  const rbl = s.rbl.length ? `<div class="sub-title">Blocklists</div><div class="rbl-grid">${s.rbl.map(x => `<div class="rbl-item"><span class="muted">${esc(x.zone)}</span>${
    { listed: '<span class="fail">LISTED</span>', clean: '<span class="pass">Clean</span>', refused: '<span class="warn" title="The blocklist refused the query (common with public DNS resolvers)">Refused</span>', error: '<span class="muted">Error</span>' }[x.status]}</div>`).join('')}</div>`
    : '<p class="notes">Blocklist checks run for IPv4 addresses only.</p>';
  return `<div class="card"><div class="card-header"><span class="card-title">Sender IP - ${esc(s.ip)}</span></div><div class="info-grid">
    ${row('Reverse DNS (PTR)', s.ptr ? esc(s.ptr) : '<span class="warn">none</span>')}
    ${row('Forward-confirmed', s.ptr ? (s.confirmed ? '<span class="pass">Yes</span>' : '<span class="warn">No</span>') : '-')}</div>${rbl}</div>`;
}

function renderVendors(r) {
  if (!r.vendors.length) return '';
  return `<div class="card"><div class="card-header"><span class="card-title">Spam filter verdicts</span></div>${r.vendors.map(g => `<div class="sub-title">${esc(g.source)}</div>
    <table>${g.items.map(i => `<tr><td style="width:30%" class="muted">${esc(i.label)}</td><td style="width:25%" class="mono">${esc(i.value)}</td><td class="${esc(i.level)}" style="font-weight:400">${esc(i.meaning)}</td></tr>`).join('')}</table>`).join('')}</div>`;
}

function renderHeaders(r) {
  return `<div class="card"><details><summary>All headers (${r.headers.length})</summary>
    <input class="filter" id="hdrFilter" placeholder="Filter headers...">
    <table id="hdrTable">${r.headers.map(h => `<tr data-s="${esc((h.name + ' ' + h.value).toLowerCase())}"><td style="width:24%" class="mono">${esc(h.name)}</td><td class="mono">${esc(h.value)}</td></tr>`).join('')}</table>
  </details></div>`;
}
