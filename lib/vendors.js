// Decoders for spam/security headers added by common mail filters.
const { toDisplay } = require('./parse');

const SFV = {
  BLK: ['Blocked sender list', 'high'], NSPM: ['Not spam', 'ok'], SFE: ['Safe sender list', 'info'],
  SKA: ['Allowed by an allow list', 'info'], SKB: ['Blocked by a block list', 'high'], SKI: ['Internal (intra-org) message', 'info'],
  SKN: ['Skipped filtering (mail flow rule set SCL -1)', 'medium'], SKQ: ['Released from quarantine', 'medium'],
  SKS: ['Marked as spam by a mail flow rule', 'high'], SPM: ['Spam', 'high'],
};
const CAT = {
  NONE: ['No threat category', 'ok'], AMP: ['Anti-malware policy', 'high'], BIMP: ['Brand impersonation', 'high'],
  BULK: ['Bulk mail', 'medium'], DIMP: ['Domain impersonation', 'high'], FTBP: ['Blocked file type', 'high'],
  GIMP: ['Mailbox intelligence impersonation', 'high'], HPHSH: ['High-confidence phishing', 'high'], HPHISH: ['High-confidence phishing', 'high'],
  HSPM: ['High-confidence spam', 'high'], INTOS: ['Intra-organization phishing', 'high'], MALW: ['Malware', 'high'],
  OSPM: ['Outbound spam', 'high'], PHSH: ['Phishing', 'high'], SAP: ['Safe Attachments policy', 'high'],
  SPM: ['Spam', 'high'], SPOOF: ['Spoofing', 'high'], UIMP: ['User impersonation', 'high'],
};
const IPV = { CAL: ['Allowed by IP allow list', 'info'], NLI: ['IP not on any reputation list', 'ok'] };

function sclMeaning(n) {
  if (n === -1) return ['Filtering skipped (trusted or allow-listed)', 'medium'];
  if (n <= 1) return ['Not spam', 'ok'];
  if (n <= 4) return ['Low spam likelihood', 'low'];
  if (n <= 6) return ['Spam', 'high'];
  return ['High-confidence spam', 'high'];
}

function bclMeaning(n) {
  if (n === 0) return ['Not bulk mail', 'ok'];
  if (n <= 3) return ['Bulk sender with few complaints', 'info'];
  if (n <= 7) return ['Bulk sender with a mix of complaints', 'low'];
  return ['Bulk sender with many complaints', 'medium'];
}

function kvList(value, sep = ';', kvSep = ':') {
  const out = {};
  for (const part of value.split(sep)) {
    const i = part.indexOf(kvSep);
    if (i > 0) out[part.slice(0, i).trim().toUpperCase()] = part.slice(i + 1).trim();
  }
  return out;
}

function decodeVendors(headers) {
  const get = name => headers.filter(h => h.name.toLowerCase() === name).map(h => toDisplay(h.value));
  const groups = [];

  // ---- Microsoft 365 / Exchange Online Protection
  const ms = [];
  for (const v of get('x-forefront-antispam-report')) {
    const kv = kvList(v);
    if (kv.SFV) { const [m, l] = SFV[kv.SFV] || ['Unknown verdict', 'info']; ms.push({ label: 'Spam verdict (SFV)', value: kv.SFV, meaning: m, level: l }); }
    if (kv.CAT) { const [m, l] = CAT[kv.CAT] || ['Unknown category', 'info']; ms.push({ label: 'Category (CAT)', value: kv.CAT, meaning: m, level: l }); }
    if (kv.SCL) { const n = Number(kv.SCL); const [m, l] = sclMeaning(n); ms.push({ label: 'Spam confidence (SCL)', value: kv.SCL, meaning: m, level: l }); }
    if (kv.IPV) { const [m, l] = IPV[kv.IPV] || ['', 'info']; ms.push({ label: 'IP reputation (IPV)', value: kv.IPV, meaning: m, level: l }); }
    if (kv.CIP) ms.push({ label: 'Connecting IP (CIP)', value: kv.CIP, meaning: 'IP that connected to Microsoft', level: 'info' });
    if (kv.CTRY) ms.push({ label: 'Source country (CTRY)', value: kv.CTRY, meaning: 'Country of the connecting IP', level: 'info' });
    if (kv.PTR) ms.push({ label: 'Reverse DNS (PTR)', value: kv.PTR, meaning: '', level: 'info' });
    if (kv.H) ms.push({ label: 'HELO name (H)', value: kv.H, meaning: '', level: 'info' });
    if (kv.SFTY) ms.push({ label: 'Safety tip (SFTY)', value: kv.SFTY, meaning: kv.SFTY.startsWith('9.25') ? 'First contact / impersonation safety tip' : 'Safety tip applied', level: 'medium' });
    if (kv.DIR) ms.push({ label: 'Direction (DIR)', value: kv.DIR, meaning: { INB: 'Inbound', OUT: 'Outbound', INT: 'Internal' }[kv.DIR] || '', level: 'info' });
  }
  for (const v of get('x-microsoft-antispam')) {
    const kv = kvList(v);
    if (kv.BCL) { const n = Number(kv.BCL); const [m, l] = bclMeaning(n); ms.push({ label: 'Bulk complaint level (BCL)', value: kv.BCL, meaning: m, level: l }); }
  }
  for (const v of get('x-ms-exchange-organization-scl')) {
    const [m, l] = sclMeaning(Number(v));
    ms.push({ label: 'Organization SCL', value: v, meaning: m, level: l });
  }
  for (const v of get('x-ms-exchange-organization-authas')) {
    ms.push({ label: 'Authenticated as', value: v, meaning: { Anonymous: 'Sent from outside the organization', Internal: 'Sent from inside the organization', Partner: 'Partner connector' }[v] || '', level: 'info' });
  }
  if (ms.length) groups.push({ source: 'Microsoft 365 / Exchange Online Protection', items: ms });

  // ---- SpamAssassin and compatible
  const sa = [];
  for (const v of get('x-spam-status')) {
    const yes = /^\s*yes/i.test(v);
    const score = (v.match(/score=(-?[\d.]+)/) || [])[1];
    const req = (v.match(/required=(-?[\d.]+)/) || [])[1];
    const tests = (v.match(/tests=([^\s]+(?:\s*,\s*[^\s]+)*)/) || [])[1];
    sa.push({ label: 'Spam status', value: yes ? 'Yes' : 'No', meaning: score ? `score ${score}${req ? ` (threshold ${req})` : ''}` : '', level: yes ? 'high' : 'ok' });
    if (tests) sa.push({ label: 'Rules matched', value: tests.replace(/\s+/g, ''), meaning: '', level: 'info' });
  }
  for (const v of get('x-spam-flag')) sa.push({ label: 'Spam flag', value: v, meaning: '', level: /yes/i.test(v) ? 'high' : 'ok' });
  for (const v of get('x-spam-score')) sa.push({ label: 'Spam score', value: v, meaning: '', level: Number(v) >= 5 ? 'high' : 'info' });
  if (sa.length) groups.push({ source: 'SpamAssassin', items: sa });

  // ---- Proofpoint
  const pp = [];
  for (const v of get('x-proofpoint-spam-details')) {
    for (const k of ['spamscore', 'phishscore', 'malwarescore', 'suspectscore', 'bulkscore', 'adultscore']) {
      const m = v.match(new RegExp(`\\b${k}=(\\d+)`));
      if (m) pp.push({ label: k, value: m[1], meaning: 'score 0-100', level: Number(m[1]) >= 80 ? 'high' : Number(m[1]) >= 50 ? 'medium' : 'ok' });
    }
    const rule = (v.match(/\brule=(\S+)/) || [])[1];
    if (rule) pp.push({ label: 'Rule', value: rule, meaning: '', level: /spam|phish|malware|quarantine/i.test(rule) ? 'high' : 'info' });
  }
  if (pp.length) groups.push({ source: 'Proofpoint', items: pp });

  // ---- Mimecast / Barracuda
  const other = [];
  for (const v of get('x-mimecast-spam-score')) other.push({ label: 'Mimecast spam score', value: v, meaning: '', level: Number(v) >= 5 ? 'medium' : 'info' });
  for (const v of get('x-barracuda-spam-score')) other.push({ label: 'Barracuda spam score', value: v, meaning: '', level: Number(v) >= 5 ? 'medium' : 'info' });
  for (const v of get('x-barracuda-spam-status')) other.push({ label: 'Barracuda spam status', value: v, meaning: '', level: /yes|tag|quarantine/i.test(v) ? 'medium' : 'info' });
  if (other.length) groups.push({ source: 'Other filters', items: other });

  return groups;
}

module.exports = { decodeVendors };
