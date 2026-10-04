// Parsing of raw message headers into structured data.
//
// All raw text is handled as a "byte string" (latin1: one char per byte) so DKIM can hash the exact
// bytes of the message. Use toDisplay() before showing a value to the user.
const net = require('net');

// Split a raw message (or a pasted header block) into header text and body.
function splitMessage(raw) {
  const text = raw.replace(/^\xEF\xBB\xBF/, '').replace(/\r\n?/g, '\n').replace(/^\s*\n/, '');
  const m = text.match(/\n[ \t]*\n/);
  if (!m) return { headerText: text.trimEnd(), body: null };
  return { headerText: text.slice(0, m.index), body: text.slice(m.index + m[0].length) };
}

// Parse the header block into [{ name, value, raw, index }], preserving the original folding in `raw`.
function parseHeaders(headerText) {
  const headers = [];
  let cur = null;
  for (const line of headerText.split('\n')) {
    if (/^[ \t]/.test(line) && cur) {
      cur.lines.push(line);
      continue;
    }
    const m = line.match(/^([!-9;-~]+)[ \t]*:/);
    if (m) {
      cur = { name: m[1], lines: [line] };
      headers.push(cur);
    } else if (line.trim() && cur) {
      cur.lines.push(line); // malformed continuation line; keep it with the previous header
    }
    // anything before the first header (e.g. "Microsoft Mail Internet Headers Version 2.0") is ignored
  }
  return headers.map((h, index) => {
    const raw = h.lines.join('\r\n');
    const value = raw.slice(raw.indexOf(':') + 1).replace(/\r\n(?=[ \t])/g, '').replace(/\r\n/g, ' ').trim();
    return { name: h.name, value, raw, index };
  });
}

// Bytes -> readable text (UTF-8 if valid, else Windows-1252), then decode RFC 2047 encoded-words.
function toDisplay(byteString) {
  if (byteString == null) return '';
  const buf = Buffer.from(byteString, 'latin1');
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    text = new TextDecoder('windows-1252').decode(buf);
  }
  return decodeWords(text);
}

function decodeWords(str) {
  return str
    .replace(/(=\?[^?\s]+\?[BbQq]\?[^?\s]*\?=)\s+(?==\?[^?\s]+\?[BbQq]\?)/g, '$1') // adjacent words join without the space
    .replace(/=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g, (all, charset, enc, data) => {
      try {
        const bytes = enc.toUpperCase() === 'B'
          ? Buffer.from(data, 'base64')
          : Buffer.from(data.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))), 'latin1');
        return new TextDecoder(charset.split('*')[0].toLowerCase()).decode(bytes);
      } catch {
        return all;
      }
    });
}

// Split on a separator character, ignoring separators inside quotes, (comments) and <angle brackets>.
function splitOutside(str, sep) {
  const out = [];
  let depth = 0, angle = 0, quoted = false, cur = '';
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (quoted) {
      if (c === '\\') { cur += c + (str[++i] || ''); continue; }
      if (c === '"') quoted = false;
    } else if (c === '"') quoted = true;
    else if (c === '(') depth++;
    else if (c === ')' && depth) depth--;
    else if (c === '<') angle++;
    else if (c === '>' && angle) angle--;
    else if (c === sep && !depth && !angle) { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  out.push(cur);
  return out.map(s => s.trim()).filter(Boolean);
}

function parseAddress(value) {
  if (!value) return null;
  const v = toDisplay(value).trim();
  let name = '', address = '';
  const angle = v.match(/^(.*?)<([^<>]*)>\s*(?:\(.*\))?$/s);
  if (angle) {
    name = angle[1].trim();
    address = angle[2].trim();
  } else {
    const m = v.match(/^([^\s()]+@[^\s()]+)\s*(?:\((.*)\))?$/);
    address = m ? m[1] : v;
    name = m && m[2] ? m[2] : '';
  }
  name = name.replace(/^"(.*)"$/s, '$1').replace(/\\(.)/g, '$1').trim();
  const at = address.lastIndexOf('@');
  const domain = at > 0 ? address.slice(at + 1).toLowerCase().replace(/[>.\s]+$/, '') : '';
  return { name, address, domain, display: v };
}

function parseAddressList(value) {
  if (!value) return [];
  return splitOutside(value, ',').map(parseAddress).filter(Boolean);
}

function parseDate(str) {
  if (!str) return null;
  const clean = str.replace(/\([^)]*\)/g, ' ').replace(/\s+/g, ' ').trim();
  const t = Date.parse(clean);
  return Number.isNaN(t) ? null : new Date(t);
}

// ------------------------------------------------------------------ IP helpers

const PRIVATE = new net.BlockList();
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
                      ['172.16.0.0', 12], ['192.168.0.0', 16], ['198.18.0.0', 15]]) PRIVATE.addSubnet(a, p, 'ipv4');
for (const [a, p] of [['::1', 128], ['fc00::', 7], ['fe80::', 10], ['::', 128]]) PRIVATE.addSubnet(a, p, 'ipv6');

function ipKind(ip) {
  const v = net.isIP(ip);
  return v === 4 ? 'ipv4' : v === 6 ? 'ipv6' : null;
}

function isPrivateIp(ip) {
  const kind = ipKind(ip);
  if (!kind) return false;
  const mapped = kind === 'ipv6' && ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  return mapped ? PRIVATE.check(mapped[1], 'ipv4') : PRIVATE.check(ip, kind);
}

function findIps(text) {
  const found = [];
  for (const m of text.matchAll(/\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]|\b(\d{1,3}(?:\.\d{1,3}){3})\b|((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:\d+\.\d+\.\d+\.\d+)?)/g)) {
    const ip = m[1] || m[2] || m[3];
    if (ip && ipKind(ip) && !found.includes(ip)) found.push(ip);
  }
  return found;
}

// ------------------------------------------------------------------ Received

function parseReceived(header) {
  const v = header.value.replace(/\s+/g, ' ').trim();
  const semi = v.lastIndexOf(';');
  const main = semi >= 0 ? v.slice(0, semi) : v;
  const dateRaw = semi >= 0 ? v.slice(semi + 1).trim() : '';

  const fromM = main.match(/\bfrom\s+(\S+)((?:\s*\((?:[^()]|\([^()]*\))*\))*)/i);
  const byM = main.match(/\bby\s+(\S+)/i);
  const fromPart = fromM ? fromM[0] : '';
  const comment = fromM ? fromM[2].trim().replace(/^\(|\)$/g, '') : '';
  const ips = findIps(fromPart);
  const ip = ips.find(i => !isPrivateIp(i)) || ips[0] || null;
  const rdnsM = comment.match(/^([A-Za-z0-9.-]+\.[A-Za-z]{2,}|unknown)\b/i);

  let protocol = null;
  if (/\bwith Microsoft SMTP Server\b/i.test(main)) protocol = 'Microsoft SMTP Server';
  else {
    const w = main.match(/\bwith\s+([A-Za-z0-9-]+)/i);
    if (w) protocol = w[1];
  }
  const tlsVer = main.match(/\b(TLS ?v?1[._]?[0-3]|TLSv1(?:\.[0-3])?|SSLv3)\b/i) || main.match(/version=(TLS[0-9_.]+)/i);
  const tls = !!tlsVer || /\b(ESMTPS|ESMTPSA|UTF8SMTPS|UTF8SMTPSA|LMTPS)\b/.test(main) || /cipher=/i.test(main);

  return {
    raw: toDisplay(header.value),
    headerIndex: header.index,
    helo: fromM ? toDisplay(fromM[1]) : null,
    rdns: rdnsM && rdnsM[1].toLowerCase() !== 'unknown' ? rdnsM[1].toLowerCase().replace(/\.$/, '') : null,
    // Whether the receiver wrote a reverse-DNS field at all ("unknown" counts). The HELO name, by
    // contrast, is chosen by the connecting client and can't be trusted.
    rdnsRecorded: !!rdnsM,
    ip,
    privateIp: ip ? isPrivateIp(ip) : null,
    by: byM ? toDisplay(byM[1]) : null,
    protocol,
    tls,
    tlsVersion: tlsVer ? tlsVer[1].replace(/_/g, '.') : null,
    authenticated: /\b(ESMTPSA|ESMTPA|UTF8SMTPSA)\b|\bauthenticated\b/i.test(main),
    id: (main.match(/\bid\s+<?([^\s;>]+)/i) || [])[1] || null,
    for: (main.match(/\bfor\s+<?([^\s>;]+@[^\s>;]+)>?/i) || [])[1] || null,
    date: parseDate(dateRaw),
    dateRaw,
  };
}

// ------------------------------------------------------------------ Authentication-Results

function parseAuthResults(header) {
  let value = toDisplay(header.value);
  const instance = (value.match(/^\s*i\s*=\s*(\d+)\s*;/) || [])[1]; // ARC-Authentication-Results
  if (instance) value = value.replace(/^\s*i\s*=\s*\d+\s*;/, '');
  const parts = splitOutside(value, ';');
  // Normally "authserv-id; method=result; ...", but Microsoft 365 omits the authserv-id entirely.
  const authserv = parts.length && !/^[a-z0-9-]+\s*=\s*[a-z]+\b/i.test(parts[0])
    ? parts.shift().split(/\s+/)[0]
    : (/sender IP is/i.test(value) ? 'Microsoft 365' : '(server not named)');
  const results = [];
  for (const p of parts) {
    const m = p.match(/^([a-z0-9-]+)\s*=\s*([a-z]+)\b/i);
    if (!m) continue;
    const comments = [...p.matchAll(/\(([^()]*)\)/g)].map(c => c[1].trim());
    const rest = p.slice(m[0].length).replace(/\([^()]*\)/g, ' ');
    const props = {};
    for (const pm of rest.matchAll(/([a-z][a-z0-9_.-]*)\s*=\s*("[^"]*"|[^\s;]+)/gi)) {
      props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, '');
    }
    results.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), props, comment: comments.join('; ') });
  }
  const senderIp = (value.match(/sender IP is ([0-9A-Fa-f.:]+)/i) || [])[1] || null;
  return { headerIndex: header.index, name: header.name, authserv, instance: instance ? Number(instance) : null, results, senderIp };
}

function parseReceivedSpf(header) {
  const v = toDisplay(header.value);
  const result = (v.match(/^\s*([a-z]+)/i) || [])[1];
  const props = {};
  for (const m of v.replace(/\([^)]*\)/g, ' ').matchAll(/([a-z][a-z-]*)\s*=\s*("[^"]*"|[^\s;]+)/gi)) {
    props[m[1].toLowerCase()] = m[2].replace(/^"|"$/g, '');
  }
  return { headerIndex: header.index, result: result ? result.toLowerCase() : null, props, comment: (v.match(/\(([^)]*)\)/) || [])[1] || '' };
}

// Canonical text form of an IP so "2001:DB8::1" and "2001:db8:0:0:0:0:0:1" compare equal.
function normalizeIp(ip) {
  if (!ip) return null;
  ip = ip.trim().replace(/^\[|\]$/g, '').replace(/^IPv6:/i, '');
  const kind = ipKind(ip);
  if (kind === 'ipv4') return ip;
  if (kind !== 'ipv6') return null;
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) return mapped[1];
  const [head, tail = ''] = ip.toLowerCase().split('::');
  const h = head ? head.split(':') : [];
  const t = ip.includes('::') && tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  return groups.map(g => parseInt(g, 16).toString(16)).join(':');
}

// DKIM-Signature / DKIM key tag lists: "k=v; k=v". Whitespace inside b/bh/p is folding and is removed.
function parseTags(value) {
  const tags = {};
  for (const part of value.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    let v = part.slice(i + 1).trim();
    if (['b', 'bh', 'p'].includes(k)) v = v.replace(/\s+/g, '');
    if (k) tags[k] = v;
  }
  return tags;
}

module.exports = {
  splitMessage, parseHeaders, toDisplay, decodeWords, splitOutside, parseAddress, parseAddressList,
  parseDate, ipKind, isPrivateIp, findIps, parseReceived, parseAuthResults, parseReceivedSpf, parseTags, normalizeIp,
};
