// Live checks that need the network: DKIM keys, SPF, DMARC, BIMI, reverse DNS and blocklists.
// Everything takes an injectable resolver so tests can run offline.
const dnsp = require('dns').promises;
const https = require('https');
const net = require('net');
const { getDomain } = require('tldts');
const { spf } = require('mailauth/lib/spf');
const dkim = require('./dkim');
const { parseTags, isPrivateIp, ipKind } = require('./parse');

const DNS_TIMEOUT_MS = 4000;

const RBLS = [
  'zen.spamhaus.org',
  'bl.spamcop.net',
  'b.barracudacentral.org',
  'psbl.surriel.com',
  'dnsbl-1.uceprotect.net',
  'bl.mailspike.net',
];

function makeResolver() {
  const r = new dnsp.Resolver({ timeout: DNS_TIMEOUT_MS, tries: 2 });
  return {
    resolveTxt: n => r.resolveTxt(n),
    resolve4: n => r.resolve4(n),
    resolve6: n => r.resolve6(n),
    reverse: ip => r.reverse(ip),
    resolve: (n, type) => r.resolve(n, type),
  };
}

const orgDomain = d => (d && getDomain(d, { allowPrivateDomains: false })) || d;

function aligned(a, b, mode) {
  if (!a || !b) return false;
  a = a.toLowerCase();
  b = b.toLowerCase();
  return mode === 's' ? a === b : orgDomain(a) === orgDomain(b);
}

async function txtRecord(resolver, name, prefix) {
  try {
    const recs = (await resolver.resolveTxt(name)).map(r => r.join(''));
    return recs.find(r => r.toLowerCase().startsWith(prefix.toLowerCase())) || null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ DMARC

async function lookupDmarc(fromDomain, resolver) {
  if (!fromDomain) return { found: false, error: 'no From domain' };
  let record = await txtRecord(resolver, `_dmarc.${fromDomain}`, 'v=DMARC1');
  let at = fromDomain;
  const org = orgDomain(fromDomain);
  if (!record && org && org !== fromDomain) {
    record = await txtRecord(resolver, `_dmarc.${org}`, 'v=DMARC1');
    at = org;
  }
  if (!record) return { found: false, error: `no DMARC record at _dmarc.${fromDomain}${org !== fromDomain ? ` or _dmarc.${org}` : ''}` };
  const t = parseTags(record);
  const isSub = at !== fromDomain;
  return {
    found: true, record, at,
    policy: (isSub && t.sp ? t.sp : t.p || 'none').toLowerCase(),
    pct: t.pct ? Number(t.pct) : 100,
    adkim: (t.adkim || 'r').toLowerCase(),
    aspf: (t.aspf || 'r').toLowerCase(),
    rua: t.rua || null,
  };
}

function evaluateDmarc(dmarc, fromDomain, dkimResults, spfResult, spfDomain) {
  const dkimPassing = dkimResults.filter(r => ['pass', 'pass-headers'].includes(r.result));
  const dkimAligned = dkimPassing.find(r => aligned(r.domain, fromDomain, dmarc.adkim));
  const spfAuthenticated = !!(spfResult && spfResult.result === 'pass');
  const spfAligned = spfAuthenticated && aligned(spfDomain, fromDomain, dmarc.aspf);
  // The four checks behind a DMARC verdict: each mechanism must both pass and match the From domain.
  const checks = {
    spfAuthenticated,
    spfAligned: aligned(spfDomain, fromDomain, dmarc.aspf),
    dkimAuthenticated: dkimPassing.length > 0,
    dkimAligned: dkimResults.some(r => aligned(r.domain, fromDomain, dmarc.adkim)),
  };
  if (!dmarc.found) return { result: 'none', detail: dmarc.error, checks };
  const pass = !!(dkimAligned || spfAligned);
  const via = [dkimAligned && `DKIM (d=${dkimAligned.domain})`, spfAligned && `SPF (${spfDomain})`].filter(Boolean);
  return {
    checks,
    result: pass ? 'pass' : 'fail',
    detail: pass
      ? `aligned via ${via.join(' and ')}`
      : `no aligned pass - DKIM ${dkimResults.length ? 'domains ' + dkimResults.map(r => `${r.domain}=${r.result}`).join(', ') : 'absent'}; SPF ${spfResult ? `${spfDomain}=${spfResult.result}` : 'not checked'}`,
    disposition: pass ? 'none' : dmarc.policy,
    headersOnlyDkim: !!(dkimAligned && dkimAligned.result === 'pass-headers'),
  };
}

// ------------------------------------------------------------------ BIMI

const MAX_LOGO_BYTES = 64 * 1024;

// Fetch the logo server-side so the browser never contacts the sender's server, and only accept a
// small SVG over HTTPS from a public address. It's shown in an <img>, where SVG can't run scripts.
function fetchLogo(url, timeoutMs = 5000) {
  return new Promise(resolve => {
    let u;
    try {
      u = new URL(url);
    } catch {
      return resolve({ error: 'logo URL is not valid' });
    }
    if (u.protocol !== 'https:') return resolve({ error: 'logo URL must use HTTPS' });
    const lookup = (host, opts, cb) => require('dns').lookup(host, opts, (err, addr, fam) => {
      if (err) return cb(err);
      const list = Array.isArray(addr) ? addr : [{ address: addr, family: fam }];
      if (list.some(a => isPrivateIp(a.address))) return cb(new Error('logo host resolves to a private address'));
      cb(null, addr, fam);
    });
    const req = https.get(u, { timeout: timeoutMs, lookup, headers: { Accept: 'image/svg+xml' } }, res => {
      if (res.statusCode !== 200) {
        res.resume();
        return resolve({ error: `logo server answered HTTP ${res.statusCode}` });
      }
      const chunks = [];
      let size = 0;
      res.on('data', c => {
        size += c.length;
        if (size > MAX_LOGO_BYTES) {
          req.destroy();
          resolve({ error: `logo is larger than ${MAX_LOGO_BYTES / 1024} KB` });
        } else chunks.push(c);
      });
      res.on('end', () => {
        if (size > MAX_LOGO_BYTES) return;
        const svg = Buffer.concat(chunks);
        const head = svg.subarray(0, 4096).toString('utf8');
        if (!/<svg[\s>]/i.test(head)) return resolve({ error: 'logo is not an SVG image' });
        const tiny = /baseProfile\s*=\s*["']tiny-ps["']/i.test(head);
        resolve({ dataUri: `data:image/svg+xml;base64,${svg.toString('base64')}`, bytes: size, svgTinyPs: tiny });
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ error: 'timed out fetching logo' }); });
    req.on('error', err => resolve({ error: `could not fetch logo (${err.message})` }));
  });
}

async function lookupBimi(fromDomain, selectorHeader, dmarc, resolver, fetcher = fetchLogo) {
  if (!fromDomain) return { found: false, error: 'no From domain' };
  const selector = ((selectorHeader || '').match(/\bs\s*=\s*([A-Za-z0-9_-]+)/) || [])[1] || 'default';
  const org = orgDomain(fromDomain);
  let at = fromDomain;
  let record = await txtRecord(resolver, `${selector}._bimi.${fromDomain}`, 'v=BIMI1');
  if (!record && org !== fromDomain) {
    record = await txtRecord(resolver, `${selector}._bimi.${org}`, 'v=BIMI1');
    at = org;
  }
  if (!record) return { found: false, selector, error: `no BIMI record at ${selector}._bimi.${fromDomain}` };
  const t = parseTags(record);
  const out = { found: true, selector, at, record, logoUrl: t.l || null, authorityUrl: t.a || null, notes: [] };
  if (!out.logoUrl) out.notes.push('Record has no logo URL (l= is empty) - the domain has opted out of BIMI.');
  if (!out.authorityUrl) out.notes.push('No certificate (a=) - Gmail and Apple Mail only show logos backed by a VMC or CMC certificate.');
  else out.notes.push('A mark certificate (VMC/CMC) is referenced; this tool does not validate the certificate chain.');
  const enforced = dmarc && dmarc.found && ['quarantine', 'reject'].includes(dmarc.policy) && dmarc.pct === 100;
  out.dmarcEligible = !!enforced;
  if (!enforced) out.notes.push('BIMI requires DMARC at p=quarantine or p=reject with pct=100; this domain does not qualify, so mail clients will not show the logo.');
  if (out.logoUrl) {
    out.logo = await fetcher(out.logoUrl);
    if (out.logo.dataUri && !out.logo.svgTinyPs) out.notes.push('Logo is not in the SVG Tiny PS profile that BIMI requires.');
  }
  return out;
}

// Receivers like Gmail store the logo they validated in a BIMI-Indicator header (base64 SVG).
function bimiIndicator(headers) {
  const h = headers.find(x => x.name.toLowerCase() === 'bimi-indicator');
  if (!h) return null;
  const b64 = h.value.replace(/\s+/g, '');
  const svg = Buffer.from(b64, 'base64').subarray(0, MAX_LOGO_BYTES + 1);
  if (svg.length > MAX_LOGO_BYTES || !/<svg[\s>]/i.test(svg.subarray(0, 4096).toString('utf8'))) return null;
  return `data:image/svg+xml;base64,${svg.toString('base64')}`;
}

// ------------------------------------------------------------------ sender IP

async function reverseDns(ip, resolver) {
  try {
    const names = await resolver.reverse(ip);
    const name = names[0];
    if (!name) return { ptr: null };
    let fwd = [];
    try {
      fwd = ipKind(ip) === 'ipv6' ? await resolver.resolve6(name) : await resolver.resolve4(name);
    } catch { /* no forward record */ }
    const norm = a => (net.isIPv6(a) ? a.toLowerCase() : a);
    return { ptr: name, confirmed: fwd.map(norm).includes(norm(ip)) };
  } catch {
    return { ptr: null };
  }
}

async function checkRbls(ip, resolver) {
  if (ipKind(ip) !== 'ipv4') return [];
  const rev = ip.split('.').reverse().join('.');
  return Promise.all(RBLS.map(async zone => {
    try {
      const answers = await resolver.resolve4(`${rev}.${zone}`);
      // 127.255.255.x is how Spamhaus refuses queries from public/open resolvers - not a listing
      const refused = answers.every(a => a.startsWith('127.255.255.') || !a.startsWith('127.'));
      return { zone, status: refused ? 'refused' : 'listed', answers };
    } catch (err) {
      return { zone, status: ['ENOTFOUND', 'ENODATA'].includes(err.code) ? 'clean' : 'error' };
    }
  }));
}

// ------------------------------------------------------------------ orchestration

async function runLiveChecks(ctx, resolver = makeResolver(), fetcher = fetchLogo) {
  const { headers, body, fromDomain, senderIp, envelopeFrom, helo, bimiSelectorHeader } = ctx;
  const out = {};

  const [dkimResults, dmarc] = await Promise.all([
    dkim.verifyAll(headers, body, n => resolver.resolveTxt(n)),
    lookupDmarc(fromDomain, resolver),
  ]);
  out.dkim = dkimResults;
  out.dmarcRecord = dmarc;

  const spfDomain = (envelopeFrom && envelopeFrom.includes('@') ? envelopeFrom.split('@').pop() : helo || '').toLowerCase();
  if (senderIp && (envelopeFrom || helo)) {
    try {
      const r = await spf({
        sender: envelopeFrom || undefined, ip: senderIp, helo: helo || undefined, mta: 'email-header-analyzer',
        resolver: (name, type) => resolver.resolve(name, type), maxElapsedTime: 15000,
      });
      out.spf = { result: r.status.result, domain: spfDomain, ip: senderIp, record: r.rr || null, comment: r.status.comment || null };
    } catch (err) {
      out.spf = { result: 'temperror', domain: spfDomain, ip: senderIp, comment: err.message };
    }
  } else {
    out.spf = { result: 'none', domain: spfDomain, comment: senderIp ? 'no envelope sender or HELO name found' : 'sender IP could not be determined from the headers' };
  }

  out.dmarc = evaluateDmarc(dmarc, fromDomain, dkimResults, out.spf, spfDomain);
  out.bimi = await lookupBimi(fromDomain, bimiSelectorHeader, dmarc, resolver, fetcher);

  // Blocklist status for every public IPv4 relay (capped so a long chain can't trigger hundreds of lookups).
  const relayIps = [...new Set([senderIp, ...(ctx.hopIps || [])].filter(ip => ip && ipKind(ip) === 'ipv4' && !isPrivateIp(ip)))].slice(0, 8);
  const rblByIp = Object.fromEntries(await Promise.all(relayIps.map(async ip => [ip, await checkRbls(ip, resolver)])));
  out.hopRbl = rblByIp;

  if (senderIp && !isPrivateIp(senderIp)) {
    const rdns = await reverseDns(senderIp, resolver);
    out.senderIp = { ip: senderIp, ...rdns, rbl: rblByIp[senderIp] || [] };
  }
  return out;
}

module.exports = { runLiveChecks, lookupDmarc, evaluateDmarc, lookupBimi, bimiIndicator, fetchLogo, checkRbls, orgDomain, aligned, makeResolver };
