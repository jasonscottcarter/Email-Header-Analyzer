// Turns a raw message / header block into the report the web page renders.
const url = require('url');
const P = require('./parse');
const { decodeVendors } = require('./vendors');
const live = require('./live');

const LEVELS = ['high', 'medium', 'low', 'info'];

function analyze(raw, opts = {}) {
  const { headerText, body } = P.splitMessage(raw);
  const headers = P.parseHeaders(headerText);
  if (!headers.length) throw new Error('No email headers found. Paste the full header block (starting with lines like "Received:" or "From:").');

  const all = name => headers.filter(h => h.name.toLowerCase() === name);
  const first = name => all(name)[0];
  const val = name => (first(name) ? P.toDisplay(first(name).value) : null);

  const from = P.parseAddress(first('from')?.value);
  const replyTo = P.parseAddressList(first('reply-to')?.value);
  const returnPath = P.parseAddress(first('return-path')?.value);
  const sender = P.parseAddress(first('sender')?.value);
  const date = P.parseDate(val('date'));
  const messageId = val('message-id');

  // Delivery path: Received headers are prepended, so reverse them for oldest-first.
  const hops = all('received').map(P.parseReceived).reverse();
  hops.forEach((h, i) => {
    h.number = i + 1;
    h.delaySeconds = i && h.date && hops[i - 1].date ? Math.round((h.date - hops[i - 1].date) / 1000) : null;
  });
  const dated = hops.filter(h => h.date);
  const totalSeconds = dated.length > 1 ? Math.round((dated[dated.length - 1].date - dated[0].date) / 1000) : null;

  const authResults = all('authentication-results').map(P.parseAuthResults);
  const arcResults = all('arc-authentication-results').map(P.parseAuthResults);
  const receivedSpf = all('received-spf').map(P.parseReceivedSpf);
  const forefronts = all('x-forefront-antispam-report').map(h => ({
    headerIndex: h.index,
    kv: Object.fromEntries(P.toDisplay(h.value).split(';').map(p => p.split(':').map(s => s.trim())).filter(p => p.length === 2)),
  }));
  const forefront = forefronts[0]?.kv || {};

  // ---- Trust boundary
  // Receiving servers add their headers on top of what they received, so anything the sender wrote
  // sits below the hop where the message entered the recipient's mail system. Trace headers claiming
  // a sender IP that the receiving servers never recorded - or sitting below the next-older Received
  // header, where only the sender can write - are treated as forged and ignored.
  const entryHop = findEntryHop(hops, opts.heloIps);
  if (entryHop) entryHop.entry = true;
  const olderThanEntry = entryHop ? hops[hops.indexOf(entryHop) - 1] : null;
  const boundary = olderThanEntry ? olderThanEntry.headerIndex : Infinity;
  const recordedIps = new Set(hops.filter(h => h.ip && (!entryHop || h.headerIndex <= entryHop.headerIndex)).map(h => P.normalizeIp(h.ip)));
  for (const x of [...authResults, ...receivedSpf]) x.trusted = !hops.length || x.headerIndex < boundary;

  const claims = [
    ...receivedSpf.map(r => ({ ip: r.props['client-ip'], header: 'Received-SPF', headerIndex: r.headerIndex, trusted: r.trusted })),
    ...authResults.filter(a => a.senderIp).map(a => ({ ip: a.senderIp, header: 'Authentication-Results', headerIndex: a.headerIndex, trusted: a.trusted })),
    // Exchange appends its own X-headers at the bottom, so position says nothing here; the IP check still applies.
    ...forefronts.filter(f => f.kv.CIP).map(f => ({ ip: f.kv.CIP, header: 'X-Forefront-Antispam-Report', headerIndex: f.headerIndex, trusted: true })),
  ].filter(c => c.ip && P.ipKind(c.ip)).sort((a, b) => a.headerIndex - b.headerIndex);

  let senderIp = null, senderIpSource = null;
  const forgedClaims = [];
  for (const c of claims) {
    if (!hops.length) {
      if (!senderIp) { senderIp = c.ip; senderIpSource = `${c.header} (unverified - the message has no Received headers)`; }
    } else if (!c.trusted) {
      forgedClaims.push({ ...c, reason: 'position' });
    } else if (!recordedIps.has(P.normalizeIp(c.ip))) {
      forgedClaims.push({ ...c, reason: 'unrecorded' });
    } else if (!senderIp) {
      senderIp = c.ip;
      senderIpSource = `${c.header}, matching the Received chain`;
    }
  }
  if (!senderIp && entryHop) {
    senderIp = entryHop.ip;
    senderIpSource = "Received header where the message entered the recipient's mail system";
  }
  const senderHop = hops.find(h => h.ip && P.normalizeIp(h.ip) === P.normalizeIp(senderIp)) || null;
  if (senderHop) senderHop.senderIp = true;
  const originatingIp = val('x-originating-ip')?.replace(/[[\]\s]/g, '') || null;

  // Envelope sender: prefer what a receiving server recorded over a Return-Path the sender could have written.
  const trustedSpf = receivedSpf.find(r => r.trusted && P.normalizeIp(r.props['client-ip']) === P.normalizeIp(senderIp));
  const envelopeFrom = authResults.filter(a => a.trusted).flatMap(a => a.results).find(r => r.props['smtp.mailfrom'])?.props['smtp.mailfrom']
    || trustedSpf?.props['envelope-from']
    || returnPath?.address?.replace(/^<|>$/g, '') || null;
  const helo = trustedSpf?.props.helo || senderHop?.helo || null;

  const dkimSignatures = all('dkim-signature').map(h => {
    const t = P.parseTags(h.value);
    return { domain: (t.d || '').toLowerCase(), selector: t.s || '', algorithm: t.a || '', canonicalization: t.c || 'simple/simple',
             signedHeaders: (t.h || '').split(':').map(s => s.trim()).filter(Boolean), timestamp: t.t ? new Date(Number(t.t) * 1000) : null };
  });
  const arcSeals = all('arc-seal').map(h => P.parseTags(P.toDisplay(h.value)));

  const report = {
    source: { kind: opts.source || 'paste', hasBody: body != null && (opts.source === 'eml' || body.trim().length > 0), headerCount: headers.length },
    summary: {
      from, to: P.parseAddressList(first('to')?.value), cc: P.parseAddressList(first('cc')?.value), replyTo, returnPath, sender,
      subject: val('subject'), date: date ? date.toISOString() : null, dateRaw: val('date'), messageId,
      mailer: val('x-mailer') || val('user-agent'), listUnsubscribe: val('list-unsubscribe'), originatingIp,
    },
    senderIp, senderIpSource, envelopeFrom, helo, forgedClaims, entryHop: entryHop ? entryHop.number : null,
    hops, totalSeconds,
    authResults, arcResults, receivedSpf,
    arc: arcSeals.length ? { sets: arcSeals.length, chain: arcSeals.map(s => ({ i: Number(s.i), cv: s.cv, domain: s.d })) } : null,
    dkimSignatures,
    vendors: decodeVendors(headers),
    bimiIndicator: live.bimiIndicator(headers),
    headers: headers.map(h => ({ name: h.name, value: P.toDisplay(h.value) })),
    flags: [],
    live: null,
  };
  report.flags = headerFlags(report, headers, all);
  return { report, ctx: { headers, body: report.source.hasBody ? body : null, fromDomain: from?.domain || null, senderIp, envelopeFrom, helo,
                          bimiSelectorHeader: val('bimi-selector'), hopIps: hops.map(h => h.ip).filter(Boolean) } };
}

const orgOf = name => {
  const n = (name || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  return n && !P.ipKind(n) ? live.orgDomain(n) : null;
};
const heloKey = h => (h || '').toLowerCase().replace(/\.$/, '');

// The hop where the message entered the recipient's mail system: walking down from the newest hop, the
// first one handed over by a server outside the receiving organization.
//  - Reverse DNS written by the receiver is trusted.
//  - The HELO name is chosen by the connecting client, so a HELO in the recipient's own domain only makes
//    a hop internal if it's proven: the name resolves to the hop's IP (live mode), or the IP is in the
//    published range of a provider that names its relays this way (Microsoft 365). Otherwise that hop is
//    the entry point and is marked so it can be flagged - a sender impersonating the recipient's servers.
// hops is oldest-first and already numbered; heloIps maps HELO names to their resolved IPs (live mode only).
function findEntryHop(hops, heloIps) {
  const receiverOrgs = new Set();
  const newestFirst = [...hops].reverse();
  for (const h of newestFirst) {
    const byOrg = orgOf(h.by);
    if (byOrg) receiverOrgs.add(byOrg);
    if (!h.ip || h.privateIp) continue;
    if (h.rdnsRecorded) {
      if (h.rdns && receiverOrgs.has(orgOf(h.rdns))) continue; // internal relay inside the receiving organization
      return h;
    }
    const heloOrg = orgOf(h.helo);
    if (heloOrg && receiverOrgs.has(heloOrg)) {
      if (live.inProviderRange(heloOrg, h.ip)) continue;
      const resolved = heloIps?.[heloKey(h.helo)];
      if (resolved && resolved.map(P.normalizeIp).includes(P.normalizeIp(h.ip))) continue;
      h.heloImpersonation = heloIps ? 'spoofed' : 'unverified';
    }
    return h;
  }
  // Sender and recipient on the same platform (e.g. Gmail to Gmail): use the newest public hop.
  return newestFirst.find(h => h.ip && !h.privateIp) || null;
}

// ------------------------------------------------------------------ red flags

function headerFlags(r, headers, all) {
  const flags = [];
  const add = (level, title, detail) => flags.push({ level, title, detail });
  const s = r.summary;
  const org = d => live.orgDomain(d);

  for (const [name, level] of [['from', 'high'], ['sender', 'high'], ['subject', 'medium'], ['date', 'medium'], ['to', 'medium'], ['message-id', 'medium'], ['reply-to', 'medium']]) {
    const n = all(name).length;
    if (n > 1) add(level, `Duplicate ${name} header`, `The message has ${n} "${name}" headers. Different mail clients may show different ones - a known spoofing technique.`);
  }
  if (!s.from) add('high', 'No From header', 'Every legitimate message has a From header.');
  if (!s.dateRaw) add('medium', 'No Date header', 'Legitimate mail software always adds a Date header.');
  if (!s.messageId) add('low', 'No Message-ID header', 'Most legitimate mail systems add a Message-ID.');

  if (s.from) {
    const inName = s.from.name.match(/[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
    if (inName && org(inName[1].toLowerCase()) !== org(s.from.domain)) {
      add('high', 'Display name shows a different address', `The display name "${s.from.name}" contains ${inName[0]}, but the real sender is ${s.from.address}.`);
    }
    for (const [label, a] of [['From', s.from], ...s.replyTo.map(x => ['Reply-To', x]), ['Return-Path', s.returnPath]]) {
      if (a?.domain?.includes('xn--')) {
        add('medium', `Internationalized domain in ${label}`, `${a.domain} displays as "${url.domainToUnicode(a.domain)}" - check it isn't a look-alike of a real domain.`);
      }
    }
    if (/[Ѐ-ӿͰ-Ͽ]/.test(s.from.name) && /[A-Za-z]/.test(s.from.name)) {
      add('medium', 'Look-alike characters in display name', `"${s.from.name}" mixes Latin with Cyrillic/Greek letters that look identical.`);
    }
    for (const rt of s.replyTo) {
      if (rt.domain && org(rt.domain) !== org(s.from.domain)) {
        add('medium', 'Reply-To goes to a different domain', `Replies go to ${rt.address}, not ${s.from.domain}. Common in phishing and invoice fraud, but also used by some newsletters and ticketing systems.`);
      }
    }
    if (s.returnPath?.domain && org(s.returnPath.domain) !== org(s.from.domain)) {
      add('low', 'Envelope sender differs from From', `Return-Path is ${s.returnPath.address}. Normal for mailing services and forwarding, but it means SPF can't align with the From domain for DMARC.`);
    }
    if (s.sender?.domain && org(s.sender.domain) !== org(s.from.domain)) {
      add('low', 'Sender header differs from From', `Sent on behalf of ${s.from.address} by ${s.sender.address}.`);
    }
    const midDomain = (s.messageId || '').match(/@([^>\s]+)>?\s*$/);
    if (midDomain && org(midDomain[1].toLowerCase()) !== org(s.from.domain) && !/(outlook|google|gmail|amazonses|sendgrid|mailgun|mail\.protection|exchangelabs|prod\.outlook)/i.test(midDomain[1])) {
      add('info', 'Message-ID domain differs from From', `Message-ID was generated by ${midDomain[1]}. Usually just reveals the sending platform.`);
    }
  }

  const dated = r.hops.filter(h => h.date);
  if (r.summary.date && dated.length) {
    const sent = new Date(r.summary.date), firstHop = dated[0].date, lastHop = dated[dated.length - 1].date;
    if (sent - lastHop > 10 * 60 * 1000) add('medium', 'Date is after delivery', `The Date header (${r.summary.dateRaw}) is later than the last Received timestamp - the sender's clock is wrong or the date was forged.`);
    else if (firstHop - sent > 24 * 3600 * 1000) add('medium', 'Sent long before it was received', `The Date header is ${Math.round((firstHop - sent) / 3600000)} hours before the first Received hop - a delayed, replayed or back-dated message.`);
  }
  for (const h of r.hops) {
    if (h.delaySeconds != null && h.delaySeconds < -300) add('medium', `Hop ${h.number} timestamp goes backwards`, `Hop ${h.number} is ${Math.round(-h.delaySeconds / 60)} minutes earlier than hop ${h.number - 1}. Clock skew, or a forged Received header added by the sender.`);
  }
  for (const h of r.hops.filter(x => x.heloImpersonation)) {
    if (h.heloImpersonation === 'spoofed') {
      add('high', "Sender used the recipient's own server name", `At hop ${h.number}, ${h.ip} introduced itself as "${h.helo}", a name in the recipient's own domain, but that name doesn't point to ${h.ip}. Sending servers do this to look internal and get forged headers trusted.`);
    } else {
      add('medium', "Sender claims to be the recipient's own server", `At hop ${h.number}, ${h.ip} introduced itself as "${h.helo}", a name in the recipient's own domain. Turn on live DNS checks to verify it; it was treated as an outside server.`);
    }
  }
  for (const c of r.forgedClaims) {
    add('high', `Forged ${c.header} header`, c.reason === 'unrecorded'
      ? `It claims the sender IP was ${c.ip}, but the receiving servers recorded the message arriving from ${r.senderIp || 'a different address'}. A sender adds headers like this to make a spoofed message look authenticated; it was ignored.`
      : `It sits below the Received headers written by the receiving servers, where only the sender can add headers. It was ignored.`);
  }
  const forgedAr = r.forgedClaims.map(c => c.headerIndex);
  for (const a of r.authResults) {
    if (!a.trusted && !forgedAr.includes(a.headerIndex)) {
      add('high', 'Forged Authentication-Results header', `A result from "${a.authserv}" sits below the Received headers written by the receiving servers, so the sender most likely wrote it. It was ignored.`);
    }
  }
  const top = r.authResults.find(a => a.trusted);
  if (top) {
    const res = m => top.results.find(x => x.method === m)?.result;
    if (['fail', 'permerror'].includes(res('dmarc'))) add('high', 'Receiving server: DMARC failed', `${top.authserv} reported dmarc=${res('dmarc')}. The From domain was not authenticated.`);
    if (res('compauth') === 'fail') add('high', 'Microsoft composite authentication failed', 'compauth=fail - Microsoft could not verify the sender; this is its spoofing verdict.');
    if (res('spf') === 'fail') add('medium', 'Receiving server: SPF failed', `The sending server was not authorized by ${top.results.find(x => x.method === 'spf')?.props['smtp.mailfrom'] || 'the envelope domain'}.`);
    else if (res('spf') === 'softfail') add('low', 'Receiving server: SPF softfail', 'The sending server is not listed as authorized, but the domain only asks for a soft fail.');
    if (['fail', 'permerror'].includes(res('dkim'))) add('medium', 'Receiving server: DKIM failed', 'A DKIM signature failed verification when the message arrived.');
  }
  if (!r.dkimSignatures.length) add('low', 'No DKIM signature', 'Most legitimate bulk and business mail is DKIM-signed.');
  if (headers.some(h => /^x-php-originating-script$/i.test(h.name))) add('medium', 'Sent by a PHP script', 'X-PHP-Originating-Script shows the message came from a script on a web server - typical of phishing kits on hacked sites.');
  for (const g of r.vendors) {
    for (const it of g.items) {
      if (it.level === 'high') add('high', `${g.source}: ${it.label} = ${it.value}`, it.meaning);
    }
  }
  if (r.summary.originatingIp) add('info', "Sender's client IP revealed", `X-Originating-IP shows the sender's own device/network address: ${r.summary.originatingIp}.`);
  const plainHops = r.hops.filter(h => !h.tls && h.ip && !h.privateIp);
  if (plainHops.length) add('info', 'Hops without TLS', `${plainHops.length} hop(s) between public servers don't show encryption: ${plainHops.map(h => h.number).join(', ')}. Some servers just don't record TLS in the header.`);
  return flags;
}

function liveFlags(report) {
  const L = report.live;
  const flags = [];
  const add = (level, title, detail) => flags.push({ level, title, detail });
  for (const d of L.dkim) {
    if (d.result === 'fail') add('high', `DKIM signature for ${d.domain} fails now`, d.detail);
    else if (d.result === 'body-mismatch') add('medium', `DKIM body hash for ${d.domain} doesn't match`, d.detail);
    else if (d.result === 'permerror') add('medium', `DKIM signature for ${d.domain} can't be checked`, d.detail);
  }
  if (['fail', 'softfail'].includes(L.spf.result)) add(L.spf.result === 'fail' ? 'medium' : 'low', `SPF ${L.spf.result} on re-check`, `${L.spf.ip} is not authorized to send for ${L.spf.domain} according to its current SPF record.`);
  if (L.dmarc.result === 'fail') {
    add(['reject', 'quarantine'].includes(L.dmarc.disposition) ? 'high' : 'medium', `DMARC fails (policy: ${L.dmarc.disposition})`, L.dmarc.detail);
    const reported = report.authResults.find(a => a.trusted)?.results.find(x => x.method === 'dmarc')?.result;
    if (reported === 'pass') {
      add('medium', 'Receiving server and re-check disagree on DMARC', 'The receiving server recorded dmarc=pass, but checking against current DNS fails. '
        + 'Either the Authentication-Results header was forged, or the domain has since changed its DKIM keys or SPF record (common for older messages).');
    }
  }
  for (const [ip, rbl] of Object.entries(L.hopRbl || {})) {
    const listed = rbl.filter(x => x.status === 'listed');
    if (listed.length) {
      add(ip === L.senderIp?.ip ? 'medium' : 'low', `${ip === L.senderIp?.ip ? 'Sender IP' : `Relay ${ip}`} on ${listed.length} blocklist(s)`,
        `${ip} is listed on ${listed.map(x => x.zone).join(', ')}.`);
    }
  }
  if (L.senderIp) {
    if (!L.senderIp.ptr) add('low', 'Sender IP has no reverse DNS', `${L.senderIp.ip} has no PTR record. Legitimate mail servers almost always have one.`);
    else if (!L.senderIp.confirmed) add('low', 'Reverse DNS not confirmed', `${L.senderIp.ip} points to ${L.senderIp.ptr}, but that name doesn't point back to the IP.`);
  }
  return flags;
}

function verdict(flags) {
  if (flags.some(f => f.level === 'high')) return { level: 'high', label: 'Suspicious' };
  if (flags.some(f => f.level === 'medium')) return { level: 'medium', label: 'Review carefully' };
  return { level: 'ok', label: 'No red flags found' };
}

// HELO names that may need checking: public-IP hops where the receiver recorded no reverse DNS.
function heloCandidates(raw) {
  const { headerText } = P.splitMessage(raw);
  const hops = P.parseHeaders(headerText).filter(h => h.name.toLowerCase() === 'received').map(P.parseReceived);
  const names = hops.filter(h => h.ip && !h.privateIp && !h.rdnsRecorded && orgOf(h.helo)).map(h => heloKey(h.helo));
  return [...new Set(names)].slice(0, 10);
}

async function analyzeMessage(raw, opts = {}) {
  if (opts.live) {
    // Resolve HELO names first: deciding which hop is trustworthy depends on them.
    opts = { ...opts, resolver: opts.resolver || live.makeResolver() };
    opts.heloIps = await live.resolveNames(heloCandidates(raw), opts.resolver);
  }
  const { report, ctx } = analyze(raw, opts);
  if (opts.live) {
    report.live = await live.runLiveChecks(ctx, opts.resolver, opts.fetcher);
    report.flags.push(...liveFlags(report));
  }
  report.flags.sort((a, b) => LEVELS.indexOf(a.level) - LEVELS.indexOf(b.level));
  report.verdict = verdict(report.flags);
  return report;
}

module.exports = { analyzeMessage, analyze };
