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
  const forefront = Object.fromEntries((val('x-forefront-antispam-report') || '').split(';').map(p => p.split(':').map(s => s.trim())).filter(p => p.length === 2));

  // The IP that handed the message to the recipient's mail system, best source first.
  let senderIp = null, senderIpSource = null;
  const candidates = [
    [receivedSpf[0]?.props['client-ip'], 'Received-SPF client-ip'],
    [authResults.find(a => a.senderIp)?.senderIp, 'Authentication-Results (sender IP is ...)'],
    [forefront.CIP, 'Microsoft X-Forefront-Antispam-Report CIP'],
    [[...hops].reverse().find(h => h.ip && !h.privateIp)?.ip, 'most recent Received hop with a public IP'],
  ];
  for (const [ip, src] of candidates) {
    if (ip && P.ipKind(ip)) { senderIp = ip; senderIpSource = src; break; }
  }
  const senderHop = hops.find(h => h.ip === senderIp) || null;
  if (senderHop) senderHop.senderIp = true;
  const originatingIp = val('x-originating-ip')?.replace(/[[\]\s]/g, '') || null;

  const envelopeFrom = returnPath?.address?.replace(/^<|>$/g, '')
    || authResults.flatMap(a => a.results).find(r => r.props['smtp.mailfrom'])?.props['smtp.mailfrom']
    || receivedSpf[0]?.props['envelope-from'] || null;
  const helo = receivedSpf[0]?.props.helo || senderHop?.helo || forefront.H || null;

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
    senderIp, senderIpSource, envelopeFrom, helo,
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
  const lastReceivedIndex = Math.max(-1, ...r.hops.map(h => h.headerIndex));
  for (const a of r.authResults) {
    if (r.hops.length && a.headerIndex > lastReceivedIndex) {
      add('high', 'Authentication-Results below every Received header', `A result from "${a.authserv}" sits below all Received headers, so it was most likely written by the sender, not a receiving server. Don't trust it.`);
    }
  }
  const top = r.authResults[0];
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

async function analyzeMessage(raw, opts = {}) {
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
