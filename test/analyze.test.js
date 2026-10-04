const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { analyzeMessage } = require('../lib/analyze');
const live = require('../lib/live');
const { fakeResolver, rsaKey, sign } = require('./helpers');

const bytes = s => Buffer.from(s, 'utf8').toString('latin1');
const fixture = name => bytes(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'));
const titles = r => r.flags.map(f => f.title);
const fakeLogo = async () => ({ dataUri: 'data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=', bytes: 11, svgTinyPs: true });

test('phishing headers: offline flags', async () => {
  const r = await analyzeMessage(fixture('phish-headers.txt'), { live: false });
  assert.equal(r.verdict.level, 'high');
  const t = titles(r);
  for (const expected of ['Display name shows a different address', 'Authentication-Results below every Received header',
                          'Receiving server: DMARC failed', 'Reply-To goes to a different domain', 'Sent by a PHP script']) {
    assert.ok(t.includes(expected), `missing flag: ${expected}\n${t.join('\n')}`);
  }
  assert.equal(r.senderIp, '203.0.113.45');
  assert.equal(r.senderIpSource, 'Received-SPF client-ip');
  assert.equal(r.hops.length, 3);
  assert.equal(r.hops[1].senderIp, true);
  assert.equal(r.live, null);
});

test('duplicate From and look-alike display names are flagged', async () => {
  const raw = bytes('Received: from a.example.com ([198.51.100.1]) by mx.example.org; Fri, 03 Oct 2025 14:12:05 +0000\n'
    + 'From: Alice <alice@example.com>\nFrom: Microsoft <security@example.net>\nTo: x@example.org\n'
    + 'Subject: hi\nDate: Fri, 03 Oct 2025 14:12:00 +0000\nMessage-ID: <1@example.com>\n');
  const t = titles(await analyzeMessage(raw, { live: false }));
  assert.ok(t.includes('Duplicate from header'));
  const raw2 = bytes('From: "Micrоsoft Support" <help@example.com>\nTo: x@example.org\nSubject: hi\nDate: Fri, 03 Oct 2025 14:12:00 +0000\n');
  assert.ok(titles(await analyzeMessage(raw2, { live: false })).includes('Look-alike characters in display name'));
});

test('backwards timestamps and future dates are flagged', async () => {
  const raw = bytes('Received: from b.example.net ([198.51.100.2]) by mx.example.org; Fri, 03 Oct 2025 12:00:00 +0000\n'
    + 'Received: from a.example.net ([198.51.100.1]) by b.example.net; Fri, 03 Oct 2025 14:00:00 +0000\n'
    + 'From: a@example.net\nTo: b@example.org\nSubject: s\nDate: Sat, 04 Oct 2025 09:00:00 +0000\nMessage-ID: <1@example.net>\n');
  const t = titles(await analyzeMessage(raw, { live: false }));
  assert.ok(t.includes('Hop 2 timestamp goes backwards'), t.join('\n'));
  assert.ok(t.includes('Date is after delivery'), t.join('\n'));
});

test('legitimate signed message with live checks: DMARC passes, BIMI shown, no red flags', async () => {
  const key = rsaKey();
  const msg = 'Received: from mail.example.com (mail.example.com [203.0.113.10]) by mx.example.org with ESMTPS; Fri, 03 Oct 2025 14:12:01 +0000\r\n'
    + 'Return-Path: <bounces@example.com>\r\n'
    + 'From: Example News <news@example.com>\r\nTo: reader@example.org\r\nSubject: October update\r\n'
    + 'Date: Fri, 03 Oct 2025 14:12:00 +0000\r\nMessage-ID: <42@example.com>\r\n\r\nHello\r\n';
  const raw = await sign(msg, { domain: 'example.com', selector: 's1', privatePem: key.privatePem });
  const resolver = fakeResolver({
    's1._domainkey.example.com': { TXT: [`v=DKIM1; k=rsa; p=${key.dnsP}`] },
    'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 -all'] },
    '_dmarc.example.com': { TXT: ['v=DMARC1; p=reject; rua=mailto:d@example.com'] },
    'default._bimi.example.com': { TXT: ['v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem'] },
    '203.0.113.10': { PTR: ['mail.example.com'] },
    'mail.example.com': { A: ['203.0.113.10'] },
  });
  const r = await analyzeMessage(raw, { live: true, source: 'eml', resolver, fetcher: fakeLogo });
  assert.equal(r.live.dkim[0].result, 'pass', r.live.dkim[0].detail);
  assert.equal(r.live.spf.result, 'pass', JSON.stringify(r.live.spf));
  assert.equal(r.live.dmarc.result, 'pass');
  assert.deepEqual(r.live.dmarc.checks, { spfAuthenticated: true, spfAligned: true, dkimAuthenticated: true, dkimAligned: true });
  assert.equal(r.live.bimi.found, true);
  assert.equal(r.live.bimi.dmarcEligible, true);
  assert.match(r.live.bimi.logo.dataUri, /^data:image\/svg\+xml;base64,/);
  assert.equal(r.live.senderIp.confirmed, true);
  assert.ok(r.live.hopRbl['203.0.113.10'].every(x => x.status === 'clean'));
  assert.deepEqual(r.flags.filter(f => ['high', 'medium'].includes(f.level)), []);
  assert.equal(r.verdict.level, 'ok');
});

test('spoofed From domain with p=reject fails DMARC on live check', async () => {
  const raw = bytes('Received: from evil.example.net (evil.example.net [198.51.100.66]) by mx.example.org with ESMTP; Fri, 03 Oct 2025 14:12:01 +0000\n'
    + 'Return-Path: <x@evil.example.net>\nFrom: Bank <alerts@bank.example>\nTo: v@example.org\nSubject: Verify\n'
    + 'Date: Fri, 03 Oct 2025 14:12:00 +0000\nMessage-ID: <9@evil.example.net>\n');
  const resolver = fakeResolver({
    '_dmarc.bank.example': { TXT: ['v=DMARC1; p=reject'] },
    'evil.example.net': { TXT: ['v=spf1 ip4:198.51.100.66 -all'] },
    '66.100.51.198.zen.spamhaus.org': { A: ['127.0.0.4'] },
  });
  const r = await analyzeMessage(raw, { live: true, resolver, fetcher: fakeLogo });
  assert.equal(r.live.dmarc.result, 'fail');
  assert.equal(r.live.dmarc.checks.spfAuthenticated, true);
  assert.equal(r.live.dmarc.checks.spfAligned, false);
  assert.ok(titles(r).includes('DMARC fails (policy: reject)'));
  assert.ok(titles(r).includes('Sender IP on 1 blocklist(s)'));
  assert.equal(r.verdict.level, 'high');
});

test('DMARC record is inherited from the organizational domain', async () => {
  const resolver = fakeResolver({ '_dmarc.example.co.uk': { TXT: ['v=DMARC1; p=quarantine; sp=reject'] } });
  const d = await live.lookupDmarc('news.mail.example.co.uk', resolver);
  assert.equal(d.at, 'example.co.uk');
  assert.equal(d.policy, 'reject'); // subdomain policy applies
});

test('Spamhaus "query refused" answers are not treated as listings', async () => {
  const resolver = fakeResolver({ '4.3.2.1.zen.spamhaus.org': { A: ['127.255.255.254'] } });
  const res = await live.checkRbls('1.2.3.4', resolver);
  assert.equal(res.find(x => x.zone === 'zen.spamhaus.org').status, 'refused');
});

test('BIMI logo fetch refuses non-HTTPS and private hosts', async () => {
  assert.match((await live.fetchLogo('http://example.com/logo.svg')).error, /HTTPS/);
  assert.match((await live.fetchLogo('https://127.0.0.1/logo.svg')).error, /private|could not fetch/);
});

test('BIMI requires DMARC enforcement', async () => {
  const resolver = fakeResolver({ 'default._bimi.example.com': { TXT: ['v=BIMI1; l=https://example.com/l.svg;'] } });
  const b = await live.lookupBimi('example.com', null, { found: true, policy: 'none', pct: 100 }, resolver, fakeLogo);
  assert.equal(b.dmarcEligible, false);
  assert.ok(b.notes.some(n => n.includes('requires DMARC')));
});
