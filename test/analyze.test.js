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
  for (const expected of ['Display name shows a different address', 'Forged Authentication-Results header',
                          'Receiving server: DMARC failed', 'Reply-To goes to a different domain', 'Sent by a PHP script']) {
    assert.ok(t.includes(expected), `missing flag: ${expected}\n${t.join('\n')}`);
  }
  // Gmail writes Received-SPF just below its own Received header; that must still be trusted.
  assert.equal(r.senderIp, '203.0.113.45');
  assert.equal(r.senderIpSource, 'Received-SPF, matching the Received chain');
  assert.equal(r.entryHop, 2);
  assert.equal(r.authResults.find(a => a.authserv === 'mx.google.com').trusted, true);
  assert.equal(r.authResults.find(a => a.authserv === 'fake.example').trusted, false);
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

// ------------------------------------------------------------------ forged trace headers

const BANK_DNS = {
  '_dmarc.bank.example': { TXT: ['v=DMARC1; p=reject'] },
  'bank.example': { TXT: ['v=spf1 ip4:198.51.100.10 -all'] },
};
// The recipient's MX recorded 203.0.113.66; every header below that line was written by the attacker.
const spoofed = forged => bytes([
  'Received: from evil.example.net (evil.example.net [203.0.113.66]) by mx.example.org with ESMTP; Fri, 03 Oct 2025 14:12:01 +0000',
  ...forged,
  'Return-Path: <alerts@bank.example>', 'From: Bank <alerts@bank.example>', 'To: v@example.org', 'Subject: Verify your account',
  'Date: Fri, 03 Oct 2025 14:12:00 +0000', 'Message-ID: <9@bank.example>', ''].join('\n'));

for (const [name, forged] of [
  ['Received-SPF', ['Received-SPF: pass (bank.example: designates 198.51.100.10 as permitted sender) client-ip=198.51.100.10; envelope-from=alerts@bank.example; helo=mail.bank.example']],
  ['Authentication-Results', ['Authentication-Results: spf=pass (sender IP is 198.51.100.10) smtp.mailfrom=bank.example; dmarc=pass action=none header.from=bank.example']],
  ['X-Forefront-Antispam-Report', ['X-Forefront-Antispam-Report: CIP:198.51.100.10;CTRY:US;SFV:NSPM;CAT:NONE;']],
  ['Received-SPF behind a fake Received hop', [
    'Received-SPF: pass client-ip=198.51.100.10; envelope-from=alerts@bank.example',
    'Received: from mail.bank.example (mail.bank.example [198.51.100.10]) by evil.example.net; Fri, 03 Oct 2025 14:12:00 +0000']],
]) {
  test(`forged ${name} can't make a spoofed message pass`, async () => {
    const r = await analyzeMessage(spoofed(forged), { live: true, resolver: fakeResolver(BANK_DNS), fetcher: fakeLogo });
    assert.equal(r.senderIp, '203.0.113.66', r.senderIpSource);
    assert.equal(r.live.dmarc.result, 'fail');
    assert.equal(r.verdict.level, 'high');
    assert.ok(r.flags.some(f => f.level === 'high' && f.title.startsWith('Forged')), titles(r).join('\n'));
  });
}

test('genuine Microsoft 365 headers: internal hops skipped, Received-SPF and A-R trusted', async () => {
  const raw = bytes([
    'Received: from SN6PR11MB2222.namprd11.prod.outlook.com (::1) by SN6PR11MB2222.namprd11.prod.outlook.com with HTTPS; Fri, 3 Oct 2025 14:12:10 +0000',
    'Received: from BN9PR03CA0006.namprd03.prod.outlook.com (2603:10b6:408:13e::11) by SN6PR11MB2222.namprd11.prod.outlook.com (2603:10b6:805:5b::21) with Microsoft SMTP Server (version=TLS1_2, cipher=X) id 15.20; Fri, 3 Oct 2025 14:12:09 +0000',
    'Authentication-Results: spf=pass (sender IP is 209.85.220.41) smtp.mailfrom=gmail.com; dkim=pass (signature was verified) header.d=gmail.com;dmarc=pass action=none header.from=gmail.com;compauth=pass reason=100',
    'Received-SPF: Pass (protection.outlook.com: domain of gmail.com designates 209.85.220.41 as permitted sender) receiver=protection.outlook.com; client-ip=209.85.220.41; helo=mail-sor-f41.google.com; pr=C',
    'Received: from mail-sor-f41.google.com (209.85.220.41) by BN9PR03CA0006.mail.protection.outlook.com (10.167.243.52) with Microsoft SMTP Server (version=TLS1_3, cipher=Y) id 15.20; Fri, 3 Oct 2025 14:12:08 +0000',
    'Received: by mail-sor-f41.google.com with SMTP id x; Fri, 03 Oct 2025 07:12:07 -0700 (PDT)',
    'From: Friend <friend@gmail.com>', 'To: me@contoso.com', 'Subject: hi', 'Date: Fri, 3 Oct 2025 07:12:06 -0700', 'Message-ID: <a@mail.gmail.com>',
    'X-Forefront-Antispam-Report: CIP:209.85.220.41;CTRY:US;SFV:NSPM;CAT:NONE;', ''].join('\n'));
  const r = await analyzeMessage(raw, { live: false });
  assert.equal(r.senderIp, '209.85.220.41');
  assert.equal(r.hops.find(h => h.entry).helo, 'mail-sor-f41.google.com');
  assert.equal(r.envelopeFrom, 'gmail.com');
  assert.deepEqual(r.forgedClaims, []);
  // Microsoft's bare-domain smtp.mailfrom must be what SPF is evaluated for (not the HELO name)
  const checked = await analyzeMessage(raw, { live: true, resolver: fakeResolver({ 'gmail.com': { TXT: ['v=spf1 ip4:209.85.128.0/17 -all'] } }), fetcher: fakeLogo });
  assert.equal(checked.live.spf.domain, 'gmail.com');
  assert.equal(checked.live.spf.result, 'pass');
  assert.ok(!r.flags.some(f => f.title.startsWith('Forged')), titles(r).join('\n'));
});

test('a forged HELO name cannot make the entry hop look internal', async () => {
  // rDNS recorded by the receiver says evil.example.net even though the client claimed to be mx2.example.org
  const raw = spoofed(['Received-SPF: pass client-ip=198.51.100.10; envelope-from=alerts@bank.example'])
    .replace('from evil.example.net (evil.example.net', 'from mx2.example.org (evil.example.net');
  const r = await analyzeMessage(raw, { live: false });
  assert.equal(r.senderIp, '203.0.113.66');
  assert.ok(titles(r).includes('Forged Received-SPF header'));
});

test('IP addresses compare in canonical form', () => {
  const { normalizeIp } = require('../lib/parse');
  assert.equal(normalizeIp('2001:DB8::1'), normalizeIp('2001:db8:0:0:0:0:0:1'));
  assert.equal(normalizeIp('::ffff:203.0.113.5'), '203.0.113.5');
  assert.equal(normalizeIp('[IPv6:2603:10b6::5]'), normalizeIp('2603:10b6:0::5'));
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
