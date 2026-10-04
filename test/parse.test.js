const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const P = require('../lib/parse');

const fixture = name => Buffer.from(fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'), 'utf8').toString('latin1');

test('splits headers from body and unfolds folded headers', () => {
  const { headerText, body } = P.splitMessage('Subject: a\r\n  long\r\n\tsubject\r\nFrom: x@y.com\r\n\r\nBody line\r\n');
  const h = P.parseHeaders(headerText);
  assert.equal(h.length, 2);
  assert.equal(h[0].value, 'a  long\tsubject');
  assert.equal(h[0].raw, 'Subject: a\r\n  long\r\n\tsubject');
  assert.equal(body, 'Body line\n');
});

test('headers-only paste has no body', () => {
  assert.equal(P.splitMessage('From: a@b.com\nTo: c@d.com\n').body, null);
});

test('decodes RFC 2047 encoded words, including adjacent ones', () => {
  assert.equal(P.toDisplay('=?UTF-8?B?WW91ciBhY2NvdW50?= =?UTF-8?Q?_is_limited?='), 'Your account is limited');
  assert.equal(P.toDisplay('=?iso-8859-1?Q?Caf=E9?='), 'Café');
});

test('parses addresses with display names', () => {
  const a = P.parseAddress('"Smith, John" <John.Smith@Example.COM>');
  assert.equal(a.name, 'Smith, John');
  assert.equal(a.domain, 'example.com');
  assert.equal(P.parseAddressList('a@x.com, "B, C" <b@y.com>').length, 2);
});

test('parses Received headers from common servers', () => {
  const postfix = P.parseReceived({ index: 0, value: 'from mail.example.net (mail.example.net [203.0.113.45]) by mx.google.com with ESMTPS id abc for <v@e.org>; Fri, 03 Oct 2025 07:12:08 -0700 (PDT)' });
  assert.equal(postfix.helo, 'mail.example.net');
  assert.equal(postfix.rdns, 'mail.example.net');
  assert.equal(postfix.ip, '203.0.113.45');
  assert.equal(postfix.by, 'mx.google.com');
  assert.equal(postfix.tls, true);
  assert.equal(postfix.for, 'v@e.org');
  assert.equal(postfix.date.toISOString(), '2025-10-03T14:12:08.000Z');

  const ms = P.parseReceived({ index: 0, value: 'from DM6PR11MB4105.namprd11.prod.outlook.com (2603:10b6:5:1b4::22) by BN6PR11MB1234.namprd11.prod.outlook.com with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8; Fri, 3 Oct 2025 14:12:09 +0000' });
  assert.equal(ms.ip, '2603:10b6:5:1b4::22');
  assert.equal(ms.protocol, 'Microsoft SMTP Server');
  assert.equal(ms.tls, true);
  assert.equal(ms.tlsVersion, 'TLS1.2');

  const sub = P.parseReceived({ index: 0, value: 'from [192.168.1.20] (unknown [198.51.100.7]) by mail.example.net (Postfix) with ESMTPSA id 4F; Fri, 03 Oct 2025 14:12:05 +0000 (UTC)' });
  assert.equal(sub.ip, '198.51.100.7');
  assert.equal(sub.rdns, null);
  assert.equal(sub.authenticated, true);
});

test('private IP detection', () => {
  for (const ip of ['10.1.2.3', '192.168.0.1', '172.20.1.1', '127.0.0.1', '::1', 'fd00::1', '::ffff:10.0.0.1']) assert.ok(P.isPrivateIp(ip), ip);
  for (const ip of ['8.8.8.8', '203.0.113.45', '2607:f8b0::1']) assert.ok(!P.isPrivateIp(ip), ip);
});

test('parses Authentication-Results, including Microsoft comments', () => {
  const a = P.parseAuthResults({ index: 0, value: 'spf=pass (sender IP is 209.85.220.41) smtp.mailfrom=gmail.com; dkim=pass (signature was verified) header.d=gmail.com;dmarc=pass action=none header.from=gmail.com;compauth=pass reason=100' });
  assert.equal(a.senderIp, '209.85.220.41');
  const m = Object.fromEntries(a.results.map(r => [r.method, r]));
  assert.equal(m.spf.result, 'pass');
  assert.equal(m.dkim.props['header.d'], 'gmail.com');
  assert.equal(m.dmarc.props.action, 'none');
  assert.equal(m.compauth.props.reason, '100');

  const g = P.parseAuthResults({ index: 0, value: 'mx.google.com; dkim=pass header.i=@example.com header.s=s1 header.b="AbC+/9"; spf=pass (google.com: domain of a@b.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=a@b.com' });
  assert.equal(g.authserv, 'mx.google.com');
  assert.equal(g.results[0].props['header.b'], 'AbC+/9');
});

test('parses the phishing fixture end to end', () => {
  const { headerText } = P.splitMessage(fixture('phish-headers.txt'));
  const h = P.parseHeaders(headerText);
  assert.ok(h.length > 15);
  assert.equal(P.toDisplay(h.find(x => x.name === 'Subject').value), 'Your account has been limited ⚠️');
});
