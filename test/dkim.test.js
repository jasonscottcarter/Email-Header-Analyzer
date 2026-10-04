const test = require('node:test');
const assert = require('node:assert/strict');
const P = require('../lib/parse');
const dkim = require('../lib/dkim');
const { fakeResolver, rsaKey, ed25519Key, sign } = require('./helpers');

const MESSAGE = 'From: Alice <alice@example.com>\r\nTo: bob@example.org\r\nSubject: Quarterly report\r\n'
  + 'Date: Fri, 03 Oct 2025 14:12:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nHello Bob,\r\n\r\nNumbers attached.  \r\n\r\n\r\n';

const rsa = rsaKey();
const ed = ed25519Key();
const resolver = fakeResolver({
  's1._domainkey.example.com': { TXT: [`v=DKIM1; k=rsa; p=${rsa.dnsP}`] },
  'ed._domainkey.example.com': { TXT: [`v=DKIM1; k=ed25519; p=${ed.dnsP}`] },
  'old._domainkey.example.com': { TXT: ['v=DKIM1; k=rsa; p='] },
}, { failNames: ['down._domainkey.example.com'] });

async function verify(raw, { headersOnly = false } = {}) {
  const { headerText, body } = P.splitMessage(raw);
  const results = await dkim.verifyAll(P.parseHeaders(headerText), headersOnly ? null : body, resolver.resolveTxt);
  return results[0];
}

test('relaxed/relaxed RSA signature verifies with body', async () => {
  const r = await verify(await sign(MESSAGE, { domain: 'example.com', selector: 's1', privatePem: rsa.privatePem }));
  assert.equal(r.result, 'pass', r.detail);
  assert.equal(r.keyBits, 2048);
});

test('simple/simple RSA signature verifies', async () => {
  const r = await verify(await sign(MESSAGE, { domain: 'example.com', selector: 's1', privatePem: rsa.privatePem, canonicalization: 'simple/simple' }));
  assert.equal(r.result, 'pass', r.detail);
});

test('ed25519 signature verifies', async () => {
  const r = await verify(await sign(MESSAGE, { domain: 'example.com', selector: 'ed', privatePem: ed.privatePem, algorithm: 'ed25519-sha256' }));
  assert.equal(r.result, 'pass', r.detail);
});

test('headers only: signature verified, body hash not checked', async () => {
  const r = await verify(await sign(MESSAGE, { domain: 'example.com', selector: 's1', privatePem: rsa.privatePem }), { headersOnly: true });
  assert.equal(r.result, 'pass-headers', r.detail);
});

test('header re-folded by a mail client still verifies with relaxed canonicalization', async () => {
  const signed = await sign(MESSAGE, { domain: 'example.com', selector: 's1', privatePem: rsa.privatePem });
  const refolded = signed.replace('Subject: Quarterly report', 'Subject: Quarterly\r\n report');
  assert.equal((await verify(refolded)).result, 'pass');
});

test('changed subject fails', async () => {
  const signed = await sign(MESSAGE, { domain: 'example.com', selector: 's1', privatePem: rsa.privatePem });
  assert.equal((await verify(signed.replace('Quarterly report', 'URGENT: wire transfer'))).result, 'fail');
});

test('changed body is reported as a body-hash mismatch', async () => {
  const signed = await sign(MESSAGE, { domain: 'example.com', selector: 's1', privatePem: rsa.privatePem });
  assert.equal((await verify(signed.replace('Numbers attached.', 'Pay invoice 4471 today.'))).result, 'body-mismatch');
});

test('revoked, missing and unreachable keys', async () => {
  const forSelector = s => sign(MESSAGE, { domain: 'example.com', selector: s, privatePem: rsa.privatePem });
  const revoked = await verify(await forSelector('old'));
  assert.equal(revoked.result, 'permerror');
  assert.match(revoked.detail, /revoked/);
  assert.equal((await verify(await forSelector('nokey'))).result, 'permerror');
  assert.equal((await verify(await forSelector('down'))).result, 'temperror');
});

test('body canonicalization follows RFC 6376', () => {
  assert.equal(dkim.canonBody('', 'simple'), '\r\n');
  assert.equal(dkim.canonBody('', 'relaxed'), '');
  assert.equal(dkim.canonBody('a  b \r\n\r\n\r\n', 'relaxed'), 'a b\r\n');
  assert.equal(dkim.canonBody('a  b \r\n\r\n', 'simple'), 'a  b \r\n');
});
