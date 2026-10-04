// DKIM signature verification (RFC 6376, RFC 8463).
//
// Works on headers alone: the header signature covers the body hash tag (bh=), so a signature can be
// checked without the body. When the full message is available the body hash is verified too.
const crypto = require('crypto');
const { parseTags, toDisplay } = require('./parse');

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function canonHeader(raw, mode) {
  if (mode === 'simple') return raw + '\r\n';
  const i = raw.indexOf(':');
  const name = raw.slice(0, i).trim().toLowerCase();
  const value = raw.slice(i + 1).replace(/\r\n/g, '').replace(/[ \t]+/g, ' ').trim();
  return `${name}:${value}\r\n`;
}

function canonBody(body, mode) {
  let lines = body.replace(/\r\n?/g, '\n').split('\n');
  if (mode === 'relaxed') lines = lines.map(l => l.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  if (!lines.length) return mode === 'relaxed' ? '' : '\r\n';
  return lines.join('\r\n') + '\r\n';
}

// Headers named in h=, each taken from the bottom up (RFC 6376 section 5.4.2).
function selectHeaders(headers, names) {
  const used = {};
  const out = [];
  for (const name of names) {
    const key = name.trim().toLowerCase();
    const instances = headers.filter(h => h.name.toLowerCase() === key);
    used[key] = (used[key] || 0) + 1;
    const h = instances[instances.length - used[key]];
    if (h) out.push(h);
  }
  return out;
}

function stripSignatureValue(raw) {
  const i = raw.indexOf(':');
  return raw.slice(0, i + 1) + raw.slice(i + 1).replace(/(^|;)([ \t\r\n]*b[ \t\r\n]*=)[^;]*/, '$1$2');
}

function publicKey(p, keyType) {
  const der = Buffer.from(p, 'base64');
  if (keyType === 'ed25519') {
    return crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, der]), format: 'der', type: 'spki' });
  }
  try {
    return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    return crypto.createPublicKey({ key: der, format: 'der', type: 'pkcs1' });
  }
}

async function fetchKey(selector, domain, resolveTxt) {
  const name = `${selector}._domainkey.${domain}`;
  try {
    const records = await resolveTxt(name);
    const txt = records.map(r => r.join('')).find(r => /(^|;)\s*p\s*=/.test(r)) || records.map(r => r.join(''))[0];
    if (!txt) return { error: 'no key record', name };
    return { tags: parseTags(txt), record: txt, name };
  } catch (err) {
    const missing = ['ENOTFOUND', 'ENODATA', 'NXDOMAIN'].includes(err.code);
    return { error: missing ? 'key not found in DNS' : `DNS error (${err.code || err.message})`, temp: !missing, name };
  }
}

/**
 * Verify one DKIM-Signature header.
 * Returns { domain, selector, algorithm, result, detail, ... } where result is one of:
 *   pass             signature and body hash verified
 *   pass-headers     signature verified; body not available so the body hash could not be checked
 *   body-mismatch    signature valid but the body was changed after signing
 *   fail             signature does not verify (headers changed or forged)
 *   permerror        malformed signature, revoked/invalid key, unsupported algorithm
 *   temperror        DNS lookup failed
 */
async function verifySignature(sigHeader, headers, body, resolveTxt, now = new Date()) {
  const tags = parseTags(sigHeader.value);
  const out = {
    domain: (tags.d || '').toLowerCase(), selector: tags.s || '', algorithm: tags.a || '',
    canonicalization: tags.c || 'simple/simple', signedHeaders: (tags.h || '').split(':').map(s => s.trim()).filter(Boolean),
    identity: tags.i || null, timestamp: tags.t ? new Date(Number(tags.t) * 1000) : null,
    expires: tags.x ? new Date(Number(tags.x) * 1000) : null, bodyLength: tags.l ? Number(tags.l) : null,
    notes: [],
  };
  const fail = (result, detail) => Object.assign(out, { result, detail });

  for (const t of ['v', 'a', 'b', 'bh', 'd', 'h', 's']) {
    if (!tags[t]) return fail('permerror', `signature is missing the required "${t}=" tag`);
  }
  const algMatch = tags.a.toLowerCase().match(/^(rsa|ed25519)-(sha256|sha1)$/);
  if (!algMatch || (algMatch[1] === 'ed25519' && algMatch[2] !== 'sha256')) return fail('permerror', `unsupported algorithm "${tags.a}"`);
  const [, keyAlg, hashAlg] = algMatch;
  if (hashAlg === 'sha1') out.notes.push('Uses SHA-1, which is deprecated (RFC 8301).');
  if (!out.signedHeaders.some(h => h.toLowerCase() === 'from')) return fail('permerror', 'signature does not cover the From header');
  const [hc, bc = 'simple'] = out.canonicalization.toLowerCase().split('/');
  if (out.expires && out.expires < now) out.notes.push(`Signature expired on ${out.expires.toISOString()} (it may have been valid when delivered).`);
  if (out.bodyLength != null) out.notes.push(`Signs only the first ${out.bodyLength} bytes of the body (l= tag); content can be appended unsigned.`);

  const key = await fetchKey(tags.s, tags.d, resolveTxt);
  out.keyRecord = key.name;
  if (key.error) return fail(key.temp ? 'temperror' : 'permerror', key.error);
  const keyType = (key.tags.k || 'rsa').toLowerCase();
  if (!key.tags.p) return fail('permerror', 'key has been revoked (empty p= in DNS)');
  if (keyType !== keyAlg) return fail('permerror', `key type "${keyType}" doesn't match algorithm "${tags.a}"`);
  if (key.tags.t && key.tags.t.split(':').includes('y')) out.notes.push('Signer has flagged this key as testing mode (t=y).');

  let pub;
  try {
    pub = publicKey(key.tags.p, keyType);
  } catch (err) {
    return fail('permerror', `key in DNS could not be read (${err.message})`);
  }
  if (keyType === 'rsa') {
    out.keyBits = pub.asymmetricKeyDetails?.modulusLength || null;
    if (out.keyBits && out.keyBits < 1024) return fail('permerror', `RSA key is only ${out.keyBits} bits (minimum 1024)`);
    if (out.keyBits && out.keyBits < 2048) out.notes.push(`RSA key is ${out.keyBits} bits; 2048 or more is recommended.`);
  }

  const data = selectHeaders(headers, out.signedHeaders).map(h => canonHeader(h.raw, hc)).join('')
    + canonHeader(stripSignatureValue(sigHeader.raw), hc).replace(/\r\n$/, '');
  const dataBuf = Buffer.from(data, 'latin1');
  const sig = Buffer.from(tags.b, 'base64');
  let valid;
  try {
    valid = keyType === 'ed25519'
      ? crypto.verify(null, crypto.createHash('sha256').update(dataBuf).digest(), pub, sig)
      : crypto.verify(hashAlg, dataBuf, pub, sig);
  } catch (err) {
    return fail('permerror', `verification error (${err.message})`);
  }
  if (!valid) {
    return fail('fail', 'signature does not match the signed headers - they were changed after signing, or the signature is forged'
      + (hc === 'simple' ? ' (simple canonicalization breaks if headers were re-folded, e.g. when copied from a mail client)' : ''));
  }

  if (body == null) return fail('pass-headers', 'signature verified; body not available, so the body hash was not checked');
  let canon = canonBody(body, bc);
  if (out.bodyLength != null) canon = Buffer.from(canon, 'latin1').subarray(0, out.bodyLength).toString('latin1');
  const bh = crypto.createHash(hashAlg).update(Buffer.from(canon, 'latin1')).digest('base64');
  if (bh !== tags.bh) return fail('body-mismatch', 'signature is valid but the body was modified after signing (e.g. a footer or disclaimer added by a gateway)');
  return fail('pass', 'signature and body hash verified');
}

async function verifyAll(headers, body, resolveTxt, now) {
  const sigs = headers.filter(h => h.name.toLowerCase() === 'dkim-signature');
  return Promise.all(sigs.map(s => verifySignature(s, headers, body, resolveTxt, now)));
}

module.exports = { verifyAll, verifySignature, canonHeader, canonBody, toDisplay };
