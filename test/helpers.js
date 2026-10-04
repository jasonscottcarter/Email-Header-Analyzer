// Test helpers: an in-memory DNS resolver and a DKIM signer (mailauth's, independent of our verifier).
const crypto = require('crypto');
const { dkimSign } = require('mailauth/lib/dkim/sign');

function dnsError(code) {
  return Object.assign(new Error(code), { code });
}

// records: { 'name': { TXT: ['...'], A: ['1.2.3.4'], PTR: ['host'] }, ... }  (TXT strings, other types arrays)
function fakeResolver(records = {}, { failNames = [] } = {}) {
  const lookup = (name, type) => {
    name = name.toLowerCase().replace(/\.$/, '');
    if (failNames.includes(name)) return Promise.reject(dnsError('ETIMEOUT'));
    const rec = records[name]?.[type];
    if (!rec) return Promise.reject(dnsError(records[name] ? 'ENODATA' : 'ENOTFOUND'));
    return Promise.resolve(type === 'TXT' ? rec.map(t => [t]) : rec);
  };
  return {
    resolveTxt: n => lookup(n, 'TXT'),
    resolve4: n => lookup(n, 'A'),
    resolve6: n => lookup(n, 'AAAA'),
    reverse: ip => lookup(ip, 'PTR'),
    resolve: (n, type) => lookup(n, type),
  };
}

function rsaKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    privatePem: privateKey.export({ type: 'pkcs1', format: 'pem' }),
    dnsP: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };
}

function ed25519Key() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    dnsP: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64'),
  };
}

async function sign(message, { domain, selector, privatePem, algorithm = 'rsa-sha256', canonicalization = 'relaxed/relaxed' }) {
  const res = await dkimSign(message, {
    canonicalization, algorithm,
    signatureData: [{ signingDomain: domain, selector, privateKey: privatePem }],
  });
  if (res.errors.length) throw new Error(JSON.stringify(res.errors));
  return res.signatures + message;
}

module.exports = { fakeResolver, rsaKey, ed25519Key, sign, dnsError };
