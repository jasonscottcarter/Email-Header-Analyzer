const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const http = require('http');
const app = require('../server');

let server, base;
test.before(() => new Promise(resolve => {
  server = app.listen(0, '127.0.0.1', () => {
    base = `http://127.0.0.1:${server.address().port}`;
    resolve();
  });
}));
test.after(() => server.close());

function request(pathname, { method = 'POST', body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(base + pathname, { method, headers }, res => {
      let data = '';
      res.on('data', c => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

const phish = fs.readFileSync(path.join(__dirname, 'fixtures', 'phish-headers.txt'));

test('analyzes pasted headers', async () => {
  const res = await request('/analyze', { body: JSON.stringify({ text: phish.toString('utf8'), live: false }), headers: { 'Content-Type': 'application/json' } });
  assert.equal(res.status, 200);
  const r = JSON.parse(res.body);
  assert.equal(r.verdict.level, 'high');
  assert.equal(r.source.kind, 'paste');
});

test('analyzes an uploaded .eml file', async () => {
  const res = await request('/analyze-file?live=0', { body: phish, headers: { 'Content-Type': 'application/octet-stream' } });
  assert.equal(res.status, 200);
  assert.equal(JSON.parse(res.body).source.kind, 'eml');
});

test('rejects a corrupt .msg with a readable error', async () => {
  const junk = Buffer.concat([Buffer.from('d0cf11e0a1b11ae1', 'hex'), Buffer.alloc(600, 7)]);
  const res = await request('/analyze-file?live=0', { body: junk, headers: { 'Content-Type': 'application/octet-stream' } });
  assert.equal(res.status, 400);
  assert.match(JSON.parse(res.body).error, /\.msg/);
});

test('empty input is a 400, not a crash', async () => {
  const res = await request('/analyze', { body: JSON.stringify({ text: '   ' }), headers: { 'Content-Type': 'application/json' } });
  assert.equal(res.status, 400);
});

test('requests for other host names are refused (DNS rebinding protection)', async () => {
  const res = await request('/', { method: 'GET', headers: { Host: 'attacker.example' } });
  assert.equal(res.status, 403);
});

test('serves the page with a Content-Security-Policy', async () => {
  const res = await request('/', { method: 'GET' });
  assert.equal(res.status, 200);
  assert.match(res.headers['content-security-policy'], /default-src 'self'/);
});
