const express = require('express');
const path = require('path');
const { analyzeMessage } = require('./lib/analyze');
const { isMsg, msgHeaders } = require('./lib/msg');

const PORT = Number(process.env.PORT) || 3002;
const HOST = '127.0.0.1'; // local use only - never listen on the network

const app = express();
app.disable('x-powered-by');

// Only answer requests addressed to this machine (blocks DNS-rebinding attacks from web pages).
app.use((req, res, next) => {
  const host = (req.headers.host || '').replace(/:\d+$/, '');
  if (!['localhost', '127.0.0.1', '[::1]'].includes(host)) return res.status(403).send('Forbidden');
  next();
});
app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

async function respond(res, raw, source, live) {
  try {
    res.json(await analyzeMessage(raw, { source, live }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
}

// Pasted text
app.post('/analyze', express.json({ limit: '5mb' }), (req, res) => {
  const { text, live = true } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: 'Paste an email header first.' });
  respond(res, Buffer.from(text, 'utf8').toString('latin1'), 'paste', !!live);
});

// Dropped / chosen file (.eml or .msg) sent as raw bytes
app.post('/analyze-file', express.raw({ type: () => true, limit: '30mb' }), (req, res) => {
  const buf = req.body;
  if (!Buffer.isBuffer(buf) || !buf.length) return res.status(400).json({ error: 'The file is empty.' });
  const live = req.query.live !== '0';
  if (isMsg(buf)) {
    let raw;
    try {
      raw = msgHeaders(buf);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    return respond(res, raw, 'msg', live);
  }
  respond(res, buf.toString('latin1'), 'eml', live);
});

if (require.main === module) {
  app.listen(PORT, HOST, () => console.log(`Email Header Analyzer running at http://localhost:${PORT}`));
}

module.exports = app;
