// Express, written the way many tutorials and READMEs end up in production.
// Every "MISTAKE" comment maps to a paragraph in the article.
import express from 'express';
import bcrypt from 'bcryptjs';

const app = express();

// MISTAKE: a large upload failed once, so the limit went from 100kb to 50mb.
// Every large body now blocks the event loop for the whole JSON.parse.
app.use(express.json({ limit: '50mb' }));

// MISTAKE: "trust proxy" copied from a README. req.ip is now the LEFTMOST
// X-Forwarded-For entry, which any client can set.
app.set('trust proxy', true);

// MISTAKE: nested quantifier -> catastrophic backtracking (ReDoS).
const SLUG = /^([a-z0-9]+-?)*$/;

const USER = { name: 'alice', hash: bcrypt.hashSync('correct horse battery staple', 10) };

const hits = new Map();
function rateLimited(key, limit = 5, windowMs = 60_000) {
  const now = Date.now();
  const e = hits.get(key);
  if (!e || now - e.start > windowMs) {
    hits.set(key, { start: now, n: 1 });
    return false;
  }
  return ++e.n > limit;
}

app.get('/healthz', (req, res) => res.send('ok'));

app.get('/search', (req, res) => {
  const q = String(req.query.q ?? '');
  res.json({ q, valid: SLUG.test(q) });
});

app.post('/orders', (req, res) => {
  const { sku, qty } = req.body ?? {};
  if (typeof sku !== 'string' || sku.length > 64 || !Number.isInteger(qty) || qty < 1 || qty > 100) {
    return res.sendStatus(400);
  }
  res.sendStatus(202);
});

app.post('/login', (req, res) => {
  if (rateLimited(req.ip)) return res.sendStatus(429); // keyed on a forgeable IP
  const { username, password } = req.body ?? {};
  // MISTAKE: synchronous bcrypt on the event loop.
  const ok = username === USER.name && bcrypt.compareSync(String(password ?? ''), USER.hash);
  res.sendStatus(ok ? 200 : 401);
});

app.post('/hash', (req, res) => {
  // MISTAKE: ~50-100 ms of CPU on the event loop per call.
  res.json({ hash: bcrypt.hashSync(String(req.body?.password ?? ''), 10) });
});

// MISTAKE: default Node timeouts (60 s for headers, 300 s per request).
const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => console.log(`express-vulnerable listening on :${port}`));
