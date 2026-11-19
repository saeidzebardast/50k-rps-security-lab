// Express with the article's controls applied.
import http from 'node:http';
import express from 'express';
// Native bcrypt hashes on the libuv thread pool, off the event loop.
// (bcryptjs' async API only yields between rounds; the CPU work still runs
// on the main thread, and the lab's `blocking` test shows the difference.)
import bcrypt from 'bcrypt';

const app = express();
app.disable('x-powered-by');

// Bound the request before you parse it. body-parser checks Content-Length
// up front and answers 413 without reading the body.
app.use(express.json({ limit: '64kb' }));

// Only believe X-Forwarded-For when it was written by a proxy we run.
// Unset (the default) means: use the socket address.
app.set('trust proxy', process.env.TRUST_PROXY || false);

// Unambiguous pattern: every character can only be matched one way, so
// matching is linear. Plus a length cap, because linear is not free either.
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const MAX_SLUG = 64;

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
setInterval(() => {
  const now = Date.now();
  for (const [k, e] of hits) if (now - e.start > 60_000) hits.delete(k);
}, 30_000).unref();

// Stand-in for a database call that honours an AbortSignal.
function saveOrder(order, signal) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, 5);
    signal.addEventListener('abort', () => { clearTimeout(t); reject(signal.reason); }, { once: true });
  });
}

app.get('/healthz', (req, res) => res.send('ok'));

app.get('/search', (req, res) => {
  const q = String(req.query.q ?? '');
  if (q.length > MAX_SLUG) return res.sendStatus(400);
  res.json({ q, valid: SLUG.test(q) });
});

app.post('/orders', async (req, res) => {
  const { sku, qty } = req.body ?? {};
  if (typeof sku !== 'string' || sku.length > 64 || !Number.isInteger(qty) || qty < 1 || qty > 100) {
    return res.sendStatus(400);
  }
  try {
    // Carry a deadline through every call.
    await saveOrder({ sku, qty }, AbortSignal.timeout(800));
    res.sendStatus(202);
  } catch {
    res.sendStatus(503);
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body ?? {};
  // Per client IP (from the socket) AND per account.
  if (rateLimited(`ip:${req.ip}`) || rateLimited(`user:${String(username)}`)) return res.sendStatus(429);
  const ok = username === USER.name && (await bcrypt.compare(String(password ?? ''), USER.hash));
  res.sendStatus(ok ? 200 : 401);
});

app.post('/hash', async (req, res) => {
  res.json({ hash: await bcrypt.hash(String(req.body?.password ?? ''), 10) });
});

// Timeouts tuned for hostility, not patience. headersTimeout is only
// enforced every connectionsCheckingInterval (30 s by default), so lower it too.
const server = http.createServer(
  {
    headersTimeout: 5_000,
    requestTimeout: 10_000,
    connectionsCheckingInterval: 1_000,
    maxHeaderSize: 16 * 1024,
  },
  app,
);
server.keepAliveTimeout = 5_000;

const port = Number(process.env.PORT ?? 3000);
server.listen(port, () => console.log(`express-hardened listening on :${port}`));

for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => process.exit(0)));
