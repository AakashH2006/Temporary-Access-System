require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ---------- crypto helpers ----------
function generateToken() {
  const n = crypto.randomInt(100000000, 1000000000);
  return String(n);
}
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function generatePassword(length = 16) {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += charset[bytes[i] % charset.length];
  return out;
}
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(12);
  return bcrypt.hash(password, salt);
}
async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// ---------- email ----------
async function sendAccessEmail({ to, accessUrl, username, password, durationLabel }) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM;
  const text = `Your temporary access has been created.\n\nAccess URL:\n${accessUrl}\n\nUsername:\n${username}\n\nTemporary Password:\n${password}\n\nAccess Duration:\n${durationLabel}`;
  const html = `<p>Your temporary access has been created.</p><p><b>Access URL:</b><br><a href="${accessUrl}">${accessUrl}</a></p><p><b>Username:</b><br>${username}</p><p><b>Temporary Password:</b><br><code>${password}</code></p><p><b>Access Duration:</b><br>${durationLabel}</p>`;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to, subject: 'Your temporary access', text, html }),
  });
  if (!res.ok) throw new Error(`Email send failed: ${res.status} ${await res.text()}`);
  return res.json();
}

// ---------- middleware ----------
function adminAuth(req, res, next) {
  const key = req.header('X-Admin-Key');
  if (!key || key !== process.env.ADMIN_API_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

async function requireSession(req, res, next) {
  const auth = req.header('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing session token' });
  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
  const { rows } = await pool.query('SELECT status, expires_at FROM access_grants WHERE id = $1', [payload.grantId]);
  const grant = rows[0];
  if (!grant || grant.status !== 'ACTIVE') return res.status(401).json({ error: 'Access no longer valid' });
  if (new Date() > new Date(grant.expires_at)) {
    await pool.query("UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1", [payload.grantId]);
    return res.status(401).json({ error: 'Access expired' });
  }
  req.grant = { id: payload.grantId, email: payload.email };
  next();
}

// ---------- app ----------
const app = express();
app.use(express.json());
app.use(express.static(__dirname)); // serves admin.html, login.html, dashboard.html, activate.html, styles.css
app.use(rateLimit({ windowMs: 60_000, max: 300 }));

app.get('/health', (_req, res) => res.json({ ok: true }));

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_DURATION_HOURS = 24 * 30;
const createLimiter = rateLimit({ windowMs: 60_000, max: 20 });
const activateLimiter = rateLimit({ windowMs: 60_000, max: 30 });
const loginLimiter = rateLimit({ windowMs: 60_000, max: 10 });

// ============ JSON API (all under /api) ============

// -- admin: create grant --
app.post('/api/admin/grants', adminAuth, createLimiter, async (req, res) => {
  const { email, durationHours } = req.body || {};
  if (!email || !EMAIL_RE.test(email)) return res.status(400).json({ error: 'Valid email required' });
  const hours = Number(durationHours);
  if (!Number.isFinite(hours) || hours <= 0 || hours > MAX_DURATION_HOURS)
    return res.status(400).json({ error: `durationHours must be > 0 and <= ${MAX_DURATION_HOURS}` });

  const token = generateToken();
  const password = generatePassword();
  const tokenHash = hashToken(token);
  const passwordHash = await hashPassword(password);
  const durationSeconds = Math.round(hours * 3600);

  let grant;
  try {
    const { rows } = await pool.query(
      `INSERT INTO access_grants (email, token_hash, password_hash, duration_seconds, status)
       VALUES ($1, $2, $3, $4, 'PENDING') RETURNING id, email, status, created_at`,
      [email, tokenHash, passwordHash, durationSeconds]
    );
    grant = rows[0];
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Token collision, please retry' });
    throw err;
  }

  // Access link now points at the HTML activation page, not the raw API.
  const accessUrl = `${process.env.PUBLIC_BASE_URL}/access/${token}`;
  const durationLabel = `${hours} hour${hours === 1 ? '' : 's'}`;

  try {
    await sendAccessEmail({ to: email, accessUrl, username: email, password, durationLabel });
  } catch (err) {
    return res.status(202).json({
      warning: 'Grant created but email failed to send',
      detail: err.message,
      grant: { id: grant.id, email: grant.email, status: grant.status },
      accessUrl,
    });
  }

  res.status(201).json({ grant: { id: grant.id, email: grant.email, status: grant.status, createdAt: grant.created_at }, accessUrl });
});

// -- admin: list grants --
app.get('/api/admin/grants', adminAuth, async (_req, res) => {
  const { rows } = await pool.query(
    'SELECT id, email, status, created_at, activated_at, expires_at FROM access_grants ORDER BY created_at DESC LIMIT 100'
  );
  res.json({ grants: rows });
});

// -- admin: revoke --
app.post('/api/admin/grants/:id/revoke', adminAuth, async (req, res) => {
  const { rows } = await pool.query(
    "UPDATE access_grants SET status = 'REVOKED' WHERE id = $1 AND status IN ('PENDING','ACTIVE') RETURNING id, status",
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Grant not found or not revocable' });
  res.json({ grant: rows[0] });
});

// -- activate access link (called by activate.html via fetch) --
app.get('/api/activate/:token', activateLimiter, async (req, res) => {
  if (!/^\d{9}$/.test(req.params.token)) {
    return res.status(404).json({ error: 'Invalid or expired access link' });
  }
  const tokenHash = hashToken(req.params.token);
  const { rows } = await pool.query('SELECT * FROM access_grants WHERE token_hash = $1', [tokenHash]);
  const grant = rows[0];
  if (!grant) return res.status(404).json({ error: 'Invalid or expired access link' });

  if (grant.status === 'PENDING') {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + grant.duration_seconds * 1000);
    await pool.query("UPDATE access_grants SET status = 'ACTIVE', activated_at = $1, expires_at = $2 WHERE id = $3", [now, expiresAt, grant.id]);
    return res.json({ message: 'Access activated.', activatedAt: now, expiresAt });
  }
  if (grant.status === 'ACTIVE') {
    if (new Date() > new Date(grant.expires_at)) {
      await pool.query("UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1", [grant.id]);
      return res.status(410).json({ error: 'This access link has expired' });
    }
    return res.json({ message: 'Access already active.', expiresAt: grant.expires_at });
  }
  res.status(410).json({ error: 'This access link is no longer valid' });
});

// -- login --
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const { rows } = await pool.query(
    "SELECT * FROM access_grants WHERE email = $1 AND status = 'ACTIVE' ORDER BY created_at DESC LIMIT 1",
    [email]
  );
  const grant = rows[0];
  const fail = () => res.status(401).json({ error: 'Invalid credentials' });
  if (!grant) return fail();

  if (new Date() > new Date(grant.expires_at)) {
    await pool.query("UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1", [grant.id]);
    return res.status(401).json({ error: 'Access expired' });
  }

  const ok = await verifyPassword(password, grant.password_hash);
  if (!ok) return fail();

  const sessionTtl = Number(process.env.SESSION_TTL_SECONDS || 3600);
  const capExpiry = new Date(grant.expires_at).getTime();
  const sessionExpiry = Math.min(Date.now() + sessionTtl * 1000, capExpiry);
  const expiresInSeconds = Math.floor((sessionExpiry - Date.now()) / 1000);

  const sessionToken = jwt.sign({ grantId: grant.id, email: grant.email }, process.env.JWT_SECRET, { expiresIn: expiresInSeconds });
  res.json({ sessionToken, expiresAt: new Date(sessionExpiry) });
});

// -- protected: current user --
app.get('/api/app/me', requireSession, (req, res) => {
  res.json({ email: req.grant.email, message: 'You are authenticated.' });
});

// -- logout: kills the grant, not just the session --
app.post('/api/auth/logout', requireSession, async (req, res) => {
  await pool.query(
    "UPDATE access_grants SET status = 'REVOKED' WHERE id = $1",
    [req.grant.id]
  );
  res.json({ message: 'Access revoked. This pass can no longer be used to log in.' });
});

// ============ HTML pages ============

// The link in the email points here: /access/<9-digit-token>
app.get('/access/:token', (req, res) => {
  if (!/^\d{9}$/.test(req.params.token)) return res.status(404).send('Invalid access link');
  res.sendFile(path.join(__dirname, 'activate.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`temp-access listening on :${PORT}`));