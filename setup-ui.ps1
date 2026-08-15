# Writes/overwrites the 6 UI files in the current folder.
# Run this FROM your project folder:
#   cd 'C:\Users\ASH\Downloads\Temporary Access'
#   powershell -ExecutionPolicy Bypass -File .\setup-ui.ps1

Write-Host "Writing server.js..."
@'
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

// ============ HTML pages ============

// The link in the email points here: /access/<9-digit-token>
app.get('/access/:token', (req, res) => {
  if (!/^\d{9}$/.test(req.params.token)) return res.status(404).send('Invalid access link');
  res.sendFile(path.join(__dirname, 'activate.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`temp-access listening on :${PORT}`));
'@ | Out-File -FilePath "server.js" -Encoding utf8 -NoNewline

Write-Host "Writing admin.html..."
@'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Grant Access — Admin</title>
<link rel="stylesheet" href="/styles.css" />
</head>
<body>
  <div class="ticket" style="max-width:440px">
    <div class="ticket-head">
      <div class="eyebrow">Admin</div>
      <h1>Grant temporary access</h1>
    </div>
    <div class="perf"></div>
    <div class="ticket-body">
      <label for="adminKey">Admin key</label>
      <input id="adminKey" type="password" placeholder="X-Admin-Key" />

      <label for="email">Email</label>
      <input id="email" type="email" placeholder="user@example.com" />

      <label for="duration">Access duration</label>
      <select id="duration">
        <option value="1">1 hour</option>
        <option value="8" selected>8 hours</option>
        <option value="24">24 hours</option>
        <option value="72">3 days</option>
        <option value="168">7 days</option>
      </select>

      <button class="primary" id="submit">Grant access</button>

      <div id="resultWrap" style="display:none; margin-top:20px">
        <div class="kv"><span>Status</span><span id="rStatus">&mdash;</span></div>
        <div class="kv"><span>Email</span><span id="rEmail">&mdash;</span></div>
        <div class="stamp" id="rDetail"></div>
      </div>
      <div class="error-text" id="errorText"></div>
    </div>
  </div>

<script>
  const $ = (id) => document.getElementById(id);

  $('submit').addEventListener('click', async () => {
    const adminKey = $('adminKey').value;
    const email = $('email').value;
    const durationHours = Number($('duration').value);
    const btn = $('submit');
    const err = $('errorText');
    err.classList.remove('show');
    $('resultWrap').style.display = 'none';
    btn.disabled = true;
    btn.textContent = 'Sending…';

    try {
      const res = await fetch('/api/admin/grants', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Admin-Key': adminKey },
        body: JSON.stringify({ email, durationHours }),
      });
      const data = await res.json();
      btn.disabled = false;
      btn.textContent = 'Grant access';

      if (!res.ok) {
        err.textContent = data.error || 'Request failed.';
        err.classList.add('show');
        return;
      }

      $('resultWrap').style.display = 'block';
      if (data.warning) {
        $('rStatus').textContent = 'Created (email failed)';
        $('rEmail').textContent = data.grant.email;
        $('rDetail').textContent = data.accessUrl || data.detail;
      } else {
        $('rStatus').textContent = 'Sent';
        $('rEmail').textContent = data.grant.email;
        $('rDetail').textContent = data.accessUrl;
      }
    } catch (e) {
      btn.disabled = false;
      btn.textContent = 'Grant access';
      err.textContent = 'Could not reach the server.';
      err.classList.add('show');
    }
  });
</script>
</body>
</html>
'@ | Out-File -FilePath "admin.html" -Encoding utf8 -NoNewline

Write-Host "Writing styles.css..."
@'
/* ---------- Temporary Access — shared design tokens ---------- */
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@500;600&display=swap');

:root {
  --ink: #12151c;
  --ink-soft: #1c212e;
  --paper: #f7f4ec;
  --paper-dim: #eae5d6;
  --brass: #c9a227;
  --moss: #3e7c6b;
  --rust: #b4432f;
  --slate: #6b7280;
  --line: rgba(18, 21, 28, 0.14);
  --radius: 14px;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px 16px;
  background: var(--ink);
  background-image:
    radial-gradient(circle at 20% 20%, rgba(201, 162, 39, 0.07), transparent 40%),
    radial-gradient(circle at 80% 80%, rgba(62, 124, 107, 0.08), transparent 45%);
  font-family: 'IBM Plex Sans', sans-serif;
  color: var(--ink);
}

.eyebrow {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--slate);
}

/* ---------- Ticket stub card ---------- */
.ticket {
  width: 100%;
  max-width: 400px;
  background: var(--paper);
  border-radius: var(--radius);
  box-shadow: 0 30px 60px -20px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04);
  overflow: hidden;
}

.ticket-head {
  padding: 28px 28px 20px;
}

.ticket-head h1 {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 22px;
  font-weight: 700;
  margin: 6px 0 0;
  letter-spacing: -0.01em;
}

.perf {
  position: relative;
  height: 0;
  border-top: 2px dashed var(--line);
  margin: 0 0 0;
}
.perf::before, .perf::after {
  content: '';
  position: absolute;
  top: -11px;
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: var(--ink);
}
.perf::before { left: -11px; }
.perf::after { right: -11px; }

.ticket-body {
  padding: 24px 28px 28px;
}

/* ---------- Status badge ---------- */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 5px 10px;
  border-radius: 999px;
}
.badge::before {
  content: '';
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
}
.badge.pending { color: var(--brass); background: rgba(201,162,39,0.14); }
.badge.active  { color: var(--moss);  background: rgba(62,124,107,0.14); }
.badge.error   { color: var(--rust);  background: rgba(180,67,47,0.14); }

/* ---------- Countdown ---------- */
.countdown {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 40px;
  font-weight: 600;
  letter-spacing: 0.02em;
  margin: 18px 0 4px;
  font-variant-numeric: tabular-nums;
}
.countdown-label {
  font-size: 11px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--slate);
}

/* ---------- Form elements ---------- */
label {
  display: block;
  font-size: 12px;
  font-weight: 500;
  color: var(--slate);
  margin: 16px 0 6px;
}
input, select {
  width: 100%;
  padding: 11px 12px;
  border-radius: 8px;
  border: 1px solid var(--line);
  background: #fff;
  font-family: 'IBM Plex Sans', sans-serif;
  font-size: 14px;
  color: var(--ink);
}
input:focus, select:focus, button:focus {
  outline: 2px solid var(--moss);
  outline-offset: 1px;
}

button.primary {
  width: 100%;
  margin-top: 20px;
  padding: 12px;
  border: none;
  border-radius: 8px;
  background: var(--ink);
  color: var(--paper);
  font-family: 'IBM Plex Sans', sans-serif;
  font-weight: 600;
  font-size: 14px;
  cursor: pointer;
  transition: transform 0.15s ease, background 0.15s ease;
}
button.primary:hover { background: #262b39; }
button.primary:active { transform: scale(0.98); }
button.primary:disabled { opacity: 0.5; cursor: not-allowed; }

button.ghost {
  width: 100%;
  margin-top: 10px;
  padding: 10px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: transparent;
  font-family: 'IBM Plex Sans', sans-serif;
  font-size: 13px;
  font-weight: 500;
  color: var(--slate);
  cursor: pointer;
}
button.ghost:hover { border-color: var(--slate); }

/* ---------- Misc ---------- */
.mono { font-family: 'IBM Plex Mono', monospace; }
.muted { color: var(--slate); font-size: 13px; line-height: 1.5; }
.error-text { color: var(--rust); font-size: 13px; margin-top: 10px; display: none; }
.error-text.show { display: block; }
.stamp {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
  color: var(--slate);
  margin-top: 18px;
  word-break: break-all;
}
.kv { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--line); font-size: 13px; }
.kv:last-child { border-bottom: none; }
.kv span:first-child { color: var(--slate); }
.kv span:last-child { font-family: 'IBM Plex Mono', monospace; font-weight: 500; }

@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; animation: none !important; }
}
'@ | Out-File -FilePath "styles.css" -Encoding utf8 -NoNewline

Write-Host "Writing login.html..."
@'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Log in — Temporary Access</title>
<link rel="stylesheet" href="/styles.css" />
</head>
<body>
  <div class="ticket">
    <div class="ticket-head">
      <div class="eyebrow">Temporary Access</div>
      <h1>Log in</h1>
    </div>
    <div class="perf"></div>
    <div class="ticket-body">
      <p class="muted">Use the email and temporary password from your access email.</p>

      <form id="loginForm">
        <label for="email">Email</label>
        <input id="email" type="email" autocomplete="username" required />

        <label for="password">Temporary password</label>
        <input id="password" type="password" autocomplete="current-password" required />

        <button class="primary" id="submitBtn" type="submit">Log in</button>
      </form>
      <div class="error-text" id="errorText"></div>
    </div>
  </div>

<script>
  const $ = (id) => document.getElementById(id);

  $('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = $('email').value.trim();
    const password = $('password').value;
    const btn = $('submitBtn');
    const err = $('errorText');
    err.classList.remove('show');
    btn.disabled = true;
    btn.textContent = 'Logging in…';

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();

      if (!res.ok) {
        err.textContent = data.error || 'Login failed.';
        err.classList.add('show');
        btn.disabled = false;
        btn.textContent = 'Log in';
        return;
      }

      sessionStorage.setItem('sessionToken', data.sessionToken);
      sessionStorage.setItem('expiresAt', data.expiresAt);
      window.location.href = '/dashboard.html';
    } catch (e2) {
      err.textContent = 'Could not reach the server.';
      err.classList.add('show');
      btn.disabled = false;
      btn.textContent = 'Log in';
    }
  });
</script>
</body>
</html>
'@ | Out-File -FilePath "login.html" -Encoding utf8 -NoNewline

Write-Host "Writing dashboard.html..."
@'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Dashboard — Temporary Access</title>
<link rel="stylesheet" href="/styles.css" />
</head>
<body>
  <div class="ticket">
    <div class="ticket-head">
      <div class="eyebrow" id="eyebrow">Checking session&hellip;</div>
      <h1 id="title">Dashboard</h1>
    </div>
    <div class="perf"></div>
    <div class="ticket-body" id="body" style="display:none">
      <span class="badge active">Authenticated</span>
      <div class="countdown" id="countdown">&mdash;</div>
      <div class="countdown-label">Access expires in</div>
      <div class="stamp" id="emailStamp"></div>
      <button class="ghost" id="logoutBtn">Log out</button>
    </div>
    <div class="ticket-body" id="deniedBody" style="display:none">
      <span class="badge error">Denied</span>
      <p class="muted" id="deniedMsg" style="margin-top:14px"></p>
      <button class="primary" id="toLoginBtn">Go to login</button>
    </div>
  </div>

<script>
  const $ = (id) => document.getElementById(id);
  const token = sessionStorage.getItem('sessionToken');
  const expiresAt = sessionStorage.getItem('expiresAt');

  function deny(message) {
    $('eyebrow').textContent = 'Temporary Access';
    $('title').textContent = 'Not authenticated';
    $('body').style.display = 'none';
    $('deniedBody').style.display = 'block';
    $('deniedMsg').textContent = message;
    $('toLoginBtn').addEventListener('click', () => window.location.href = '/login.html');
  }

  function formatRemaining(ms) {
    if (ms <= 0) return '00:00:00';
    const totalSec = Math.floor(ms / 1000);
    const h = String(Math.floor(totalSec / 3600)).padStart(2, '0');
    const m = String(Math.floor((totalSec % 3600) / 60)).padStart(2, '0');
    const s = String(totalSec % 60).padStart(2, '0');
    return `${h}:${m}:${s}`;
  }

  async function load() {
    if (!token) return deny('No active session. Log in to continue.');

    try {
      const res = await fetch('/api/app/me', {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();

      if (!res.ok) {
        sessionStorage.clear();
        return deny(data.error || 'Your session is no longer valid.');
      }

      $('eyebrow').textContent = 'Temporary Access';
      $('title').textContent = 'Welcome';
      $('body').style.display = 'block';
      $('emailStamp').textContent = data.email;

      const exp = new Date(expiresAt).getTime();
      const tick = () => {
        const remaining = exp - Date.now();
        $('countdown').textContent = formatRemaining(remaining);
        if (remaining <= 0) {
          sessionStorage.clear();
          deny('Your access window has ended.');
        }
      };
      tick();
      setInterval(tick, 1000);
    } catch (e) {
      deny('Could not reach the server.');
    }
  }

  $('logoutBtn').addEventListener('click', () => {
    sessionStorage.clear();
    window.location.href = '/login.html';
  });

  load();
</script>
</body>
</html>
'@ | Out-File -FilePath "dashboard.html" -Encoding utf8 -NoNewline

Write-Host "Writing activate.html..."
@'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Activate access</title>
<link rel="stylesheet" href="/styles.css" />
</head>
<body>
  <div class="ticket">
    <div class="ticket-head">
      <div class="eyebrow" id="eyebrow">Checking pass&hellip;</div>
      <h1 id="title">Temporary Access</h1>
    </div>
    <div class="perf"></div>
    <div class="ticket-body" id="body">
      <span class="badge pending" id="badge">Verifying</span>
      <div class="countdown" id="countdown">&mdash;</div>
      <div class="countdown-label" id="countdownLabel">&nbsp;</div>
      <p class="muted" id="message">Reading your access link&hellip;</p>
      <button class="primary" id="continueBtn" style="display:none">Continue to login</button>
      <div class="error-text" id="errorText"></div>
    </div>
  </div>

<script>
  const token = window.location.pathname.replace(/^\//, '');
  const $ = (id) => document.getElementById(id);

  function setBadge(state, text) {
    const b = $('badge');
    b.className = 'badge ' + state;
    b.textContent = text;
  }

  function formatRemaining(ms) {
    if (ms <= 0) return '00:00:00';
    const totalSec = Math.floor(ms / 1000);
    const h = String(Math.floor(totalSec / 3600)).padStart(2, '0');
    const m = String(Math.floor((totalSec % 3600) / 60)).padStart(2, '0');
    const s = String(totalSec % 60).padStart(2, '0');
    return `${h}:${m}:${s}`;
  }

  let tickHandle;
  function startCountdown(expiresAtIso) {
    const expiresAt = new Date(expiresAtIso).getTime();
    $('countdownLabel').textContent = 'Time remaining';
    const tick = () => {
      const remaining = expiresAt - Date.now();
      $('countdown').textContent = formatRemaining(remaining);
      if (remaining <= 0) clearInterval(tickHandle);
    };
    tick();
    tickHandle = setInterval(tick, 1000);
  }

  async function activate() {
    try {
      const res = await fetch(`/api/activate/${token}`);
      const data = await res.json();

      if (!res.ok) {
        setBadge('error', 'Invalid');
        $('eyebrow').textContent = 'Access link';
        $('title').textContent = 'Not available';
        $('message').textContent = data.error || 'This link could not be verified.';
        $('countdownLabel').textContent = '';
        return;
      }

      setBadge('active', 'Active');
      $('eyebrow').textContent = 'Access link';
      $('title').textContent = 'Pass activated';
      $('message').textContent = 'Your access window has started. Log in with the credentials from your email to continue.';
      startCountdown(data.expiresAt);
      $('continueBtn').style.display = 'block';
      $('continueBtn').addEventListener('click', () => {
        window.location.href = '/login.html';
      });
    } catch (err) {
      setBadge('error', 'Error');
      $('message').textContent = 'Could not reach the server. Check your connection and try again.';
    }
  }

  activate();
</script>
</body>
</html>
'@ | Out-File -FilePath "activate.html" -Encoding utf8 -NoNewline

Write-Host "Done. 6 files written." -ForegroundColor Green
