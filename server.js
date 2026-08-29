require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const ipaddr = require('ipaddr.js');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

// ============================================================
// Config
// ============================================================
// Fail at boot, not at the first request. A gateway that starts without an
// upstream or a signing secret is worse than one that refuses to start: it
// looks healthy while being either useless or insecure.
const REQUIRED = ['DATABASE_URL', 'JWT_SECRET', 'PUBLIC_BASE_URL', 'UPSTREAM_URL'];
const missing = REQUIRED.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`Refusing to start. Missing required env vars: ${missing.join(', ')}`);
  process.exit(1);
}
if (process.env.JWT_SECRET.length < 32) {
  console.error('Refusing to start. JWT_SECRET must be at least 32 characters.');
  process.exit(1);
}

// Every gateway-owned URL lives under this one prefix. Everything else on
// this origin is forwarded to the upstream app untouched, so the app keeps
// its own URL structure and its root-relative links keep working. Reserving
// a single namespace is what makes that collision-free -- the app is free to
// have its own /api, /login or /admin.
const GATE = '/__access';

const PORT = Number(process.env.PORT || 3000);
const UPSTREAM_URL = process.env.UPSTREAM_URL;
const COOKIE_NAME = 'ta_session';
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true'
  || process.env.PUBLIC_BASE_URL.startsWith('https://');
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 3600);
const MAX_DURATION_HOURS = Number(process.env.MAX_DURATION_HOURS || 24 * 30);
const SWEEP_INTERVAL_MS = Number(process.env.SWEEP_INTERVAL_MS || 60_000);
const GRANT_CACHE_TTL_MS = Number(process.env.GRANT_CACHE_TTL_MS || 5000);
const INJECT_BANNER = process.env.INJECT_BANNER !== 'false';
const STRIP_UPSTREAM_CSP = process.env.STRIP_UPSTREAM_CSP === 'true';

// ---- admin ----
const ADMIN_COOKIE_NAME = 'ta_admin';
const ADMIN_SESSION_TTL_SECONDS = Number(process.env.ADMIN_SESSION_TTL_SECONDS || 3600);
const ADMIN_MAX_FAILED_ATTEMPTS = Number(process.env.ADMIN_MAX_FAILED_ATTEMPTS || 5);
const ADMIN_LOCKOUT_MINUTES = Number(process.env.ADMIN_LOCKOUT_MINUTES || 15);
const ADMIN_MIN_PASSWORD_LENGTH = 12;

// Admin sessions are signed with a key *derived* from JWT_SECRET rather than
// with JWT_SECRET itself. Both cookies would otherwise verify against the same
// secret, and a customer's session token could be replayed as an admin token.
// Deriving the key makes that fail at the signature check, structurally --
// rather than depending on someone remembering to check a claim.
const ADMIN_JWT_KEY = crypto
  .createHmac('sha256', process.env.JWT_SECRET)
  .update('admin-sessions-v1')
  .digest();

// Comma-separated CIDRs allowed to reach the admin console. Empty means no
// restriction, which keeps local development working; production should scope
// this to the VPN or office range so the console is not answerable to the
// public internet at all.
const ADMIN_IP_ALLOWLIST = (process.env.ADMIN_IP_ALLOWLIST || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
  .map((cidr) => {
    try {
      return cidr.includes('/') ? ipaddr.parseCIDR(cidr) : ipaddr.parseCIDR(`${cidr}/32`);
    } catch {
      console.error(`Refusing to start. ADMIN_IP_ALLOWLIST entry is not valid CIDR: ${cidr}`);
      process.exit(1);
    }
  });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Managed Postgres (Neon/Supabase/RDS) requires TLS; a local socket does not.
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

// ============================================================
// Crypto helpers
// ============================================================
function generateToken() {
  return String(crypto.randomInt(100000000, 1000000000));
}
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function generatePassword(length = 16) {
  // Ambiguous glyphs (0/O, 1/l/I) are omitted: these passwords get read off a
  // screen and retyped by hand, so transcription errors are the failure mode
  // actually worth designing against.
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += charset[bytes[i] % charset.length];
  return out;
}
async function hashPassword(password) {
  return bcrypt.hash(password, await bcrypt.genSalt(12));
}

// ============================================================
// Email
// ============================================================
async function sendAccessEmail({ to, accessUrl, username, password, durationLabel }) {
  if (!process.env.RESEND_API_KEY) throw new Error('RESEND_API_KEY is not configured');

  const text = `Your temporary access has been created.

Access URL:
${accessUrl}

Username:
${username}

Temporary Password:
${password}

Access Duration:
${durationLabel}

The countdown starts when you open the access URL, not now.`;

  const html = `<p>Your temporary access has been created.</p>
<p><b>Access URL:</b><br><a href="${accessUrl}">${accessUrl}</a></p>
<p><b>Username:</b><br>${username}</p>
<p><b>Temporary Password:</b><br><code>${password}</code></p>
<p><b>Access Duration:</b><br>${durationLabel}</p>
<p style="color:#6b7280;font-size:13px">The countdown starts when you open the access URL, not now.</p>`;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: process.env.EMAIL_FROM,
      to,
      subject: 'Your temporary access',
      text,
      html,
    }),
  });
  if (!res.ok) throw new Error(`Email send failed: ${res.status} ${await res.text()}`);
  return res.json();
}

// ============================================================
// Audit log
// ============================================================
// Append-only, and never allowed to break the calling request: if the audit
// insert itself fails we log to stderr rather than fail a user-facing flow
// for a logging problem. `req` may be null for events raised by background
// jobs, which have no request context.
async function audit(req, { grantId = null, event, actor = null, detail = null }) {
  try {
    const ip = req ? (req.ip || req.socket?.remoteAddress || null) : null;
    const userAgent = req ? (req.header?.('User-Agent') || null) : null;
    await pool.query(
      `INSERT INTO audit_log (grant_id, event, actor, ip_address, user_agent, detail)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [grantId, event, actor, ip, userAgent, detail ? JSON.stringify(detail) : null]
    );
  } catch (err) {
    console.error('audit log write failed:', err.message);
  }
}

// ============================================================
// Grant status cache
// ============================================================
// The proxy re-authorizes on EVERY forwarded request, including every image
// and stylesheet the upstream app pulls in. Hitting Postgres for each of
// those would make the gateway the slowest thing in the stack, so statuses
// are cached for a few seconds. Revocation stays effectively instant because
// logout and admin-revoke bust the entry directly; the TTL is only the worst
// case for a change made by some other process.
const grantCache = new Map();

function cacheBust(grantId) {
  grantCache.delete(grantId);
}

async function loadGrant(grantId) {
  const hit = grantCache.get(grantId);
  if (hit && Date.now() - hit.at < GRANT_CACHE_TTL_MS) return hit.grant;
  const { rows } = await pool.query(
    'SELECT id, email, status, expires_at FROM access_grants WHERE id = $1',
    [grantId]
  );
  const grant = rows[0] || null;
  grantCache.set(grantId, { at: Date.now(), grant });
  return grant;
}

// ============================================================
// Session resolution
// ============================================================
// Sessions are carried in an httpOnly cookie rather than an Authorization
// header. The proxy forces this: when the browser loads the upstream app's
// own stylesheets, scripts and XHRs, it attaches cookies but never a bearer
// token. A header-based session simply cannot gate a reverse proxy.
function readSessionCookie(req) {
  if (req.cookies && req.cookies[COOKIE_NAME]) return req.cookies[COOKIE_NAME];
  // Raw-header fallback for the websocket upgrade path, which does not run
  // through Express middleware and so has no req.cookies.
  const raw = req.headers?.cookie;
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === COOKIE_NAME) return decodeURIComponent(v.join('='));
  }
  return null;
}

// Returns { ok: true, session } or { ok: false, reason }. Verifying the JWT
// signature is necessary but not sufficient -- the grant is re-read so that a
// revoked or expired grant kills the session immediately, instead of lingering
// until the token's own expiry catches up.
async function resolveSession(req) {
  const token = readSessionCookie(req);
  if (!token) return { ok: false, reason: 'no_session' };

  let payload;
  let sessionLapsed = false;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    if (err.name !== 'TokenExpiredError') return { ok: false, reason: 'bad_token' };
    // The session is capped at the grant's expiry, so when a window closes
    // naturally the JWT and the grant expire at the same instant. Reporting
    // 'bad_token' there would tell a customer their session was unverifiable
    // when in truth their time simply ran out. Re-read the token with the
    // signature still enforced, purely to name the reason accurately -- the
    // grant lookup below remains the thing that actually decides access.
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: true });
      sessionLapsed = true;
    } catch {
      return { ok: false, reason: 'bad_token' };
    }
  }

  const grant = await loadGrant(payload.grantId);
  if (!grant) return { ok: false, reason: 'grant_missing' };
  if (grant.status === 'REVOKED') return { ok: false, reason: 'revoked' };
  // A window can be closed either by the background sweeper or lazily by the
  // check further down, depending on which got there first. Both mean the same
  // thing to the customer, so both must report the same reason -- otherwise
  // the message they see depends on timing they cannot observe.
  if (grant.status === 'EXPIRED') return { ok: false, reason: 'expired' };
  if (grant.status !== 'ACTIVE') return { ok: false, reason: 'not_active' };

  if (grant.expires_at && new Date() > new Date(grant.expires_at)) {
    await pool.query("UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1", [grant.id]);
    cacheBust(grant.id);
    await audit(req, { grantId: grant.id, event: 'GRANT_EXPIRED', actor: 'system' });
    return { ok: false, reason: 'expired' };
  }

  // The grant is still open but this particular login has aged out. That is a
  // materially different message from 'expired': the customer still has time
  // left and can simply log in again with the same emailed credentials.
  if (sessionLapsed) return { ok: false, reason: 'session_expired' };

  return {
    ok: true,
    session: { grantId: grant.id, email: grant.email, expiresAt: grant.expires_at },
  };
}

// ============================================================
// Middleware
// ============================================================
function cookieOptions() {
  return { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'lax', path: '/' };
}

function adminCookieOptions() {
  // sameSite 'strict' rather than the customer cookie's 'lax'. The admin
  // console is never reached by cross-site navigation, and strict is what
  // stops a cross-site POST from riding an authenticated admin's cookie --
  // this is the CSRF control for every state-changing admin route.
  return { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'strict', path: GATE };
}

// Normalises an IPv4-mapped IPv6 address (::ffff:10.0.0.5) down to plain IPv4.
// Without this every IPv4 admin is denied on a dual-stack host, because the
// address arrives in v6 form and never matches a v4 CIDR.
function clientAddr(req) {
  const raw = req.ip || req.socket?.remoteAddress || '';
  try {
    const parsed = ipaddr.parse(raw.replace(/^::ffff:/i, ''));
    return parsed;
  } catch {
    return null;
  }
}

// First line of defence for the admin console: network position. The premise
// of this whole system is that admins have VPN access and customers do not,
// so the console has no business answering the public internet.
async function adminIpAllowlist(req, res, next) {
  if (!ADMIN_IP_ALLOWLIST.length) return next();

  const addr = clientAddr(req);
  const allowed = addr && ADMIN_IP_ALLOWLIST.some((cidr) => {
    // A v4 address cannot match a v6 range or vice versa; match() throws on
    // a kind mismatch rather than returning false.
    if (cidr[0].kind() !== addr.kind()) return false;
    return addr.match(cidr);
  });

  if (!allowed) {
    await audit(req, {
      event: 'ADMIN_IP_DENIED',
      actor: 'system',
      detail: { ip: req.ip || null, path: req.originalUrl },
    });
    // 404 rather than 403: an address that isn't permitted to use the console
    // learns nothing about whether one exists here.
    return res.status(404).json({ error: 'Not found' });
  }
  next();
}

// Mirrors requireSessionApi for customers: the admin row is re-read on every
// request, so disabling an account takes effect immediately rather than
// whenever the token happens to expire.
async function requireAdminSession(req, res, next) {
  const token = req.cookies?.[ADMIN_COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Admin authentication required' });

  let payload;
  try {
    payload = jwt.verify(token, ADMIN_JWT_KEY);
  } catch {
    res.clearCookie(ADMIN_COOKIE_NAME, adminCookieOptions());
    return res.status(401).json({ error: 'Admin session invalid or expired' });
  }
  // Belt-and-braces alongside the derived signing key above.
  if (payload.typ !== 'admin') {
    res.clearCookie(ADMIN_COOKIE_NAME, adminCookieOptions());
    return res.status(401).json({ error: 'Admin session invalid' });
  }

  const { rows } = await pool.query(
    'SELECT id, email, disabled_at FROM admins WHERE id = $1',
    [payload.adminId]
  );
  const admin = rows[0];
  if (!admin || admin.disabled_at) {
    res.clearCookie(ADMIN_COOKIE_NAME, adminCookieOptions());
    return res.status(401).json({ error: 'Admin account is no longer active' });
  }

  req.admin = { id: admin.id, email: admin.email };
  next();
}

// Applied to every admin route, in order: network first, then identity.
const adminOnly = [adminIpAllowlist, requireAdminSession];

async function requireSessionApi(req, res, next) {
  const result = await resolveSession(req);
  if (!result.ok) {
    res.clearCookie(COOKIE_NAME, cookieOptions());
    return res.status(401).json({ error: 'Access no longer valid', reason: result.reason });
  }
  req.session = result.session;
  next();
}

// ============================================================
// App
// ============================================================
const app = express();

// Only trust X-Forwarded-For when a reverse proxy is genuinely in front.
// Trusting it unconditionally would let any client spoof its own IP in the
// audit log and evade per-IP rate limiting.
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(cookieParser());

// Body parsing is scoped to the gate's own API. Applying express.json()
// globally would consume the request stream before the proxy could forward
// it, which silently hangs every POST and PUT bound for the upstream app.
app.use(`${GATE}/api`, express.json({ limit: '100kb' }));

app.use(GATE, helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      frameAncestors: ["'none'"],
    },
  },
}));

const gateLimiter = rateLimit({ windowMs: 60_000, max: 300 });
const createLimiter = rateLimit({ windowMs: 60_000, max: 20 });
const activateLimiter = rateLimit({ windowMs: 60_000, max: 30 });
const loginLimiter = rateLimit({ windowMs: 60_000, max: 10 });
// Two different controls guard admin sign-in, and they are deliberately not
// the same number:
//
//   - this limiter is PER IP, in memory, and stops one source hammering or
//     spraying across many accounts;
//   - the lockout in the login handler is PER ACCOUNT, in Postgres, survives a
//     restart, and is what catches a distributed attempt on one account.
//
// The limiter must be the looser of the two, otherwise it always trips first
// and the account lockout becomes unreachable dead code -- and an operator
// sees an opaque 429 instead of an audited ADMIN_LOCKED event.
const adminLoginLimiter = rateLimit({
  windowMs: Number(process.env.ADMIN_LOGIN_RATE_WINDOW_MINUTES || 15) * 60_000,
  max: Number(process.env.ADMIN_LOGIN_RATE_MAX || 10),
  skipSuccessfulRequests: true,
  handler: async (req, res) => {
    await audit(req, {
      event: 'ADMIN_LOGIN_RATE_LIMITED',
      actor: 'system',
      detail: { ip: req.ip || null },
    });
    res.status(429).json({ error: 'Too many attempts. Try again later.' });
  },
});
app.use(GATE, gateLimiter);

// Static assets for the gate's own pages only. The previous build served
// __dirname, which published server.js, schema.sql and package.json to
// anyone who asked for them.
app.use(GATE, express.static(path.join(__dirname, 'public'), { dotfiles: 'deny' }));

const page = (name) => (_req, res) => res.sendFile(path.join(__dirname, 'public', name));
app.get(`${GATE}/login`, page('login.html'));
app.get(`${GATE}/dashboard`, page('dashboard.html'));
// Both admin pages sit behind the IP allowlist too, so a disallowed network
// cannot even discover that a console exists here.
app.get(`${GATE}/admin`, adminIpAllowlist, page('admin.html'));
app.get(`${GATE}/admin-login`, adminIpAllowlist, page('admin-login.html'));
app.get(`${GATE}/health`, (_req, res) => res.json({ ok: true, upstream: UPSTREAM_URL }));

// The link in the access email points here.
app.get(`${GATE}/link/:token`, (req, res) => {
  if (!/^\d{9}$/.test(req.params.token)) return res.status(404).send('Invalid access link');
  res.sendFile(path.join(__dirname, 'public', 'activate.html'));
});

// ============================================================
// Gate API -- admin authentication
// ============================================================
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post(`${GATE}/api/admin/auth/login`, adminIpAllowlist, adminLoginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const normalised = String(email).trim().toLowerCase();
  const { rows } = await pool.query('SELECT * FROM admins WHERE email = $1', [normalised]);
  const admin = rows[0];

  // Every failure below returns the same message and, as far as the caller can
  // measure, takes the same time -- an attacker learns nothing about which
  // admin emails exist.
  const deny = async (reason, status = 401) => {
    await audit(req, {
      event: 'ADMIN_LOGIN_FAILED',
      actor: normalised,
      detail: { reason },
    });
    return res.status(status).json({ error: 'Invalid credentials' });
  };

  if (!admin) {
    await bcrypt.compare(password, DUMMY_HASH);
    return deny('unknown_email');
  }
  if (admin.disabled_at) {
    await bcrypt.compare(password, DUMMY_HASH);
    return deny('disabled');
  }
  // Checked before the password: a locked account stays locked even when the
  // correct password finally arrives, which is the entire point of a lockout.
  if (admin.locked_until && new Date(admin.locked_until) > new Date()) {
    await bcrypt.compare(password, DUMMY_HASH);
    return deny('locked');
  }

  if (!(await bcrypt.compare(password, admin.password_hash))) {
    const attempts = admin.failed_login_attempts + 1;
    const lock = attempts >= ADMIN_MAX_FAILED_ATTEMPTS;
    await pool.query(
      `UPDATE admins SET failed_login_attempts = $1,
              locked_until = CASE WHEN $2 THEN now() + ($3 || ' minutes')::interval ELSE locked_until END
       WHERE id = $4`,
      [lock ? 0 : attempts, lock, String(ADMIN_LOCKOUT_MINUTES), admin.id]
    );
    if (lock) {
      await audit(req, {
        event: 'ADMIN_LOCKED',
        actor: admin.email,
        detail: { minutes: ADMIN_LOCKOUT_MINUTES, afterAttempts: ADMIN_MAX_FAILED_ATTEMPTS },
      });
    }
    return deny('bad_password');
  }

  // TOTP hook. The columns and this branch exist so enabling two-factor later
  // is a feature flag rather than a migration; nothing verifies a code yet.
  if (admin.totp_enabled) {
    return res.status(501).json({ error: 'Two-factor is enabled for this account but not yet implemented' });
  }

  await pool.query(
    'UPDATE admins SET failed_login_attempts = 0, locked_until = NULL, last_login_at = now() WHERE id = $1',
    [admin.id]
  );

  const token = jwt.sign(
    { adminId: admin.id, email: admin.email, typ: 'admin' },
    ADMIN_JWT_KEY,
    { expiresIn: ADMIN_SESSION_TTL_SECONDS }
  );

  await audit(req, { event: 'ADMIN_LOGIN_SUCCESS', actor: admin.email });

  res.cookie(ADMIN_COOKIE_NAME, token, {
    ...adminCookieOptions(),
    maxAge: ADMIN_SESSION_TTL_SECONDS * 1000,
  });
  res.json({ email: admin.email });
});

app.post(`${GATE}/api/admin/auth/logout`, adminOnly, async (req, res) => {
  await audit(req, { event: 'ADMIN_LOGOUT', actor: req.admin.email });
  res.clearCookie(ADMIN_COOKIE_NAME, adminCookieOptions());
  res.json({ message: 'Signed out.' });
});

app.get(`${GATE}/api/admin/auth/me`, adminOnly, (req, res) => {
  res.json({ email: req.admin.email });
});

// ============================================================
// Gate API -- admin
// ============================================================

app.post(`${GATE}/api/admin/grants`, adminOnly, createLimiter, async (req, res) => {
  const { email, durationHours } = req.body || {};
  if (!email || !EMAIL_RE.test(email)) return res.status(400).json({ error: 'Valid email required' });

  const hours = Number(durationHours);
  if (!Number.isFinite(hours) || hours <= 0 || hours > MAX_DURATION_HOURS) {
    return res.status(400).json({ error: `durationHours must be > 0 and <= ${MAX_DURATION_HOURS}` });
  }

  const token = generateToken();
  const password = generatePassword();
  const durationSeconds = Math.round(hours * 3600);

  let grant;
  try {
    const { rows } = await pool.query(
      `INSERT INTO access_grants (email, token_hash, password_hash, duration_seconds, status)
       VALUES ($1, $2, $3, $4, 'PENDING') RETURNING id, email, status, created_at`,
      [email, hashToken(token), await hashPassword(password), durationSeconds]
    );
    grant = rows[0];
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Token collision, please retry' });
    throw err;
  }

  await audit(req, {
    grantId: grant.id,
    event: 'GRANT_CREATED',
    actor: req.admin.email,
    detail: { email, durationHours: hours },
  });

  const accessUrl = `${process.env.PUBLIC_BASE_URL}${GATE}/link/${token}`;
  const durationLabel = `${hours} hour${hours === 1 ? '' : 's'}`;
  const payload = {
    grant: { id: grant.id, email: grant.email, status: grant.status, createdAt: grant.created_at },
    accessUrl,
  };

  try {
    await sendAccessEmail({ to: email, accessUrl, username: email, password, durationLabel });
  } catch (err) {
    await audit(req, {
      grantId: grant.id,
      event: 'GRANT_EMAIL_FAILED',
      actor: req.admin.email,
      detail: { error: err.message },
    });
    // The grant is real even though the email is not, so hand the admin the
    // credentials to relay by hand. Without the password here the grant would
    // be dead on arrival and would have to be recreated.
    return res.status(202).json({
      ...payload,
      warning: 'Grant created, but the email failed to send. Relay these credentials manually.',
      detail: err.message,
      password,
    });
  }

  await audit(req, { grantId: grant.id, event: 'GRANT_EMAIL_SENT', actor: req.admin.email });
  res.status(201).json(payload);
});

app.get(`${GATE}/api/admin/grants`, adminOnly, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, email, status, created_at, activated_at, expires_at, activated_ip
     FROM access_grants ORDER BY created_at DESC LIMIT 100`
  );
  res.json({ grants: rows });
});

app.post(`${GATE}/api/admin/grants/:id/revoke`, adminOnly, async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE access_grants SET status = 'REVOKED'
     WHERE id = $1 AND status IN ('PENDING','ACTIVE') RETURNING id, status`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Grant not found or not revocable' });

  cacheBust(rows[0].id);
  await audit(req, {
    grantId: rows[0].id,
    event: 'GRANT_REVOKED',
    actor: req.admin.email,
    detail: { reason: 'admin_action' },
  });
  res.json({ grant: rows[0] });
});

app.get(`${GATE}/api/admin/audit-log`, adminOnly, async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 1000);
  const { grantId } = req.query;
  const { rows } = grantId
    ? await pool.query(
        'SELECT * FROM audit_log WHERE grant_id = $1 ORDER BY created_at DESC LIMIT $2',
        [grantId, limit])
    : await pool.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $1', [limit]);
  res.json({ events: rows });
});

// ============================================================
// Gate API -- activation, login, session
// ============================================================
app.get(`${GATE}/api/activate/:token`, activateLimiter, async (req, res) => {
  if (!/^\d{9}$/.test(req.params.token)) {
    return res.status(404).json({ error: 'Invalid or expired access link' });
  }

  const { rows } = await pool.query(
    'SELECT * FROM access_grants WHERE token_hash = $1',
    [hashToken(req.params.token)]
  );
  const grant = rows[0];
  if (!grant) {
    await audit(req, { event: 'ACTIVATE_INVALID_TOKEN' });
    return res.status(404).json({ error: 'Invalid or expired access link' });
  }

  if (grant.status === 'PENDING') {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + grant.duration_seconds * 1000);
    await pool.query(
      `UPDATE access_grants
       SET status = 'ACTIVE', activated_at = $1, expires_at = $2,
           activated_ip = $3, activated_user_agent = $4
       WHERE id = $5`,
      [now, expiresAt, req.ip || null, req.header('User-Agent') || null, grant.id]
    );
    cacheBust(grant.id);
    await audit(req, {
      grantId: grant.id,
      event: 'GRANT_ACTIVATED',
      actor: grant.email,
      detail: { expiresAt },
    });
    return res.json({ message: 'Access activated.', activatedAt: now, expiresAt });
  }

  if (grant.status === 'ACTIVE') {
    if (new Date() > new Date(grant.expires_at)) {
      await pool.query("UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1", [grant.id]);
      cacheBust(grant.id);
      await audit(req, { grantId: grant.id, event: 'GRANT_EXPIRED', actor: 'system' });
      return res.status(410).json({ error: 'This access link has expired' });
    }
    // Reopening an active link is usually innocent -- a refresh, or checking
    // the time left -- so it isn't blocked. But an open from a different IP or
    // browser than the one that first activated it can mean the link was
    // forwarded or intercepted, which earns a distinct audit event.
    const mismatch = (grant.activated_ip && grant.activated_ip !== req.ip)
      || (grant.activated_user_agent && grant.activated_user_agent !== req.header('User-Agent'));
    await audit(req, {
      grantId: grant.id,
      event: mismatch ? 'ACTIVATE_REOPENED_FINGERPRINT_MISMATCH' : 'ACTIVATE_REOPENED',
      actor: grant.email,
      detail: mismatch ? { firstIp: grant.activated_ip, thisIp: req.ip } : null,
    });
    return res.json({ message: 'Access already active.', expiresAt: grant.expires_at });
  }

  await audit(req, {
    grantId: grant.id,
    event: 'ACTIVATE_REJECTED',
    actor: grant.email,
    detail: { status: grant.status },
  });
  res.status(410).json({ error: 'This access link is no longer valid' });
});

// A bcrypt hash of a value nobody can supply. Comparing against it burns the
// same time a real check would, so "no such grant" and "wrong password" are
// indistinguishable by response latency.
const DUMMY_HASH = '$2b$12$C6UzMDM.H6dfI/f/IKcEe.mB1TUpU4A1r9Ea3q2Ao8mwrLIfBSbLC';

app.post(`${GATE}/api/auth/login`, loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const { rows } = await pool.query(
    `SELECT * FROM access_grants WHERE email = $1 AND status = 'ACTIVE'
     ORDER BY created_at DESC LIMIT 1`,
    [email]
  );
  const grant = rows[0];

  if (!grant) {
    await bcrypt.compare(password, DUMMY_HASH);
    await audit(req, { event: 'LOGIN_FAILED', actor: email, detail: { reason: 'no_active_grant' } });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (new Date() > new Date(grant.expires_at)) {
    await pool.query("UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1", [grant.id]);
    cacheBust(grant.id);
    await audit(req, { grantId: grant.id, event: 'GRANT_EXPIRED', actor: 'system' });
    return res.status(401).json({ error: 'Access expired' });
  }

  if (!(await bcrypt.compare(password, grant.password_hash))) {
    await pool.query(
      'UPDATE access_grants SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1',
      [grant.id]
    );
    await audit(req, {
      grantId: grant.id,
      event: 'LOGIN_FAILED',
      actor: email,
      detail: { reason: 'bad_password' },
    });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // A session can never outlive the grant that authorized it.
  const capExpiry = new Date(grant.expires_at).getTime();
  const sessionExpiry = Math.min(Date.now() + SESSION_TTL_SECONDS * 1000, capExpiry);
  const expiresInSeconds = Math.max(1, Math.floor((sessionExpiry - Date.now()) / 1000));

  const sessionToken = jwt.sign(
    { grantId: grant.id, email: grant.email },
    process.env.JWT_SECRET,
    { expiresIn: expiresInSeconds }
  );

  await pool.query('UPDATE access_grants SET failed_login_attempts = 0 WHERE id = $1', [grant.id]);
  await audit(req, {
    grantId: grant.id,
    event: 'LOGIN_SUCCESS',
    actor: grant.email,
    detail: { sessionExpiresAt: new Date(sessionExpiry) },
  });

  res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions(), maxAge: expiresInSeconds * 1000 });
  res.json({ expiresAt: grant.expires_at, sessionExpiresAt: new Date(sessionExpiry) });
});

// Powers the countdown, both on the dashboard and in the banner injected into
// the upstream app's pages.
app.get(`${GATE}/api/session`, requireSessionApi, (req, res) => {
  res.json({
    email: req.session.email,
    expiresAt: req.session.expiresAt,
    remainingSeconds: Math.max(
      0,
      Math.floor((new Date(req.session.expiresAt).getTime() - Date.now()) / 1000)
    ),
  });
});

// Logging out ends the grant, not just the session: the emailed credentials
// become permanently unusable even if time remains on the clock.
app.post(`${GATE}/api/auth/logout`, requireSessionApi, async (req, res) => {
  await pool.query("UPDATE access_grants SET status = 'REVOKED' WHERE id = $1", [req.session.grantId]);
  cacheBust(req.session.grantId);
  await audit(req, {
    grantId: req.session.grantId,
    event: 'GRANT_REVOKED',
    actor: req.session.email,
    detail: { reason: 'user_logout' },
  });
  res.clearCookie(COOKIE_NAME, cookieOptions());
  res.json({ message: 'Access revoked. This pass can no longer be used to log in.' });
});

// Legacy paths from the pre-gateway build. These URLs now belong to the
// upstream app, so redirect rather than silently 404 a bookmarked link.
app.get('/login.html', (_req, res) => res.redirect(`${GATE}/login`));
app.get('/admin.html', (_req, res) => res.redirect(`${GATE}/admin`));
app.get('/dashboard.html', (_req, res) => res.redirect(`${GATE}/dashboard`));
app.get('/access/:token', (req, res) => res.redirect(`${GATE}/link/${req.params.token}`));

// The gate namespace is reserved, and that has to be true for paths the gate
// does NOT define as well as the ones it does. Without this, an unmatched
// /__access/* URL falls through to the proxy below and is forwarded to the
// upstream app -- so the app could see (and answer) requests inside the one
// namespace this design promises it will never own.
app.use(GATE, (_req, res) => res.status(404).json({ error: 'Not found' }));

// ============================================================
// The proxy
// ============================================================
// Injected into every HTML document the upstream app returns, so the customer
// always sees the time left and can end the session from anywhere inside the
// app rather than having to find their way back to the dashboard.
const bannerScript = `
<script>(function(){
  if (window.top !== window.self) return;
  var bar = document.createElement('div');
  bar.id = 'ta-banner';
  bar.innerHTML = '<span>Temporary access &mdash; <span class="t">--:--:--</span> remaining</span>';
  var btn = document.createElement('button');
  btn.textContent = 'End session';
  btn.onclick = function(){
    fetch('${GATE}/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
      .then(function(){ location.href = '${GATE}/login'; });
  };
  bar.appendChild(btn);

  var css = document.createElement('style');
  css.textContent = '#ta-banner{position:fixed;top:0;left:0;right:0;z-index:2147483647;display:flex;'
    + 'align-items:center;justify-content:space-between;gap:16px;padding:8px 16px;background:#12151c;'
    + 'color:#f7f4ec;font-family:system-ui,sans-serif;font-size:13px;box-shadow:0 2px 12px rgba(0,0,0,.35)}'
    + '#ta-banner.warn{background:#b4432f}'
    + '#ta-banner .t{font-weight:600;font-variant-numeric:tabular-nums}'
    + '#ta-banner button{border:1px solid rgba(255,255,255,.35);background:transparent;color:inherit;'
    + 'border-radius:6px;padding:4px 12px;font-size:12px;cursor:pointer}'
    + 'body{padding-top:38px!important}';
  document.head.appendChild(css);
  document.body.appendChild(bar);

  function fmt(s){
    var h=Math.floor(s/3600), m=Math.floor(s%3600/60), x=Math.floor(s%60);
    return (h<10?'0':'')+h+':'+(m<10?'0':'')+m+':'+(x<10?'0':'')+x;
  }

  var left = 0;
  function paint(){
    bar.querySelector('.t').textContent = fmt(Math.max(0,left));
    bar.className = left < 300 ? 'warn' : '';
    if (left <= 0) { location.href = '${GATE}/login'; return; }
    left--;
  }
  // Re-sync against the server rather than trusting the local clock: the
  // countdown is a courtesy, the server is the authority. This also notices
  // an admin revoke within a minute.
  function sync(){
    fetch('${GATE}/api/session', { credentials: 'same-origin' })
      .then(function(r){ if(!r.ok) throw 0; return r.json(); })
      .then(function(d){ left = d.remainingSeconds; })
      .catch(function(){ location.href = '${GATE}/login'; });
  }
  sync();
  setInterval(paint, 1000);
  setInterval(sync, 60000);
})();</script>`;

const proxyCommon = {
  target: UPSTREAM_URL,
  changeOrigin: true,
  xfwd: true,
  proxyTimeout: 30_000,
  timeout: 30_000,
  on: {
    proxyReq: (proxyReq, req) => {
      // Never leak the gateway's own session cookie to the upstream app.
      const cookie = req.headers.cookie;
      if (cookie) {
        const kept = cookie
          .split(';')
          .filter((c) => c.trim().split('=')[0] !== COOKIE_NAME)
          .join(';')
          .trim();
        if (kept) proxyReq.setHeader('cookie', kept);
        else proxyReq.removeHeader('cookie');
      }
      // Tell the upstream app who this is. Set unconditionally (not merged)
      // so a client cannot forge the claim by sending the header itself.
      proxyReq.setHeader('X-Temp-Access-Email', req.session?.email || '');
      proxyReq.setHeader('X-Temp-Access-Grant', req.session?.grantId || '');
    },
    error: (err, _req, res) => {
      console.error('proxy error:', err.message);
      if (res && !res.headersSent && typeof res.status === 'function') {
        res.status(502).json({ error: 'The application behind the gateway is unreachable.' });
      }
    },
  },
};

// Two proxies, deliberately. The HTML one buffers the response so the
// countdown banner can be injected; the raw one streams. Routing assets and
// downloads through the buffering path would hold whole files in memory for
// no benefit, since only documents can carry the banner.
const proxyRaw = createProxyMiddleware({ ...proxyCommon, ws: true });

const proxyHtml = createProxyMiddleware({
  ...proxyCommon,
  selfHandleResponse: true,
  on: {
    ...proxyCommon.on,
    proxyRes: responseInterceptor(async (buffer, proxyRes, _req, res) => {
      const type = proxyRes.headers['content-type'] || '';
      if (!type.includes('text/html')) return buffer;
      if (STRIP_UPSTREAM_CSP) {
        res.removeHeader('content-security-policy');
        res.removeHeader('content-security-policy-report-only');
      }
      const html = buffer.toString('utf8');
      return html.includes('</body>')
        ? html.replace('</body>', `${bannerScript}</body>`)
        : html + bannerScript;
    }),
  },
});

function wantsHtml(req) {
  return req.method === 'GET' && (req.headers.accept || '').includes('text/html');
}

// Everything not claimed by the gate is forwarded -- but only for a live
// session. This check runs on every single request, which is what makes an
// expiry or a revoke cut a customer off mid-session rather than at next login.
app.use(async (req, res, next) => {
  const result = await resolveSession(req);

  if (!result.ok) {
    if (wantsHtml(req)) {
      // Remember where they were headed so login can return them there.
      const back = encodeURIComponent(req.originalUrl);
      return res.redirect(`${GATE}/login?next=${back}&reason=${result.reason}`);
    }
    return res.status(401).json({ error: 'Access no longer valid', reason: result.reason });
  }

  req.session = result.session;
  return (INJECT_BANNER && wantsHtml(req) ? proxyHtml : proxyRaw)(req, res, next);
});

// ============================================================
// Error handling
// ============================================================
app.use((err, _req, res, _next) => {
  console.error('unhandled error:', err);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================================
// Background expiry sweeper
// ============================================================
// Grants would otherwise only flip to EXPIRED when something happened to
// touch them, leaving the admin console showing stale ACTIVE rows for windows
// that closed hours ago.
async function sweepExpired() {
  try {
    const { rows } = await pool.query(
      `UPDATE access_grants SET status = 'EXPIRED'
       WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at <= now()
       RETURNING id`
    );
    for (const row of rows) {
      cacheBust(row.id);
      await audit(null, {
        grantId: row.id,
        event: 'GRANT_EXPIRED',
        actor: 'system',
        detail: { reason: 'sweeper' },
      });
    }
    if (rows.length) console.log(`sweeper: expired ${rows.length} grant(s)`);
  } catch (err) {
    console.error('sweeper failed:', err.message);
  }
}

// ============================================================
// Boot
// ============================================================
// An empty admins table means nobody can issue access, and the only symptom
// would be a 401 that looks like a wrong password. Say so plainly at boot.
async function checkAdminSetup() {
  try {
    const { rows } = await pool.query(
      'SELECT count(*)::int AS n FROM admins WHERE disabled_at IS NULL'
    );
    if (rows[0].n === 0) {
      console.warn('  WARNING: no admin accounts exist. Run: npm run create-admin');
    } else {
      console.log(`  admins   : ${rows[0].n} active`);
    }
  } catch (err) {
    console.error('  WARNING: could not read the admins table. Has schema.sql been applied?');
    console.error(`           ${err.message}`);
  }

  if (!ADMIN_IP_ALLOWLIST.length && COOKIE_SECURE) {
    console.warn('  WARNING: ADMIN_IP_ALLOWLIST is empty, so the admin console answers');
    console.warn('           the public internet. Scope it to your VPN or office range.');
  }
}

const server = app.listen(PORT, () => {
  console.log(`gateway listening on :${PORT}`);
  console.log(`  upstream : ${UPSTREAM_URL}`);
  console.log(`  public   : ${process.env.PUBLIC_BASE_URL}`);
  console.log(`  admin    : ${process.env.PUBLIC_BASE_URL}${GATE}/admin`);
  checkAdminSetup();
});

// Websocket upgrades bypass Express middleware entirely, so they need their
// own authorization check. Without this, a customer whose window has closed
// keeps a live socket into the app.
server.on('upgrade', async (req, socket, head) => {
  try {
    const result = await resolveSession(req);
    if (!result.ok) return socket.destroy();
    req.session = result.session;
    proxyRaw.upgrade(req, socket, head);
  } catch {
    socket.destroy();
  }
});

const sweepTimer = setInterval(sweepExpired, SWEEP_INTERVAL_MS);
sweepExpired();

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    console.log(`${sig} received, shutting down`);
    clearInterval(sweepTimer);
    server.close(() => pool.end().then(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10_000).unref();
  });
}
