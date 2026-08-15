const express = require('express');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const pool = require('../db');
const { hashToken, verifyPassword } = require('../crypto');
const requireSession = require('../middleware/requireSession');

const router = express.Router();

const activateLimiter = rateLimit({ windowMs: 60_000, max: 30 });
const loginLimiter = rateLimit({ windowMs: 60_000, max: 10 });

// GET /:token  -- activates access on first open, starts the timer
router.get('/:token', activateLimiter, async (req, res) => {
  const { token } = req.params;
  if (!/^\d{9}$/.test(token)) {
    return res.status(404).json({ error: 'Invalid or expired access link' });
  }
  const tokenHash = hashToken(token);

  const { rows } = await pool.query(
    `SELECT * FROM access_grants WHERE token_hash = $1`,
    [tokenHash]
  );
  const grant = rows[0];
  if (!grant) return res.status(404).json({ error: 'Invalid or expired access link' });

  if (grant.status === 'PENDING') {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + grant.duration_seconds * 1000);
    await pool.query(
      `UPDATE access_grants
       SET status = 'ACTIVE', activated_at = $1, expires_at = $2
       WHERE id = $3`,
      [now, expiresAt, grant.id]
    );
    return res.json({
      message: 'Access activated. You may now log in with your emailed credentials.',
      activatedAt: now,
      expiresAt,
    });
  }

  if (grant.status === 'ACTIVE') {
    if (new Date() > new Date(grant.expires_at)) {
      await pool.query(`UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1`, [grant.id]);
      return res.status(410).json({ error: 'This access link has expired' });
    }
    return res.json({
      message: 'Access already active. Log in with your emailed credentials.',
      expiresAt: grant.expires_at,
    });
  }

  return res.status(410).json({ error: 'This access link is no longer valid' });
});

// POST /auth/login  { email, password }
router.post('/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const { rows } = await pool.query(
    `SELECT * FROM access_grants
     WHERE email = $1 AND status = 'ACTIVE'
     ORDER BY created_at DESC LIMIT 1`,
    [email]
  );
  const grant = rows[0];
  const genericFail = () => res.status(401).json({ error: 'Invalid credentials' });

  if (!grant) return genericFail();

  if (new Date() > new Date(grant.expires_at)) {
    await pool.query(`UPDATE access_grants SET status = 'EXPIRED' WHERE id = $1`, [grant.id]);
    return res.status(401).json({ error: 'Access expired' });
  }

  const ok = await verifyPassword(password, grant.password_hash);
  if (!ok) return genericFail();

  const sessionTtl = Number(process.env.SESSION_TTL_SECONDS || 3600);
  const capExpiry = new Date(grant.expires_at).getTime();
  const sessionExpiry = Math.min(Date.now() + sessionTtl * 1000, capExpiry);
  const expiresInSeconds = Math.floor((sessionExpiry - Date.now()) / 1000);

  const sessionToken = jwt.sign(
    { grantId: grant.id, email: grant.email },
    process.env.JWT_SECRET,
    { expiresIn: expiresInSeconds }
  );

  res.json({ sessionToken, expiresAt: new Date(sessionExpiry) });
});

// Example protected application route
router.get('/app/me', requireSession, (req, res) => {
  res.json({ email: req.grant.email, message: 'You are authenticated.' });
});

module.exports = router;
