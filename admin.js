const express = require('express');
const rateLimit = require('express-rate-limit');
const pool = require('../db');
const adminAuth = require('../middleware/adminAuth');
const { sendAccessEmail } = require('../email');
const {
  generateToken,
  hashToken,
  generatePassword,
  hashPassword,
} = require('../crypto');

const router = express.Router();

const createLimiter = rateLimit({ windowMs: 60_000, max: 20 });

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_DURATION_HOURS = 24 * 30; // 30 days safety cap

router.post('/grants', adminAuth, createLimiter, async (req, res) => {
  const { email, durationHours } = req.body || {};

  if (!email || !EMAIL_RE.test(email)) {
    return res.status(400).json({ error: 'Valid email required' });
  }
  const hours = Number(durationHours);
  if (!Number.isFinite(hours) || hours <= 0 || hours > MAX_DURATION_HOURS) {
    return res.status(400).json({ error: `durationHours must be > 0 and <= ${MAX_DURATION_HOURS}` });
  }

  const token = generateToken();
  const password = generatePassword();
  const tokenHash = hashToken(token);
  const passwordHash = await hashPassword(password);
  const durationSeconds = Math.round(hours * 3600);

  let grant;
  try {
    const { rows } = await pool.query(
      `INSERT INTO access_grants (email, token_hash, password_hash, duration_seconds, status)
       VALUES ($1, $2, $3, $4, 'PENDING')
       RETURNING id, email, status, created_at`,
      [email, tokenHash, passwordHash, durationSeconds]
    );
    grant = rows[0];
  } catch (err) {
    // token collision is astronomically unlikely (1 in 9e8) but retry once just in case
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Token collision, please retry' });
    }
    throw err;
  }

  const accessUrl = `${process.env.PUBLIC_BASE_URL}/${token}`;
  const durationLabel = `${hours} hour${hours === 1 ? '' : 's'}`;

  try {
    await sendAccessEmail({
      to: email,
      accessUrl,
      username: email,
      password,
      durationLabel,
    });
  } catch (err) {
    // Grant is created even if email fails; admin can be told to resend/inspect.
    return res.status(202).json({
      warning: 'Grant created but email failed to send',
      detail: err.message,
      grant: { id: grant.id, email: grant.email, status: grant.status },
    });
  }

  return res.status(201).json({
    grant: { id: grant.id, email: grant.email, status: grant.status, createdAt: grant.created_at },
    accessUrl,
  });
});

// Optional: list grants for admin visibility
router.get('/grants', adminAuth, async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, email, status, created_at, activated_at, expires_at
     FROM access_grants ORDER BY created_at DESC LIMIT 100`
  );
  res.json({ grants: rows });
});

// Optional: revoke
router.post('/grants/:id/revoke', adminAuth, async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE access_grants SET status = 'REVOKED'
     WHERE id = $1 AND status IN ('PENDING','ACTIVE')
     RETURNING id, status`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Grant not found or not revocable' });
  res.json({ grant: rows[0] });
});

module.exports = router;
