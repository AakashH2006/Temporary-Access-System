const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// 9-digit numeric token, e.g. 583921746. Uses randomInt (CSPRNG-backed).
function generateToken() {
  const n = crypto.randomInt(100000000, 1000000000); // 100000000..999999999
  return String(n);
}

// Token is an identifier, not a secret credential -> fast deterministic
// hash (sha256) is fine and lets us look it up by hash in O(1).
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Random temp password: 16 chars, mixed classes, CSPRNG-backed.
function generatePassword(length = 16) {
  const charset =
    'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += charset[bytes[i] % charset.length];
  }
  return out;
}

// Password is a real credential -> slow, salted bcrypt hash.
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(12);
  return bcrypt.hash(password, salt);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

module.exports = {
  generateToken,
  hashToken,
  generatePassword,
  hashPassword,
  verifyPassword,
};
