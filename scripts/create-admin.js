#!/usr/bin/env node
//
// Creates or updates an admin account.
//
//   npm run create-admin                      (prompts)
//   npm run create-admin -- you@example.com   (prompts for the password only)
//
// This is deliberately the ONLY way an admin account comes into existence.
// There is no signup page and no password-reset email, so recovering from a
// lost password requires shell access to the host -- which is itself a
// control, and a far better one than an internet-facing reset flow guarding
// the credential that mints access to the internal network.

require('dotenv').config({ quiet: true });

const readline = require('readline');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const MIN_PASSWORD_LENGTH = 12;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. Run this from the project directory with a .env present.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

// Answers are read differently depending on whether a human is typing.
//
// Interactively we mask the password so it is not echoed or left in a
// scrollback buffer. When stdin is piped (CI, or a scripted test) there is no
// terminal to mask and readline's terminal mode misbehaves, so the whole of
// stdin is read up front and consumed a line at a time instead.
const isInteractive = process.stdin.isTTY;
let pipedLines = null;

async function readPipedLines() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8').split(/\r?\n/);
}

async function ask(question, { silent = false } = {}) {
  if (!isInteractive) {
    if (pipedLines === null) pipedLines = await readPipedLines();
    const answer = pipedLines.shift();
    if (answer === undefined) throw new Error('unexpected end of input');
    process.stdout.write(`${question}${silent ? '' : answer}\n`);
    return answer;
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });

  if (silent) {
    // readline calls this for every keystroke it would echo; swallowing it
    // keeps the password off the screen while still accepting input.
    let primed = false;
    rl._writeToOutput = (chunk) => {
      if (!primed) { rl.output.write(chunk); primed = true; }
    };
  }

  try {
    const answer = await new Promise((resolve) => rl.question(question, resolve));
    if (silent) process.stdout.write('\n');
    return answer;
  } finally {
    rl.close();
  }
}

(async () => {
  try {
    let email = process.argv[2];
    if (!email) email = await ask('Admin email: ');
    email = String(email).trim().toLowerCase();

    if (!EMAIL_RE.test(email)) {
      console.error('That is not a valid email address.');
      process.exit(1);
    }

    const existing = await pool.query('SELECT id, disabled_at FROM admins WHERE email = $1', [email]);
    if (existing.rows[0]) {
      const answer = await ask(`${email} already exists. Reset its password? [y/N] `);
      if (answer.trim().toLowerCase() !== 'y') {
        console.log('Nothing changed.');
        process.exit(0);
      }
    }

    const password = await ask('Password: ', { silent: true });
    if (password.length < MIN_PASSWORD_LENGTH) {
      console.error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      process.exit(1);
    }
    const confirm = await ask('Confirm password: ', { silent: true });
    if (password !== confirm) {
      console.error('Passwords do not match.');
      process.exit(1);
    }

    const hash = await bcrypt.hash(password, await bcrypt.genSalt(12));

    // Resets the lockout and re-enables the account, so this doubles as the
    // recovery path for an admin who locked themselves out.
    const { rows } = await pool.query(
      `INSERT INTO admins (email, password_hash) VALUES ($1, $2)
       ON CONFLICT (email) DO UPDATE
         SET password_hash = EXCLUDED.password_hash,
             failed_login_attempts = 0,
             locked_until = NULL,
             disabled_at = NULL
       RETURNING id, email, created_at`,
      [email, hash]
    );

    await pool.query(
      `INSERT INTO audit_log (event, actor, detail)
       VALUES ($1, $2, $3)`,
      [
        existing.rows[0] ? 'ADMIN_PASSWORD_RESET' : 'ADMIN_CREATED',
        'cli',
        JSON.stringify({ email }),
      ]
    );

    console.log(`\n${existing.rows[0] ? 'Updated' : 'Created'} admin: ${rows[0].email}`);
    console.log(`Sign in at ${process.env.PUBLIC_BASE_URL || 'http://localhost:3000'}/__access/admin`);
  } catch (err) {
    console.error(`\nFailed: ${err.message}`);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();
