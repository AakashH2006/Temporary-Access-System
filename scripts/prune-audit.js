#!/usr/bin/env node
//
// Prunes audit_log rows older than the retention window.
//
//   npm run prune-audit                 (uses AUDIT_RETENTION_MONTHS, default 12)
//   npm run prune-audit -- --months=6
//   npm run prune-audit -- --dry-run
//
// The audit log is append-only by design and the application never deletes
// from it. This script is the one exception, and it is meant for cron rather
// than for hands: retention is a policy decision, so it lives in a scheduled
// job with a documented default rather than in the request path.
//
// At this system's volume the table is a few MB a year, so this is not really
// about disk. It is about having an answer -- before anyone asks -- to "how
// long do you keep access records", which is a question the client's legal or
// compliance people will ask eventually.

require('dotenv').config({ quiet: true });

const { Pool } = require('pg');

// Deletes run in batches so a long-neglected table does not hold one
// transaction (and one lock) open for minutes at a time.
const BATCH_SIZE = 5000;

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const monthsArg = args.find((a) => a.startsWith('--months='));
const months = Number(
  monthsArg ? monthsArg.split('=')[1] : (process.env.AUDIT_RETENTION_MONTHS || 12)
);

if (!Number.isFinite(months) || months < 1) {
  console.error('Retention must be a whole number of months, at least 1.');
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. Run this from the project directory with a .env present.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

(async () => {
  try {
    const cutoffSql = `now() - ($1 || ' months')::interval`;
    const { rows: [{ n, oldest }] } = await pool.query(
      `SELECT count(*)::int AS n, min(created_at) AS oldest
         FROM audit_log WHERE created_at < ${cutoffSql}`,
      [String(months)]
    );

    console.log(`retention : ${months} month${months === 1 ? '' : 's'}`);
    console.log(`eligible  : ${n} row${n === 1 ? '' : 's'}${oldest ? `, oldest ${oldest.toISOString()}` : ''}`);

    if (dryRun) {
      console.log('dry run   : nothing deleted');
      return;
    }
    if (n === 0) return;

    let deleted = 0;
    for (;;) {
      const { rowCount } = await pool.query(
        `DELETE FROM audit_log
          WHERE id IN (
            SELECT id FROM audit_log WHERE created_at < ${cutoffSql}
             ORDER BY id LIMIT ${BATCH_SIZE}
          )`,
        [String(months)]
      );
      deleted += rowCount;
      if (rowCount < BATCH_SIZE) break;
    }

    // The prune is itself an audited event: a log that can be silently
    // shortened is not much of an audit trail. This row is inside the
    // retention window by definition, so the next run will not remove it.
    await pool.query(
      `INSERT INTO audit_log (event, actor, detail) VALUES ($1, $2, $3)`,
      ['AUDIT_PRUNED', 'cli', JSON.stringify({ retentionMonths: months, deleted })]
    );

    console.log(`deleted   : ${deleted} row${deleted === 1 ? '' : 's'}`);
  } catch (err) {
    console.error(`Failed: ${err.message}`);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();
