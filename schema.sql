CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS access_grants (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email          TEXT NOT NULL,
  token_hash     TEXT NOT NULL UNIQUE,
  password_hash  TEXT NOT NULL,
  duration_seconds INTEGER NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  activated_at   TIMESTAMPTZ,
  expires_at     TIMESTAMPTZ,
  status         TEXT NOT NULL DEFAULT 'PENDING'
                 CHECK (status IN ('PENDING','ACTIVE','EXPIRED','REVOKED')),
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  -- Set once failed_login_attempts crosses GRANT_MAX_FAILED_ATTEMPTS. Held in
  -- the database rather than in memory so a lockout survives a restart, and
  -- so it is not per-process the way the rate limiter is.
  locked_until          TIMESTAMPTZ,
  -- Fingerprint captured at first activation. Used to flag (not block)
  -- later opens of the same link from a different device/network, which
  -- can indicate the link was forwarded or intercepted.
  activated_ip         TEXT,
  activated_user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_access_grants_email ON access_grants(email);
CREATE INDEX IF NOT EXISTS idx_access_grants_status ON access_grants(status);

-- Safe to re-run: adds the fingerprint columns to an already-existing
-- access_grants table (CREATE TABLE IF NOT EXISTS above won't touch an
-- existing table's columns).
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS activated_ip TEXT;
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS activated_user_agent TEXT;
ALTER TABLE access_grants ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

-- Append-only audit trail. Never updated or deleted by the app;
-- independent of access_grants.status so history survives even if a
-- grant row is later purged.
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGSERIAL PRIMARY KEY,
  grant_id    UUID REFERENCES access_grants(id) ON DELETE SET NULL,
  event       TEXT NOT NULL,       -- e.g. GRANT_CREATED, GRANT_ACTIVATED, LOGIN_SUCCESS,
                                    -- LOGIN_FAILED, GRANT_REVOKED, GRANT_EXPIRED, LOGOUT
  actor       TEXT,                -- 'admin', an email, or 'system'
  ip_address  TEXT,
  user_agent  TEXT,
  detail      JSONB,               -- freeform context (e.g. {"reason":"admin_revoke"})
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_grant_id ON audit_log(grant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_event ON audit_log(event);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- ------------------------------------------------------------------
-- Grant migrations that write to audit_log, so they live below it.
-- ------------------------------------------------------------------
-- Emails are stored lower-cased and trimmed, and the application normalises on
-- both write and read. Existing rows are normalised in place rather than being
-- matched with lower(email) at query time, because idx_access_grants_email is
-- on the raw column and a function in the predicate would not use it.
--
-- (CITEXT would fix this at the schema level instead. It is not used here only
-- because it needs an extension on the host, and one lower() at each of the
-- two call sites is a smaller thing to carry.)
UPDATE access_grants
   SET email = lower(btrim(email))
 WHERE email <> lower(btrim(email));

-- The invariant: at most one LIVE grant per email, where live means PENDING or
-- ACTIVE.
--
-- Two concurrent live grants for one email used to be accepted and then only
-- half work: login reads the newest row, so the older grant's password -- valid,
-- freshly emailed -- failed against the newer grant's hash, and the failure was
-- counted against the wrong grant. The application now refuses the second grant
-- with a 409; this index is what makes that true under a race, and what stops
-- the state ever existing again.
--
-- It must run AFTER the lower-casing above, or rows differing only by case will
-- not collide and the index will happily admit the duplicates it exists to
-- prevent.
--
-- Creating it fails outright if live duplicates are already present, so they
-- are resolved first: all but the newest per email are revoked, which is what
-- the application would have done had it been able to. Every one of them is
-- written to the audit log rather than disappearing quietly -- someone's access
-- is being ended here.
WITH ranked AS (
  SELECT id,
         row_number() OVER (PARTITION BY email ORDER BY created_at DESC, id DESC) AS rn
    FROM access_grants
   WHERE status IN ('PENDING','ACTIVE')
), superseded AS (
  UPDATE access_grants g
     SET status = 'REVOKED'
    FROM ranked r
   WHERE g.id = r.id AND r.rn > 1
  RETURNING g.id, g.email
)
INSERT INTO audit_log (grant_id, event, actor, detail)
SELECT id, 'GRANT_SUPERSEDED', 'system',
       jsonb_build_object('reason', 'migration_one_open_grant_per_email', 'email', email)
  FROM superseded;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_live_grant_per_email
    ON access_grants (email)
 WHERE status IN ('PENDING','ACTIVE');
-- Admin accounts. Whoever holds one of these can mint access to the internal
-- network for anyone, so this table gets the same protections the customer
-- grants get: bcrypt hashing, failed-attempt counting, and a disable switch
-- that takes effect immediately rather than at token expiry.
--
-- There is deliberately no self-service signup and no password-reset email:
-- accounts are created on the host with `npm run create-admin`, so recovery
-- requires SSH access, which is itself a control.
CREATE TABLE IF NOT EXISTS admins (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email                 TEXT NOT NULL UNIQUE,
  password_hash         TEXT NOT NULL,
  -- Reserved for TOTP two-factor. The columns and the branch in the login
  -- flow exist now so enabling 2FA later is a feature flag, not a migration.
  totp_secret           TEXT,
  totp_enabled          BOOLEAN NOT NULL DEFAULT false,
  -- Persisted rather than held in memory so a lockout survives a restart;
  -- an in-memory counter would reset on every deploy.
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until          TIMESTAMPTZ,
  disabled_at           TIMESTAMPTZ,
  last_login_at         TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_admins_email ON admins(email);

-- Safe to re-run against an admins table created by an earlier version.
ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;

-- The login flow has a branch for totp_enabled that returns 501, because no
-- code verifies a TOTP code yet. Anything that flips this column to true --
-- a well-meaning DBA, a future migration run early -- would therefore lock
-- that admin out permanently, with no recovery except SQL.
--
-- So the database refuses the one state the code cannot handle. The columns
-- stay: the forward-compatibility intent is right, and implementing TOTP means
-- dropping this constraint in the same change.
DO $$ BEGIN
  ALTER TABLE admins ADD CONSTRAINT admins_totp_not_implemented CHECK (totp_enabled = false);
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;
