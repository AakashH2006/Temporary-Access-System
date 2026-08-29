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
