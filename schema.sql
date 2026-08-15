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
  failed_login_attempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_access_grants_email ON access_grants(email);
CREATE INDEX IF NOT EXISTS idx_access_grants_status ON access_grants(status);
