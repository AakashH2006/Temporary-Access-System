# Temporary Access System

A convenience-first temporary access system: an admin enters an email and a
duration, the system generates a one-time access link, a random password,
and emails both. Opening the link starts the access timer. The user logs in
with the emailed credentials, and access ends either when the timer runs
out or the user logs out.

## How it works

```
ADMIN                     SYSTEM                        USER
  │                         │                             │
  ├─ email + duration ──────▶                             │
  │                         ├─ generate 9-digit token      │
  │                         ├─ generate random password    │
  │                         ├─ create PENDING grant        │
  │                         ├─ send email ─────────────────▶
  │                         │                             ├─ opens /access/<token>
  │                         │◀──────── activate ───────────┤
  │                         ├─ status → ACTIVE             │
  │                         ├─ timer starts                │
  │                         │                             ├─ logs in (email + password)
  │                         │◀──────── /api/auth/login ────┤
  │                         ├─ issues session token ───────▶
  │                         │                             ├─ uses /dashboard.html
  │                         │                             ├─ logs out
  │                         │◀──────── /api/auth/logout ───┤
  │                         ├─ status → REVOKED            │
  │                         │           (credentials dead) │
```

**Logout permanently ends the grant.** It isn't just a client-side session
clear — it revokes the underlying access grant, so the emailed
email/password can never be used again, even if the 8-hour (or whatever)
window hasn't run out yet. If someone wants access again, an admin has to
issue a new grant.

## Stack

- **Backend:** Node.js + Express
- **Database:** PostgreSQL
- **Email:** Resend (HTTP API, no SDK dependency)
- **Auth:** bcrypt-hashed passwords, JWT session tokens
- **Frontend:** plain HTML/CSS/JS, no build step, no framework

## Project structure

```
.
├── server.js         # entire backend — routes, auth, email, DB queries
├── admin.html         # admin panel: create/view grants
├── activate.html       # landing page opened from the emailed link
├── login.html          # real login form
├── dashboard.html      # protected page, live countdown, logout
├── styles.css          # shared design system (all pages)
├── schema.sql           # Postgres table definition
├── .env                # local secrets (not committed)
└── .env.example         # template for .env
```

## Setup

**1. Install dependencies**
```bash
npm install
```

**2. Create the database** (PostgreSQL must be running)
```sql
CREATE USER temp_access_user WITH PASSWORD 'localdevpass';
CREATE DATABASE temp_access OWNER temp_access_user;
```

**3. Run the migration**
```bash
psql -U temp_access_user -d temp_access -h localhost -f schema.sql
```

**4. Configure `.env`**
```
PORT=3000
DATABASE_URL=postgres://temp_access_user:localdevpass@localhost:5432/temp_access
JWT_SECRET=<long random string>
ADMIN_API_KEY=<random string — this is your admin panel password>
RESEND_API_KEY=<from resend.com>
EMAIL_FROM=onboarding@resend.dev
PUBLIC_BASE_URL=http://localhost:3000
SESSION_TTL_SECONDS=3600
```

Resend's free tier without a verified domain can only send **from**
`onboarding@resend.dev` **to** the email you signed up with. Verify a
domain later to send to anyone.

**5. Start the server**
```bash
npm start
```

**6. Open the admin panel**
```
http://localhost:3000/admin.html
```

## Pages

| Page | Purpose |
|---|---|
| `/admin.html` | Admin creates a grant: email, duration, admin key |
| `/access/<token>` | Opened from the emailed link. Activates the grant, starts the timer, shows a live countdown |
| `/login.html` | Enter the emailed email + temporary password |
| `/dashboard.html` | Protected page. Shows live countdown to expiry, logout button |

## API reference

All JSON endpoints live under `/api`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/admin/grants` | `X-Admin-Key` header | Create a grant, sends the access email |
| GET | `/api/admin/grants` | `X-Admin-Key` header | List recent grants |
| POST | `/api/admin/grants/:id/revoke` | `X-Admin-Key` header | Revoke a PENDING/ACTIVE grant |
| GET | `/api/activate/:token` | none | Activate access, starts the timer (called by `activate.html`) |
| POST | `/api/auth/login` | none | `{email, password}` → session JWT |
| GET | `/api/app/me` | `Authorization: Bearer <token>` | Example protected route |
| POST | `/api/auth/logout` | `Authorization: Bearer <token>` | Revokes the grant — credentials become permanently unusable |
| GET | `/health` | none | Health check |

## Access grant lifecycle

```
PENDING → ACTIVE → EXPIRED
              │
              └──────→ REVOKED   (admin revoke, or user logout)
```

- **PENDING** — grant created, link not yet opened, timer not started.
- **ACTIVE** — link opened, timer running, login allowed.
- **EXPIRED** — timer ran out. Enforced server-side against `expires_at`
  in Postgres; the frontend never decides this.
- **REVOKED** — either an admin revoked it, or the user logged out.
  Credentials are permanently dead; a new grant is required for further
  access.

## Design notes

- **Token vs. password.** The 9-digit token is an identifier, not a secret
  — it's hashed with SHA-256 for fast lookup. The password is a real
  credential — hashed with bcrypt (cost 12).
- **Timer starts on activation, not creation.** If a grant is created at
  10am and opened at 4pm, the clock starts at 4pm. Matches the original
  design brief exactly.
- **Session JWTs are capped at the grant's expiry** —
  `min(now + SESSION_TTL_SECONDS, grant.expires_at)` — so a session can
  never outlive its grant.
- **`requireSession` re-checks the database on every request**, not just
  the JWT signature, so revocation (via logout or admin action) takes
  effect immediately rather than waiting for the JWT to naturally expire.
- **All expiry and status decisions happen server-side** against Postgres.
  The frontend only displays what the server tells it.

## Not handled (by design)

Per the project's "convenience over maximum security" philosophy, this
does not attempt to solve: phishing, social engineering, credential
sharing, screenshotted or forwarded credentials, or compromised user
devices.

## Extending later

The `access_grants` table and its status enum already support most future
additions without a schema change:

- Access-duration extension
- Audit log / dashboard of all grants
- MFA for sensitive applications
- Device or session restriction
- One-time (single-use) access links
- Multiple applications / granular permissions