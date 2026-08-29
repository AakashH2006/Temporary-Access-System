# Temporary Access Gateway

Lets a customer who has **no VPN credentials** reach a VPN-hosted application
for a window of time an admin decides — through a browser, with nothing to
install.

An admin enters an email and a duration. The system emails a one-time link and
a temporary password. Opening the link starts the clock. From then until the
window closes, that person's browser reaches the internal app through this
gateway, and the gateway re-checks their authorization on every single request.

## How it works

The gateway is an **identity-aware reverse proxy**. It is the only component
that sits in both networks: public on one side, on the VPN on the other.

```
                    ┌─────────────────────────────────────┐
   customer         │  gateway host                       │
   (no VPN)         │                                     │
       │            │   nginx :443  ──▶  node :3000       │
       └── HTTPS ───┼──▶ (TLS)           (this repo)      │
                    │                        │            │
                    │                   Postgres          │
                    └────────────────────────┼────────────┘
                                             │ VPN interface
                                             ▼
                                   the internal app
                                   (never public)
```

The customer never receives VPN credentials and never gets a route into the
internal network. They can reach exactly one thing: whatever `UPSTREAM_URL`
names.

## The flow

```
ADMIN                     GATEWAY                       CUSTOMER
  │                         │                             │
  ├─ email + duration ──────▶                             │
  │                         ├─ 9-digit token + password    │
  │                         ├─ create PENDING grant        │
  │                         ├─ email link + password ──────▶
  │                         │                             ├─ opens the link
  │                         │◀──────── activate ───────────┤
  │                         ├─ ACTIVE, timer starts        │
  │                         │                             ├─ logs in
  │                         │◀──────── login ──────────────┤
  │                         ├─ httpOnly session cookie ────▶
  │                         │                             ├─ uses the real app
  │                         │◀═══════ every request ═══════┤
  │                         ├─ re-check grant, then proxy  │
  │                         │                             ├─ ends session
  │                         │◀──────── logout ─────────────┤
  │                         ├─ REVOKED (credentials dead)  │
```

**Authorization is re-checked on every proxied request**, not just at login.
That is what makes an expiry or a revoke cut someone off *mid-session* rather
than at their next login.

**Logging out permanently ends the grant.** It doesn't just clear a session —
the emailed credentials can never be used again, even with time left on the
clock. Getting back in requires a new grant.

## URL layout

The gateway reserves exactly one namespace. Everything else on the origin
belongs to the app.

| Path | Owner |
|---|---|
| `/__access/*` | the gateway |
| everything else | the upstream app, proxied verbatim |

This is why the app keeps its own `/api`, `/login`, `/admin` and its
root-relative asset paths. A gateway mounted at `/` with the app under a
subpath would break every absolute link the app emits.

| Page | Purpose |
|---|---|
| `/__access/admin-login` | Admin sign in |
| `/__access/admin` | Issue a grant, list recent grants, revoke |
| `/__access/link/<token>` | Opened from the email. Activates the grant and starts the clock |
| `/__access/login` | Email + temporary password |
| `/__access/dashboard` | Countdown, and a way into the app |
| `/` and everything else | The internal application |

## Stack

- **Backend:** Node.js 20+ / Express 5, single `server.js`
- **Proxy:** `http-proxy-middleware`, with websocket support
- **Database:** PostgreSQL
- **Email:** Resend (HTTP API, no SDK)
- **Auth:** bcrypt passwords (cost 12), JWT in an httpOnly cookie, separate
  admin accounts with per-account lockout
- **Frontend:** plain HTML/CSS/JS, no build step

## Project structure

```
server.js               the entire gateway
schema.sql              Postgres tables (re-runnable)
public/                 the gate's own pages
  admin-login.html      admin sign in
  admin.html            issue and revoke grants
  activate.html         landing page for the emailed link
  login.html            credential entry
  dashboard.html        countdown and entry to the app
  styles.css            shared design system
demo-app/app.js         stand-in upstream, for testing without the real app
scripts/create-admin.js the only way an admin account is created
deploy/
  nginx.conf            TLS termination and websocket upgrade
  temp-access.service   systemd unit
DEPLOY.md               production runbook
.env.example            annotated configuration template
```

## Running locally

```bash
npm install
cp .env.example .env          # then fill in the secrets it names
psql "$DATABASE_URL" -f schema.sql
npm run create-admin          # create the account you'll sign in with
```

Two processes — the gateway, and something for it to proxy to:

```bash
npm run demo-app     # stand-in upstream on :4000
npm start            # gateway on :3000
```

Then open `http://localhost:3000/__access/admin`, issue a grant to yourself,
and follow the emailed link. Without a verified Resend domain the send will
fail — that's expected, and the admin console shows the password on screen so
you can carry on.

Point `UPSTREAM_URL` at the real application when you have one. Nothing else
changes.

## Admin authentication

Whoever holds admin access can mint access to the internal network for anyone,
indefinitely. It is the most powerful credential in the system, so it is
guarded by three independent layers rather than one shared secret.

**1. Network position.** `ADMIN_IP_ALLOWLIST` (and the matching `allow`/`deny`
block in `deploy/nginx.conf`) restricts the console to your VPN or office
range. Admins already have VPN access by the premise of this system, so the
console never needs to answer the public internet. A request from outside the
allowlist gets a `404`, not a `403` — it learns nothing about what is here.

**2. Per-person accounts.** Each admin has their own email and bcrypt password,
and can be disabled individually without disrupting anyone else. Every action
in the audit log carries the admin's real email, so the log can answer *who let
this customer in*. Disabling an account takes effect on the next request, not
at token expiry.

**3. Lockout and rate limiting.** Two deliberately different controls:
`ADMIN_MAX_FAILED_ATTEMPTS` (default 5) locks a single **account** in Postgres,
surviving restarts; `ADMIN_LOGIN_RATE_MAX` (default 10) throttles a single
**IP**, catching spraying across accounts. The limiter is the looser of the two
on purpose — if it tripped first, the account lockout would be unreachable dead
code and operators would see an opaque `429` instead of an audited
`ADMIN_LOCKED` event.

Accounts exist only via the CLI:

```bash
npm run create-admin                      # prompts
npm run create-admin -- you@example.com   # prompts for the password only
```

There is no signup page and no password-reset email — deliberately. Recovery
from a lost password or a lockout means SSH plus re-running that command, so
host access is the recovery control. Re-running it for an existing email resets
the password and clears any lockout.

TOTP two-factor is scaffolded but not implemented: the `totp_secret` and
`totp_enabled` columns exist and the login flow has the branch, so enabling it
later is additive rather than a migration.

## Access grant lifecycle

```
PENDING → ACTIVE → EXPIRED
              │
              └──────→ REVOKED   (admin revoke, or customer logout)
```

- **PENDING** — created, link not yet opened, clock not started.
- **ACTIVE** — link opened, clock running, login and proxying allowed.
- **EXPIRED** — window closed. Decided server-side against `expires_at`.
- **REVOKED** — admin revoked it, or the customer logged out. Permanent.

## Design notes

- **The clock starts on activation, not creation.** A grant created at 10am
  and opened at 4pm runs from 4pm.
- **Sessions live in an httpOnly cookie, not `sessionStorage`.** This is forced
  by the proxy: when the browser fetches the app's own stylesheets, scripts and
  XHRs it attaches cookies but never an `Authorization` header. A bearer-token
  session cannot gate a reverse proxy.
- **Sessions are capped at the grant's expiry** — `min(now + SESSION_TTL, grant.expires_at)`
  — so a session can never outlive its grant.
- **Grant status is cached for a few seconds** on the proxy hot path, because
  re-reading Postgres for every image would make the gateway the slowest thing
  in the stack. Logout and admin-revoke bust the cache directly, so revocation
  stays effectively instant.
- **The session cookie is stripped before forwarding.** The upstream app never
  sees it. It receives `X-Temp-Access-Email` and `X-Temp-Access-Grant` instead,
  set unconditionally so a client cannot forge them.
- **A countdown bar is injected into the app's HTML pages** so the customer can
  always see the time left and end the session from anywhere inside the app.
  Only documents are buffered for injection; assets stream untouched.
- **Websocket upgrades are authorized separately**, since they bypass Express
  middleware entirely.
- **Token vs. password.** The 9-digit token is an identifier, SHA-256 hashed
  for lookup. The password is a real credential, bcrypt cost 12.
- **Failed logins are counted and audited**, and a login against a
  non-existent grant still runs a bcrypt comparison, so response timing does
  not reveal which emails have grants.
- **A background sweeper** flips lapsed grants to `EXPIRED`, so the admin
  console doesn't show stale `ACTIVE` rows for windows that closed hours ago.
- **Admin and customer sessions cannot be swapped.** Admin tokens are signed
  with a key *derived* from `JWT_SECRET`, not `JWT_SECRET` itself, so a
  customer's cookie replayed as an admin cookie fails the signature check
  structurally — rather than depending on someone remembering to check a claim.
- **The reserved namespace is sealed in both directions.** A `/__access/*` URL
  the gateway does not define returns 404 instead of falling through to the
  proxy, so the app can never see or answer requests inside the one namespace
  this design promises it will never own.

## Not handled (by design)

Per the project's convenience-over-maximum-security philosophy, this does not
attempt to solve: phishing, social engineering, credential sharing,
screenshotted or forwarded credentials, or compromised customer devices.

The fingerprint captured at activation flags a link opened from a different
IP or browser (`ACTIVATE_REOPENED_FINGERPRINT_MISMATCH` in the audit log) but
deliberately does not block it — customers roam between networks, and a false
lockout is worse than a logged anomaly.

## Extending later

The schema already supports most of these without a migration:

- Extending an active window
- TOTP two-factor for admins (columns and login branch already in place)
- Multiple upstreams, with per-grant permissions
- One-time (single-use) links
- Per-grant path allowlists within the app
- Ephemeral WireGuard peers, for non-HTTP access (SSH, RDP, databases)

## Deployment

See [DEPLOY.md](DEPLOY.md).
