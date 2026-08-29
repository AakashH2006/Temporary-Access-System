# Deploying the gateway

The gateway is the only machine that needs to sit in two networks at once:
reachable from the public internet, and able to reach the VPN-hosted app.
Nothing else changes about the app, and customers install nothing.

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

The security property that matters: **the gateway's own network position is
the secret.** A customer never receives VPN credentials, never gets a route
into the internal network, and can only reach whatever single upstream
`UPSTREAM_URL` names.

---

## 1. Host prerequisites

A small VM is plenty — this is I/O-bound, not CPU-bound.

```bash
sudo apt update
sudo apt install -y nodejs npm postgresql nginx certbot python3-certbot-nginx
node -v      # needs >= 20
```

The host must already be on the VPN and able to reach the app:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://<internal-app>:<port>/
```

If that doesn't return a status code, stop here — the gateway cannot forward
to something it can't reach, and nothing downstream will work.

## 2. Service user and code

```bash
sudo useradd --system --home /opt/temp-access --shell /usr/sbin/nologin tempaccess
sudo mkdir -p /opt/temp-access
sudo chown tempaccess:tempaccess /opt/temp-access

sudo -u tempaccess git clone <your-repo> /opt/temp-access
cd /opt/temp-access
sudo -u tempaccess npm ci --omit=dev
```

## 3. Database

```bash
sudo -u postgres psql <<'SQL'
CREATE USER temp_access_user WITH PASSWORD 'CHANGE-ME';
CREATE DATABASE temp_access OWNER temp_access_user;
SQL

psql "postgres://temp_access_user:CHANGE-ME@localhost:5432/temp_access" -f schema.sql
```

`schema.sql` is written to be re-runnable, so applying it again on upgrade is
safe.

## 4. Configuration

```bash
sudo -u tempaccess cp .env.example .env
sudo -u tempaccess nano .env
```

Generate the signing secret:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

There is no admin API key to generate any more — admin access is per-person
accounts, created in step 4b.

The values that actually decide whether this works:

| Variable | Production value | What breaks if wrong |
|---|---|---|
| `PUBLIC_BASE_URL` | `https://access.example.com` | Emailed links point somewhere dead. Must be the **public** URL, https, no trailing slash. |
| `UPSTREAM_URL` | `http://10.x.x.x:8080` | 502 for every customer. Must be reachable from this host and **not** from the internet. |
| `TRUST_PROXY` | `true` | Left `false` behind nginx, every visitor shares one rate-limit bucket and the audit log records nginx's IP for everyone. |
| `JWT_SECRET` | 48 random bytes | Under 32 chars the gateway refuses to boot. Changing it later invalidates every live session. |
| `DATABASE_SSL` | `true` for managed Postgres | Connection failures at boot. |
| `ADMIN_IP_ALLOWLIST` | your VPN/office CIDRs | Left empty, the admin console answers the public internet. This is the cheapest strong control available -- use it. |

Lock the file down — it holds the key to the internal network:

```bash
sudo chown root:tempaccess .env && sudo chmod 640 .env
```

## 4b. Create the first admin

There is no shared admin key and no signup page. Accounts are created here:

```bash
sudo -u tempaccess npm run create-admin
```

Use a real address and a password from a password manager. Nothing can be
issued until at least one account exists -- the gateway warns loudly at boot
when the table is empty.

This same command is the recovery path: re-running it for an existing email
resets the password and clears any lockout. Losing an admin password therefore
requires SSH to fix, which is itself a control worth keeping.

## 5. Service

```bash
sudo cp deploy/temp-access.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now temp-access
sudo journalctl -u temp-access -f
```

A healthy start logs the upstream and admin URLs. A misconfigured one exits
immediately naming the missing variable, rather than starting and failing per
request.

## 6. TLS and nginx

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/temp-access
sudo nano /etc/nginx/sites-available/temp-access     # set your hostname
sudo ln -s /etc/nginx/sites-available/temp-access /etc/nginx/sites-enabled/
```

Add to the `http {}` block of `/etc/nginx/nginx.conf` if not already present:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

Then:

```bash
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d access.example.com
```

Certbot rewrites the TLS paths itself, so run it after the config is in place.

## 7. Firewall

The gateway is the only public surface. Node must not be reachable directly —
if it is, `TRUST_PROXY=true` lets anyone forge their source IP.

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80,443/tcp
sudo ufw deny 3000/tcp
sudo ufw enable
```

Confirm from a machine that is **not** on the VPN:

```bash
curl -sS -m 5 http://<gateway-public-ip>:3000/    # must fail
curl -sS -m 5 http://<internal-app>:<port>/       # must fail
```

Both failing is the whole point of the design. If either succeeds, the
gateway is being bypassed.

## 8. Verify

```bash
curl -sS https://access.example.com/__access/health
# {"ok":true,"upstream":"http://10.x.x.x:8080"}

curl -sSI https://access.example.com/
# HTTP/2 302 ... location: /__access/login?next=%2F&reason=no_session
```

That 302 on `/` is the real test: an unauthenticated visitor is bounced to the
login page instead of reaching the app.

Then issue a grant to yourself at `https://access.example.com/__access/admin`
and walk the flow once end to end.

---

## Email

Resend without a verified domain will only send **from** `onboarding@resend.dev`
**to** the address the account was registered with. Real customers will not
receive anything until a domain is verified at
[resend.com/domains](https://resend.com/domains) and `EMAIL_FROM` points at it.

Until then the admin console still works: a failed send returns the password
on screen for the admin to relay by hand, and the grant itself is valid.

## Operating notes

**Upgrades**

```bash
cd /opt/temp-access
sudo -u tempaccess git pull
sudo -u tempaccess npm ci --omit=dev
psql "$DATABASE_URL" -f schema.sql     # re-runnable
sudo systemctl restart temp-access
```

Restarting drops live sessions only if `JWT_SECRET` changed; otherwise
customers keep working, since sessions are stateless and re-checked against
Postgres on every request.

**Backups.** `access_grants` is small; `audit_log` grows forever by design.

```bash
pg_dump "$DATABASE_URL" | gzip > /var/backups/temp-access-$(date +%F).sql.gz
```

**Removing an admin.** Takes effect on their next request, no restart needed:

```sql
UPDATE admins SET disabled_at = now() WHERE email = 'someone@example.com';
```

**Revoking customer access in a hurry.** Any of these ends access immediately:

- the Revoke button in the admin console (takes effect within `GRANT_CACHE_TTL_MS`, default 5s)
- `systemctl stop temp-access` — kills all access at once
- `UPDATE access_grants SET status='REVOKED' WHERE status='ACTIVE';` in psql

**Reading the audit log.**

```sql
SELECT created_at, event, actor, ip_address, detail
FROM audit_log ORDER BY created_at DESC LIMIT 50;
```

`ADMIN_LOGIN_FAILED`, `ADMIN_LOCKED` and `ADMIN_IP_DENIED` are the admin-side
events worth alerting on -- repeated ones mean someone is probing the console.

`ACTIVATE_REOPENED_FINGERPRINT_MISMATCH` is the customer-side one: an
access link opened from a different IP or browser than the one that first
activated it, which is what a forwarded or intercepted link looks like.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Admin console 404s from your own machine | Your IP is outside `ADMIN_IP_ALLOWLIST` or nginx's `allow` list. Check the `ADMIN_IP_DENIED` audit rows for the address it actually saw. |
| Admin sign-in 401s with the right password | The account is locked (`ADMIN_LOCKED` in the audit log). Wait `ADMIN_LOCKOUT_MINUTES`, or re-run `npm run create-admin`. |
| Admin sign-in returns 429 | Per-IP throttle; waits out `ADMIN_LOGIN_RATE_WINDOW_MINUTES`. |
| `no admin accounts exist` at boot | Run `npm run create-admin`. |
| Exits at boot naming a variable | That variable is missing from `.env`. |
| `502` on every page | `UPSTREAM_URL` unreachable from this host. Test with `curl` as the service user. |
| Redirect loop at login | `COOKIE_SECURE=true` while serving over plain HTTP — the browser refuses to store the cookie. |
| Login works, app pages 401 | Something is stripping cookies between nginx and node. |
| Countdown bar missing | The app sets a `Content-Security-Policy`. Set `STRIP_UPSTREAM_CSP=true`, or `INJECT_BANNER=false` to drop the bar. |
| All audit rows share one IP | `TRUST_PROXY` is not `true` while nginx is in front. |
| Everyone rate-limited at once | Same cause. |
| App's links point at the internal hostname | The app has a hardcoded base URL. Configure the app to use `https://access.example.com`, or have it honour `X-Forwarded-Host`. |
