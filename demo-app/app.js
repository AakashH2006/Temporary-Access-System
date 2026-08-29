// A stand-in for the real VPN-hosted application.
//
// It exists so the whole path -- grant, email, activate, log in, proxy --
// can be exercised before anyone knows what the real app is. It deliberately
// uses root-relative asset paths and its own /api and /login routes, because
// those are exactly the things a naive proxy breaks. If this app renders
// correctly through the gateway, a real one will too.
//
// Replace it by pointing UPSTREAM_URL at the real app. Nothing else changes.

const express = require('express');

const app = express();
const PORT = Number(process.env.DEMO_PORT || 4000);

// Root-relative, and deliberately named to collide with the gate's own
// vocabulary. The /__access namespace is what keeps these separate.
app.get('/app.css', (_req, res) => {
  res.type('text/css').send(`
    body { margin:0; font-family: system-ui, sans-serif; background:#0f1218; color:#e8e6e1; }
    .wrap { max-width: 680px; margin: 0 auto; padding: 64px 24px; }
    h1 { font-size: 28px; margin: 0 0 8px; }
    .who { font-family: ui-monospace, monospace; color:#7fd1b9; }
    .card { background:#161b24; border:1px solid #232a36; border-radius:12px; padding:20px; margin-top:24px; }
    a { color:#7fd1b9; }
    code { background:#0b0e13; padding:2px 6px; border-radius:4px; }
  `);
});

// An app-owned /api route, proving the gate's /__access/api namespace does
// not collide with the application's own API.
app.get('/api/data', (req, res) => {
  res.json({
    source: 'the internal application',
    seenAs: req.header('X-Temp-Access-Email') || null,
    at: new Date().toISOString(),
  });
});

// An app-owned /login route, which under the old layout would have been
// shadowed by the gate's own login page.
app.get('/login', (_req, res) => {
  res.type('html').send('<link rel="stylesheet" href="/app.css"><div class="wrap">'
    + '<h1>The application\'s own /login</h1>'
    + '<p>This route belongs to the app, not the gateway. It is reachable, '
    + 'which is the point.</p><p><a href="/">Back</a></p></div>');
});

app.get('/', (req, res) => {
  const email = req.header('X-Temp-Access-Email') || '(no identity header)';
  const grant = req.header('X-Temp-Access-Grant') || '(none)';
  res.type('html').send(`<!doctype html>
<html><head><meta charset="utf-8"><title>Internal Application</title>
<link rel="stylesheet" href="/app.css"></head>
<body>
  <div class="wrap">
    <h1>Internal Application</h1>
    <p>You are inside the VPN-hosted app, reached through the temporary access gateway.</p>

    <div class="card">
      <p>The gateway told me who you are:</p>
      <p class="who">${email}</p>
      <p style="color:#6b7280;font-size:13px">grant ${grant}</p>
    </div>

    <div class="card">
      <p>Things that prove the proxy is honest:</p>
      <ul>
        <li>This page's stylesheet loaded from <code>/app.css</code> &mdash; a root-relative path.</li>
        <li><a href="/login">/login</a> is the app's own route, not the gateway's.</li>
        <li><a href="/api/data">/api/data</a> is the app's own API.</li>
      </ul>
    </div>

    <p style="color:#6b7280;font-size:13px">
      The bar pinned at the top of this page was injected by the gateway.
      The application itself knows nothing about it.
    </p>
  </div>
</body></html>`);
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`demo upstream app listening on http://127.0.0.1:${PORT}`);
});
