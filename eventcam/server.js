const express = require('express');
const https = require('https');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const qrcode = require('qrcode');
const archiver = require('archiver');
const { Pool } = require('pg');

const app = express();

const PORT = Number(process.env.PORT || 5000);
const BASE_URL_ENV = process.env.BASE_URL || '';
const DEFAULT_EVENT_NAME = process.env.DEFAULT_EVENT_NAME || 'My Event';
const ALLOW_GUEST_UPLOADS = (process.env.ALLOW_GUEST_UPLOADS || 'true').toLowerCase() === 'true';
const PHOTOS_DIR = process.env.PHOTOS_DIR || '/photos';
const CONFIG_DIR = process.env.CONFIG_DIR || '/config';
const SSL_CERT_PATH = process.env.SSL_CERT_PATH || '';
const SSL_KEY_PATH = process.env.SSL_KEY_PATH || '';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';

const DB_HOST = process.env.DB_HOST || '';
const DB_PORT = Number(process.env.DB_PORT || 5432);
const DB_NAME = process.env.DB_NAME || 'eventcam';
const DB_USER = process.env.DB_USER || 'eventcam';
const DB_PASSWORD = process.env.DB_PASSWORD || '';
const DB_SSLMODE = process.env.DB_SSLMODE || 'disable';

const EVENTS_FILE = path.join(CONFIG_DIR, 'events.json');
const ADMIN_FILE = path.join(CONFIG_DIR, 'admin.json');
const AUTH_SECRET_FILE = path.join(CONFIG_DIR, 'auth-secret');

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/static', express.static(path.join(__dirname, 'public')));

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function loadAuthSecret() {
  ensureDir(CONFIG_DIR);
  try {
    return fs.readFileSync(AUTH_SECRET_FILE, 'utf8').trim();
  } catch (err) {
    const secret = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(AUTH_SECRET_FILE, secret, 'utf8');
    return secret;
  }
}

function safeId() {
  return crypto.randomBytes(4).toString('hex');
}

function base64UrlEncode(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (padded.length % 4)) % 4;
  const paddedValue = padded + '='.repeat(padLength);
  return Buffer.from(paddedValue, 'base64').toString('utf8');
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  return header.split(';').reduce((acc, part) => {
    const [key, ...rest] = part.trim().split('=');
    if (!key) return acc;
    acc[key] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

const AUTH_SECRET = loadAuthSecret();

function signToken(value) {
  return crypto.createHmac('sha256', AUTH_SECRET).update(value).digest('hex');
}

function encodeAuthToken(payload) {
  const body = base64UrlEncode(JSON.stringify(payload));
  const signature = signToken(body);
  return `${body}.${signature}`;
}

function decodeAuthToken(token) {
  if (!token) return null;
  const [body, signature] = token.split('.');
  if (!body || !signature) return null;
  if (signToken(body) !== signature) return null;
  try {
    return JSON.parse(base64UrlDecode(body));
  } catch (err) {
    return null;
  }
}

function setAuthCookie(req, res, token) {
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const attributes = [
    `eventcam_auth=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${60 * 60 * 24 * 7}`
  ];
  if (secure) {
    attributes.push('Secure');
  }
  res.setHeader('Set-Cookie', attributes.join('; '));
}

function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', 'eventcam_auth=; Path=/; Max-Age=0; SameSite=Lax');
}

function baseUrlFromRequest(req) {
  if (BASE_URL_ENV) return BASE_URL_ENV;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.get('host')}`;
}

function generateEventCredentials() {
  const username = `guest-${crypto.randomBytes(3).toString('hex')}`;
  const password = crypto.randomBytes(9).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 12);
  return { username, password };
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex'), iterations = 100000) {
  const hash = crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha256').toString('hex');
  return { salt, hash, iterations };
}

function loadAdminConfig() {
  try {
    const raw = fs.readFileSync(ADMIN_FILE, 'utf8');
    const data = JSON.parse(raw);
    if (data && data.user && data.salt && data.hash && data.iterations) {
      return data;
    }
  } catch (err) {
    // Fall through to environment defaults.
  }
  return {
    user: ADMIN_USER,
    ...hashPassword(ADMIN_PASSWORD)
  };
}

function saveAdminConfig(config) {
  ensureDir(CONFIG_DIR);
  fs.writeFileSync(ADMIN_FILE, JSON.stringify({
    user: config.user,
    salt: config.salt,
    hash: config.hash,
    iterations: config.iterations,
    updatedAt: new Date().toISOString()
  }, null, 2), 'utf8');
}

function verifyPassword(password, config) {
  const test = crypto.pbkdf2Sync(password, config.salt, config.iterations, 64, 'sha256').toString('hex');
  const expected = Buffer.from(config.hash, 'hex');
  const actual = Buffer.from(test, 'hex');
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(expected, actual);
}

const adminConfig = loadAdminConfig();

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="EventCam Admin"');
    res.status(401).send('Authentication required.');
    return;
  }
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const [user, pass] = decoded.split(':');
  if (user !== adminConfig.user || !verifyPassword(pass || '', adminConfig)) {
    res.set('WWW-Authenticate', 'Basic realm="EventCam Admin"');
    res.status(401).send('Invalid credentials.');
    return;
  }
  next();
}

function listPhotosForEvent(eventId) {
  const eventPath = path.join(PHOTOS_DIR, eventId);
  try {
    const files = fs.readdirSync(eventPath);
    return files.filter((file) => /\.(jpe?g|png|webp)$/i.test(file));
  } catch (err) {
    return [];
  }
}

let pool = null;

async function initDb() {
  if (!DB_HOST) return;
  pool = new Pool({
    host: DB_HOST,
    port: DB_PORT,
    database: DB_NAME,
    user: DB_USER,
    password: DB_PASSWORD,
    ssl: DB_SSLMODE === 'disable' ? false : { rejectUnauthorized: DB_SSLMODE !== 'require' }
  });

  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS event_user TEXT;`);
  await pool.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS event_password TEXT;`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS photos (
      id SERIAL PRIMARY KEY,
      event_id TEXT REFERENCES events(id),
      path TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  const missing = await pool.query('SELECT id FROM events WHERE event_user IS NULL OR event_password IS NULL');
  for (const row of missing.rows) {
    const creds = generateEventCredentials();
    await pool.query(
      'UPDATE events SET event_user = $1, event_password = $2 WHERE id = $3',
      [creds.username, creds.password, row.id]
    );
  }
}

function loadEventsLocal() {
  try {
    const raw = fs.readFileSync(EVENTS_FILE, 'utf8');
    const events = JSON.parse(raw);
    let updated = false;
    events.forEach((evt) => {
      if (!evt.event_user || !evt.event_password) {
        const creds = generateEventCredentials();
        evt.event_user = creds.username;
        evt.event_password = creds.password;
        updated = true;
      }
    });
    if (updated) {
      saveEventsLocal(events);
    }
    return events;
  } catch (err) {
    return [];
  }
}

function saveEventsLocal(events) {
  ensureDir(CONFIG_DIR);
  fs.writeFileSync(EVENTS_FILE, JSON.stringify(events, null, 2), 'utf8');
}

async function listEvents() {
  if (pool) {
    const result = await pool.query('SELECT id, name, event_user, event_password FROM events ORDER BY created_at DESC');
    return result.rows;
  }
  return loadEventsLocal();
}

async function createEvent(name) {
  const id = safeId();
  const creds = generateEventCredentials();
  if (pool) {
    await pool.query('INSERT INTO events (id, name, event_user, event_password) VALUES ($1, $2, $3, $4)', [
      id,
      name,
      creds.username,
      creds.password
    ]);
  } else {
    const events = loadEventsLocal();
    events.unshift({ id, name, event_user: creds.username, event_password: creds.password });
    saveEventsLocal(events);
  }
  return { id, name, event_user: creds.username, event_password: creds.password };
}

async function eventExists(eventId) {
  const event = await getEvent(eventId);
  return Boolean(event);
}

async function getEvent(eventId) {
  if (pool) {
    const result = await pool.query(
      'SELECT id, name, event_user, event_password FROM events WHERE id = $1',
      [eventId]
    );
    return result.rows[0] || null;
  }
  const events = loadEventsLocal();
  return events.find((evt) => evt.id === eventId) || null;
}

async function recordPhoto(eventId, filePath) {
  if (!pool) return;
  await pool.query('INSERT INTO photos (event_id, path) VALUES ($1, $2)', [eventId, filePath]);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const eventId = req.body.eventId || req.query.event;
    const eventPath = path.join(PHOTOS_DIR, eventId || 'unknown');
    ensureDir(eventPath);
    cb(null, eventPath);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '') || '.jpg';
    const name = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}${ext}`;
    cb(null, name);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 }
});

function isAuthorizedForEvent(req, event) {
  const cookies = parseCookies(req);
  const token = cookies.eventcam_auth;
  const payload = decodeAuthToken(token);
  if (!payload) return false;
  if (payload.eventId !== event.id) return false;
  if (payload.user !== event.event_user) return false;
  if (payload.exp && Date.now() > payload.exp) return false;
  return true;
}

app.get('/', async (req, res) => {
  const eventId = req.query.event;
  if (!eventId) {
    res.redirect('/admin');
    return;
  }

  const event = await getEvent(eventId);
  if (!event) {
    res.status(404).send(renderPage('Event Not Found', `<p class="muted">Event not found.</p>`));
    return;
  }

  if (!isAuthorizedForEvent(req, event)) {
    res.redirect(`/login?event=${encodeURIComponent(eventId)}`);
    return;
  }

  res.send(renderCapturePage(eventId));
});

app.get('/event/dashboard', async (req, res) => {
  const eventId = req.query.event;
  if (!eventId) {
    res.status(400).send(renderPage('Missing Event', '<p class="muted">Missing event id.</p>'));
    return;
  }
  const event = await getEvent(eventId);
  if (!event) {
    res.status(404).send(renderPage('Event Not Found', '<p class="muted">Event not found.</p>'));
    return;
  }
  if (!isAuthorizedForEvent(req, event)) {
    res.redirect(`/login?event=${encodeURIComponent(eventId)}`);
    return;
  }

  const files = listPhotosForEvent(eventId);
  const gallery = files.map((file) => `
    <a class="thumb" href="/event/media/${encodeURIComponent(eventId)}/${encodeURIComponent(file)}" target="_blank" rel="noopener">
      <img src="/event/media/${encodeURIComponent(eventId)}/${encodeURIComponent(file)}" alt="Photo" />
    </a>
  `).join('');

  const content = `
    <section class="hero">
      <h1>${escapeHtml(event.name)}</h1>
      <p class="muted">Your private event gallery.</p>
    </section>
    <section class="panel">
      <div class="row">
        <a href="/event/download?event=${encodeURIComponent(eventId)}">
          <button type="button">Download all photos</button>
        </a>
        <a href="/?event=${encodeURIComponent(eventId)}">
          <button type="button">Back to camera</button>
        </a>
      </div>
    </section>
    <section class="gallery">
      ${gallery || '<p class="muted">No photos yet.</p>'}
    </section>
  `;

  res.send(renderPage('Event Dashboard', content));
});

app.get('/event/media/:eventId/:filename', async (req, res) => {
  const eventId = req.params.eventId;
  const filename = path.basename(req.params.filename);
  const event = await getEvent(eventId);
  if (!event) {
    res.status(404).send('Event not found.');
    return;
  }
  if (!isAuthorizedForEvent(req, event)) {
    res.status(401).send('Authentication required.');
    return;
  }
  const filePath = path.join(PHOTOS_DIR, eventId, filename);
  res.sendFile(filePath);
});

app.get('/event/download', async (req, res) => {
  const eventId = req.query.event;
  if (!eventId) {
    res.status(400).send('Missing event id.');
    return;
  }
  const event = await getEvent(eventId);
  if (!event) {
    res.status(404).send('Event not found.');
    return;
  }
  if (!isAuthorizedForEvent(req, event)) {
    res.status(401).send('Authentication required.');
    return;
  }

  const files = listPhotosForEvent(eventId);
  if (!files.length) {
    res.status(404).send('No photos to download.');
    return;
  }

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="event-${eventId}-photos.zip"`);

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.on('error', (err) => {
    res.status(500).send(err.message);
  });

  archive.pipe(res);
  for (const file of files) {
    const filePath = path.join(PHOTOS_DIR, eventId, file);
    archive.file(filePath, { name: file });
  }
  archive.finalize();
});

app.get('/admin', requireAdmin, async (req, res) => {
  const events = await listEvents();
  const baseUrl = baseUrlFromRequest(req);
  const passwordNotice = (() => {
    switch (req.query.pw) {
      case 'changed':
        return '<p class="status">Password updated.</p>';
      case 'mismatch':
        return '<p class="muted">New passwords do not match.</p>';
      case 'weak':
        return '<p class="muted">New password must be at least 8 characters.</p>';
      case 'invalid':
        return '<p class="muted">Current password is incorrect.</p>';
      default:
        return '';
    }
  })();

  const cards = await Promise.all(events.map(async (evt) => {
    const url = `${baseUrl}/?event=${evt.id}`;
    const qr = await qrcode.toDataURL(url, { margin: 1, width: 240 });
    const galleryUrl = `/admin/photos?event=${evt.id}`;
    return `
      <div class="card">
        <h3>${escapeHtml(evt.name)}</h3>
        <p class="muted">Event ID: ${evt.id}</p>
        <p class="muted">Login: ${escapeHtml(evt.event_user || '')} / ${escapeHtml(evt.event_password || '')}</p>
        <img src="${qr}" alt="QR code for ${escapeHtml(evt.name)}" />
        <p><a href="${url}">${url}</a></p>
        <p><a href="${galleryUrl}">View photos</a></p>
      </div>
    `;
  }));

  const content = `
    <section class="hero">
      <h1>EventCam Admin</h1>
      <p>Create an event and share its QR code with guests.</p>
    </section>
    <section class="panel">
      <form method="POST" action="/admin/create" class="row">
        <input type="text" name="name" placeholder="Event name" value="${escapeHtml(DEFAULT_EVENT_NAME)}" />
        <button type="submit">Create Event</button>
      </form>
    </section>
    <section class="panel">
      <h3>Change Admin Password</h3>
      ${passwordNotice}
      <form method="POST" action="/admin/password" class="row">
        <input type="password" name="currentPassword" placeholder="Current password" autocomplete="current-password" required />
        <input type="password" name="newPassword" placeholder="New password" autocomplete="new-password" required />
        <input type="password" name="confirmPassword" placeholder="Confirm new password" autocomplete="new-password" required />
        <button type="submit">Update Password</button>
      </form>
    </section>
    <section class="grid">
      ${cards.join('') || '<p class="muted">No events yet.</p>'}
    </section>
  `;

  res.send(renderPage('EventCam Admin', content));
});

app.post('/admin/create', requireAdmin, async (req, res) => {
  const name = (req.body.name || DEFAULT_EVENT_NAME).trim() || DEFAULT_EVENT_NAME;
  await createEvent(name);
  res.redirect('/admin');
});

app.post('/admin/password', requireAdmin, (req, res) => {
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');
  const confirmPassword = String(req.body.confirmPassword || '');

  if (!verifyPassword(currentPassword, adminConfig)) {
    res.redirect('/admin?pw=invalid');
    return;
  }
  if (newPassword.length < 8) {
    res.redirect('/admin?pw=weak');
    return;
  }
  if (newPassword !== confirmPassword) {
    res.redirect('/admin?pw=mismatch');
    return;
  }

  const nextConfig = {
    user: adminConfig.user,
    ...hashPassword(newPassword)
  };
  adminConfig.salt = nextConfig.salt;
  adminConfig.hash = nextConfig.hash;
  adminConfig.iterations = nextConfig.iterations;
  saveAdminConfig(adminConfig);
  res.redirect('/admin?pw=changed');
});

app.get('/login', async (req, res) => {
  const eventId = req.query.event;
  if (!eventId) {
    res.status(400).send(renderPage('Missing Event', '<p class="muted">Missing event id.</p>'));
    return;
  }
  const event = await getEvent(eventId);
  if (!event) {
    res.status(404).send(renderPage('Event Not Found', '<p class="muted">Event not found.</p>'));
    return;
  }
  const error = req.query.error === 'invalid' ? 'Invalid credentials.' : '';
  res.send(renderLoginPage(eventId, event.name, error));
});

app.post('/login', async (req, res) => {
  const eventId = String(req.body.eventId || '');
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');
  if (!eventId) {
    res.status(400).send(renderPage('Missing Event', '<p class="muted">Missing event id.</p>'));
    return;
  }
  const event = await getEvent(eventId);
  if (!event) {
    res.status(404).send(renderPage('Event Not Found', '<p class="muted">Event not found.</p>'));
    return;
  }
  if (username !== event.event_user || password !== event.event_password) {
    res.send(renderLoginPage(eventId, event.name, 'Invalid credentials.'));
    return;
  }

  const payload = {
    eventId: event.id,
    user: event.event_user,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 7
  };
  setAuthCookie(req, res, encodeAuthToken(payload));
  res.redirect(`/?event=${encodeURIComponent(eventId)}`);
});

app.get('/admin/photos', requireAdmin, async (req, res) => {
  const eventId = req.query.event;
  if (!eventId) {
    res.status(400).send(renderPage('Missing Event', '<p class="muted">Missing event id.</p>'));
    return;
  }

  const exists = await eventExists(eventId);
  if (!exists) {
    res.status(404).send(renderPage('Event Not Found', '<p class="muted">Event not found.</p>'));
    return;
  }

  const files = listPhotosForEvent(eventId);
  const gallery = files.map((file) => `
    <a class="thumb" href="/admin/media/${encodeURIComponent(eventId)}/${encodeURIComponent(file)}" target="_blank" rel="noopener">
      <img src="/admin/media/${encodeURIComponent(eventId)}/${encodeURIComponent(file)}" alt="Photo" />
    </a>
  `).join('');

  const content = `
    <section class="hero">
      <h1>Event Photos</h1>
      <p class="muted">Event ID: ${escapeHtml(eventId)}</p>
    </section>
    <section class="panel">
      <p><a href="/admin">Back to admin</a></p>
    </section>
    <section class="gallery">
      ${gallery || '<p class="muted">No photos yet.</p>'}
    </section>
  `;

  res.send(renderPage('Event Photos', content));
});

app.get('/admin/media/:eventId/:filename', requireAdmin, (req, res) => {
  const eventId = req.params.eventId;
  const filename = path.basename(req.params.filename);
  const filePath = path.join(PHOTOS_DIR, eventId, filename);
  res.sendFile(filePath);
});

app.post('/upload', upload.single('photo'), async (req, res) => {
  if (!ALLOW_GUEST_UPLOADS) {
    res.status(403).json({ ok: false, error: 'Guest uploads disabled' });
    return;
  }

  const eventId = req.body.eventId || req.query.event;
  if (!eventId) {
    res.status(400).json({ ok: false, error: 'Missing event id' });
    return;
  }

  const event = await getEvent(eventId);
  if (!event) {
    res.status(404).json({ ok: false, error: 'Event not found' });
    return;
  }

  if (!isAuthorizedForEvent(req, event)) {
    res.status(401).json({ ok: false, error: 'Authentication required' });
    return;
  }

  if (!req.file) {
    res.status(400).json({ ok: false, error: 'No file uploaded' });
    return;
  }

  await recordPhoto(eventId, req.file.path);

  res.json({ ok: true, path: req.file.path });
});

function renderPage(title, body) {
  return `<!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <link rel="stylesheet" href="/static/styles.css" />
  </head>
  <body>
    <main>
      ${body}
    </main>
  </body>
  </html>`;
}

function renderCapturePage(eventId) {
  return `<!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>EventCam</title>
    <link rel="stylesheet" href="/static/styles.css" />
  </head>
  <body>
    <main class="capture">
      <section class="camera">
        <video id="video" autoplay playsinline></video>
        <canvas id="canvas" hidden></canvas>
      </section>
      <section class="controls">
        <button id="capture">Take Photo</button>
        <a href="/event/dashboard?event=${encodeURIComponent(eventId)}">
          <button type="button">Event dashboard</button>
        </a>
      </section>
      <section class="status" id="status">Ready.</section>
    </main>
    <script>
      window.EVENT_ID = ${JSON.stringify(eventId)};
    </script>
    <script src="/static/app.js"></script>
  </body>
  </html>`;
}

function renderLoginPage(eventId, eventName, errorMessage) {
  return renderPage('Event Login', `
    <section class="hero">
      <h1>${escapeHtml(eventName)}</h1>
      <p class="muted">Enter the event login to continue.</p>
    </section>
    <section class="panel">
      ${errorMessage ? `<p class="muted">${escapeHtml(errorMessage)}</p>` : ''}
      <form method="POST" action="/login" class="row">
        <input type="hidden" name="eventId" value="${escapeHtml(eventId)}" />
        <input type="text" name="username" placeholder="Username" autocomplete="username" required />
        <input type="password" name="password" placeholder="Password" autocomplete="current-password" required />
        <button type="submit">Continue</button>
      </form>
    </section>
  `);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

initDb()
  .then(() => {
    ensureDir(PHOTOS_DIR);
    ensureDir(CONFIG_DIR);

    if (SSL_CERT_PATH && SSL_KEY_PATH) {
      const cert = fs.readFileSync(SSL_CERT_PATH);
      const key = fs.readFileSync(SSL_KEY_PATH);
      https.createServer({ key, cert }, app).listen(PORT, () => {
        console.log(`EventCam HTTPS listening on ${PORT}`);
      });
      return;
    }

    app.listen(PORT, () => {
      console.log(`EventCam listening on ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to start EventCam:', err);
    process.exit(1);
  });
