const express = require('express');
const https = require('https');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const qrcode = require('qrcode');
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

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/static', express.static(path.join(__dirname, 'public')));

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function safeId() {
  return crypto.randomBytes(4).toString('hex');
}

function baseUrlFromRequest(req) {
  if (BASE_URL_ENV) return BASE_URL_ENV;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.get('host')}`;
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="EventCam Admin"');
    res.status(401).send('Authentication required.');
    return;
  }
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const [user, pass] = decoded.split(':');
  if (user !== ADMIN_USER || pass !== ADMIN_PASSWORD) {
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS photos (
      id SERIAL PRIMARY KEY,
      event_id TEXT REFERENCES events(id),
      path TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

function loadEventsLocal() {
  try {
    const raw = fs.readFileSync(EVENTS_FILE, 'utf8');
    return JSON.parse(raw);
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
    const result = await pool.query('SELECT id, name FROM events ORDER BY created_at DESC');
    return result.rows;
  }
  return loadEventsLocal();
}

async function createEvent(name) {
  const id = safeId();
  if (pool) {
    await pool.query('INSERT INTO events (id, name) VALUES ($1, $2)', [id, name]);
  } else {
    const events = loadEventsLocal();
    events.unshift({ id, name });
    saveEventsLocal(events);
  }
  return { id, name };
}

async function eventExists(eventId) {
  if (pool) {
    const result = await pool.query('SELECT id FROM events WHERE id = $1', [eventId]);
    return result.rowCount > 0;
  }
  const events = loadEventsLocal();
  return events.some((evt) => evt.id === eventId);
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

app.get('/', async (req, res) => {
  const eventId = req.query.event;
  if (!eventId) {
    res.redirect('/admin');
    return;
  }

  const exists = await eventExists(eventId);
  if (!exists) {
    res.status(404).send(renderPage('Event Not Found', `<p class="muted">Event not found.</p>`));
    return;
  }

  res.send(renderCapturePage(eventId));
});

app.get('/admin', requireAdmin, async (req, res) => {
  const events = await listEvents();
  const baseUrl = baseUrlFromRequest(req);

  const cards = await Promise.all(events.map(async (evt) => {
    const url = `${baseUrl}/?event=${evt.id}`;
    const qr = await qrcode.toDataURL(url, { margin: 1, width: 240 });
    const galleryUrl = `/admin/photos?event=${evt.id}`;
    return `
      <div class="card">
        <h3>${escapeHtml(evt.name)}</h3>
        <p class="muted">Event ID: ${evt.id}</p>
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

  const exists = await eventExists(eventId);
  if (!exists) {
    res.status(404).json({ ok: false, error: 'Event not found' });
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
