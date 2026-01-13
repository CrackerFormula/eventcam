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

const PORT = Number(process.env.PORT || 5001);
const BASE_URL_ENV = process.env.BASE_URL || '';
const DEFAULT_EVENT_NAME = process.env.DEFAULT_EVENT_NAME || 'My Event';
const ALLOW_GUEST_UPLOADS = (process.env.ALLOW_GUEST_UPLOADS || 'true').toLowerCase() === 'true';
const PHOTOS_DIR = process.env.PHOTOS_DIR || '/photos';
const CONFIG_DIR = process.env.CONFIG_DIR || '/config';
const SSL_CERT_PATH = process.env.SSL_CERT_PATH || '';
const SSL_KEY_PATH = process.env.SSL_KEY_PATH || '';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const INFERRED_GRACE_HOURS = Number(process.env.INFERRED_GRACE_HOURS || 168);

const DB_HOST = process.env.DB_HOST || '';
const DB_PORT = Number(process.env.DB_PORT || 5432);
const DB_NAME = process.env.DB_NAME || 'eventcam';
const DB_USER = process.env.DB_USER || 'eventcam';
const DB_PASSWORD = process.env.DB_PASSWORD || '';
const DB_SSLMODE = process.env.DB_SSLMODE || 'disable';

const EVENTS_FILE = path.join(CONFIG_DIR, 'events.json');
const ADMIN_FILE = path.join(CONFIG_DIR, 'admin.json');
const AUTH_SECRET_FILE = path.join(CONFIG_DIR, 'auth-secret');
const UPLOADS_FILE = path.join(CONFIG_DIR, 'uploads.json');
const RATE_LIMIT_FILE = path.join(CONFIG_DIR, 'rate-limits.json');

const pendingEventCredentials = new Map();
const qrCache = new Map();
const QR_CACHE_TTL_MS = 30 * 60 * 1000;
const statsCache = new Map();
let uploadsCache = null;
let uploadsDirty = false;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/static', express.static(path.join(__dirname, 'public')));
app.get('/styles.css', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'styles.css'));
});
app.get('/app.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.js'));
});

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

function appendSetCookie(res, value) {
  const current = res.getHeader('Set-Cookie');
  if (!current) {
    res.setHeader('Set-Cookie', value);
    return;
  }
  if (Array.isArray(current)) {
    res.setHeader('Set-Cookie', current.concat(value));
    return;
  }
  res.setHeader('Set-Cookie', [current, value]);
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
  const expected = Buffer.from(signToken(body), 'hex');
  const actual = Buffer.from(signature, 'hex');
  if (expected.length !== actual.length) return null;
  if (!crypto.timingSafeEqual(expected, actual)) return null;
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
  appendSetCookie(res, attributes.join('; '));
}

function clearAuthCookie(req, res) {
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const attributes = [
    'eventcam_auth=',
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0'
  ];
  if (secure) {
    attributes.push('Secure');
  }
  appendSetCookie(res, attributes.join('; '));
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

const DEVICE_ALIASES = [
  'Disco Llama',
  'Cosmic Otter',
  'Sassy Cactus',
  'Pixel Penguin',
  'Neon Narwhal',
  'Waffle Wizard',
  'Robo Raccoon',
  'Turbo Turtle',
  'Laser Lemur',
  'Snazzy Sloth',
  'Banana Bandit',
  'Sparkle Badger',
  'Moonlit Moose',
  'Funky Fox',
  'Jelly Jaguar'
];

function generateDeviceAlias() {
  return DEVICE_ALIASES[Math.floor(Math.random() * DEVICE_ALIASES.length)];
}

function setDeviceCookie(req, res, id, alias) {
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const baseAttributes = [
    'Path=/',
    'SameSite=Lax',
    `Max-Age=${60 * 60 * 24 * 365}`
  ];
  if (secure) {
    baseAttributes.push('Secure');
  }
  appendSetCookie(res, [`eventcam_device=${encodeURIComponent(id)}`].concat(baseAttributes).join('; '));
  appendSetCookie(res, [`eventcam_alias=${encodeURIComponent(alias)}`].concat(baseAttributes).join('; '));
}

function ensureDeviceCookie(req, res) {
  const cookies = parseCookies(req);
  let deviceId = cookies.eventcam_device;
  let deviceAlias = cookies.eventcam_alias;
  let changed = false;
  if (!deviceId) {
    deviceId = crypto.randomBytes(10).toString('hex');
    changed = true;
  }
  if (!deviceAlias) {
    deviceAlias = generateDeviceAlias();
    changed = true;
  }
  if (changed) {
    setDeviceCookie(req, res, deviceId, deviceAlias);
  }
  return { id: deviceId, alias: deviceAlias };
}

function rememberEventPassword(eventId, password) {
  pendingEventCredentials.set(eventId, password);
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

function verifyEventPassword(password, event) {
  if (!event.event_password_hash || !event.event_password_salt || !event.event_password_iterations) {
    return false;
  }
  const test = crypto.pbkdf2Sync(
    password,
    event.event_password_salt,
    event.event_password_iterations,
    64,
    'sha256'
  ).toString('hex');
  const expected = Buffer.from(event.event_password_hash, 'hex');
  const actual = Buffer.from(test, 'hex');
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(expected, actual);
}

function loadUploadsLocal() {
  try {
    const raw = fs.readFileSync(UPLOADS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    return { events: {} };
  }
}

function saveUploadsLocal(data) {
  uploadsCache = data;
  uploadsDirty = true;
}

function getUploadsStore() {
  if (!uploadsCache) {
    uploadsCache = loadUploadsLocal();
  }
  return uploadsCache;
}

function flushUploadsLocal(forceSync = false) {
  if (!uploadsDirty || !uploadsCache) return;
  ensureDir(CONFIG_DIR);
  const payload = JSON.stringify(uploadsCache, null, 2);
  uploadsDirty = false;
  if (forceSync) {
    fs.writeFileSync(UPLOADS_FILE, payload, 'utf8');
    return;
  }
  fs.writeFile(UPLOADS_FILE, payload, 'utf8', (err) => {
    if (err) {
      uploadsDirty = true;
    }
  });
}

function recordUploadLocal(eventId, device) {
  const uploads = getUploadsStore();
  if (!uploads.events) uploads.events = {};
  if (!uploads.events[eventId]) {
    uploads.events[eventId] = { devices: {} };
  }
  uploads.events[eventId].devices[device.id] = {
    alias: device.alias,
    lastSeen: new Date().toISOString()
  };
  saveUploadsLocal(uploads);
}

function loadRateLimitsLocal() {
  try {
    const raw = fs.readFileSync(RATE_LIMIT_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    return { startEvents: {} };
  }
}

function saveRateLimitsLocal(data) {
  ensureDir(CONFIG_DIR);
  fs.writeFileSync(RATE_LIMIT_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function recordStartEvent(key) {
  const data = loadRateLimitsLocal();
  if (!data.startEvents) data.startEvents = {};
  if (!data.startEvents[key]) data.startEvents[key] = [];
  data.startEvents[key].push(Date.now());
  data.startEvents[key] = data.startEvents[key].slice(-10);
  saveRateLimitsLocal(data);
}

function isStartEventLimited(key) {
  const data = loadRateLimitsLocal();
  const now = Date.now();
  const windowMs = 24 * 60 * 60 * 1000;
  const entries = (data.startEvents && data.startEvents[key]) || [];
  const recent = entries.filter((ts) => now - ts < windowMs);
  if (recent.length !== entries.length) {
    data.startEvents[key] = recent;
    saveRateLimitsLocal(data);
  }
  return recent.length >= 5;
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length) {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.connection?.remoteAddress || 'unknown';
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

function getEventFileStatsCached(eventId) {
  const eventPath = path.join(PHOTOS_DIR, eventId);
  let dirMtime = null;
  try {
    dirMtime = fs.statSync(eventPath).mtimeMs;
  } catch (err) {
    dirMtime = null;
  }

  const cached = statsCache.get(eventId);
  if (cached && cached.mtime === dirMtime) {
    return cached.stats;
  }

  const files = listPhotosForEvent(eventId);
  let bytes = 0;
  files.forEach((file) => {
    try {
      const stat = fs.statSync(path.join(eventPath, file));
      bytes += stat.size;
    } catch (err) {
      // Ignore missing files.
    }
  });
  const stats = { photos: files.length, bytes };
  statsCache.set(eventId, { mtime: dirMtime, stats });
  return stats;
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
  await pool.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS event_password_hash TEXT;`);
  await pool.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS event_password_salt TEXT;`);
  await pool.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS event_password_iterations INTEGER;`);
  await pool.query(`ALTER TABLE events ADD COLUMN IF NOT EXISTS event_password TEXT;`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS photos (
      id SERIAL PRIMARY KEY,
      event_id TEXT REFERENCES events(id),
      path TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`ALTER TABLE photos ADD COLUMN IF NOT EXISTS size_bytes BIGINT;`);
  await pool.query(`ALTER TABLE photos ADD COLUMN IF NOT EXISTS device_id TEXT;`);
  await pool.query(`ALTER TABLE photos ADD COLUMN IF NOT EXISTS device_alias TEXT;`);

  const missing = await pool.query(`
    SELECT id, event_user, event_password, event_password_hash
    FROM events
    WHERE event_user IS NULL OR event_password_hash IS NULL
  `);
  for (const row of missing.rows) {
    const existingPassword = row.event_password;
    const creds = existingPassword
      ? { username: row.event_user || `guest-${crypto.randomBytes(3).toString('hex')}`, password: existingPassword }
      : generateEventCredentials();
    const hashed = hashPassword(creds.password);
    await pool.query(
      `UPDATE events
       SET event_user = $1,
           event_password_hash = $2,
           event_password_salt = $3,
           event_password_iterations = $4,
           event_password = NULL
       WHERE id = $5`,
      [creds.username, hashed.hash, hashed.salt, hashed.iterations, row.id]
    );
    if (!existingPassword) {
      rememberEventPassword(row.id, creds.password);
    }
  }
}

function loadEventsLocal() {
  try {
    const raw = fs.readFileSync(EVENTS_FILE, 'utf8');
    const events = JSON.parse(raw);
    let updated = false;
    events.forEach((evt) => {
      if (!evt.created_at) {
        evt.created_at = new Date().toISOString();
        evt.created_at_inferred = true;
        updated = true;
      }
      if (!evt.event_user) {
        evt.event_user = `guest-${crypto.randomBytes(3).toString('hex')}`;
        updated = true;
      }
      if (evt.event_password) {
        const hashed = hashPassword(evt.event_password);
        evt.event_password_hash = hashed.hash;
        evt.event_password_salt = hashed.salt;
        evt.event_password_iterations = hashed.iterations;
        delete evt.event_password;
        updated = true;
      }
      if (!evt.event_password_hash) {
        const creds = generateEventCredentials();
        const hashed = hashPassword(creds.password);
        evt.event_user = evt.event_user || creds.username;
        evt.event_password_hash = hashed.hash;
        evt.event_password_salt = hashed.salt;
        evt.event_password_iterations = hashed.iterations;
        rememberEventPassword(evt.id, creds.password);
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

function ensureCreatedAt(value) {
  return value || new Date().toISOString();
}

async function listEvents() {
  if (pool) {
    const result = await pool.query(`
      SELECT id, name, event_user, event_password_hash, event_password_salt, event_password_iterations
      FROM events
      ORDER BY created_at DESC
    `);
    return result.rows;
  }
  return loadEventsLocal();
}

async function createEvent(name) {
  const id = safeId();
  const creds = generateEventCredentials();
  const hashed = hashPassword(creds.password);
  if (pool) {
    await pool.query(
      `INSERT INTO events (id, name, event_user, event_password_hash, event_password_salt, event_password_iterations)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [id, name, creds.username, hashed.hash, hashed.salt, hashed.iterations]
    );
  } else {
    const events = loadEventsLocal();
    events.unshift({
      id,
      name,
      created_at: new Date().toISOString(),
      event_user: creds.username,
      event_password_hash: hashed.hash,
      event_password_salt: hashed.salt,
      event_password_iterations: hashed.iterations
    });
    saveEventsLocal(events);
  }
  rememberEventPassword(id, creds.password);
  return { id, name, event_user: creds.username, event_password: creds.password };
}

async function eventExists(eventId) {
  const event = await getEvent(eventId);
  return Boolean(event);
}

async function getEvent(eventId) {
  if (pool) {
    const result = await pool.query(
      `SELECT id, name, event_user, event_password_hash, event_password_salt, event_password_iterations
       FROM events
       WHERE id = $1`,
      [eventId]
    );
    return result.rows[0] || null;
  }
  const events = loadEventsLocal();
  return events.find((evt) => evt.id === eventId) || null;
}

async function deleteEventById(eventId) {
  if (pool) {
    await pool.query('DELETE FROM photos WHERE event_id = $1', [eventId]);
    await pool.query('DELETE FROM events WHERE id = $1', [eventId]);
  } else {
    const events = loadEventsLocal();
    const next = events.filter((evt) => evt.id !== eventId);
    saveEventsLocal(next);
    const uploads = getUploadsStore();
    if (uploads.events && uploads.events[eventId]) {
      delete uploads.events[eventId];
      saveUploadsLocal(uploads);
      flushUploadsLocal(true);
    }
  }

  pendingEventCredentials.delete(eventId);
  const eventPath = path.join(PHOTOS_DIR, eventId);
  try {
    fs.rmSync(eventPath, { recursive: true, force: true });
  } catch (err) {
    // Ignore delete errors.
  }
}

async function cleanupStaleEvents() {
  const cutoff = Date.now() - 72 * 60 * 60 * 1000;
  if (pool) {
    const result = await pool.query(`
      SELECT e.id
      FROM events e
      LEFT JOIN photos p ON p.event_id = e.id
      WHERE p.id IS NULL
        AND e.created_at < NOW() - INTERVAL '72 hours'
    `);
    for (const row of result.rows) {
      await deleteEventById(row.id);
    }
    return;
  }

  const events = loadEventsLocal().map((evt) => ({
    ...evt,
    created_at: ensureCreatedAt(evt.created_at)
  }));
  const deletions = [];
  events.forEach((evt) => {
    const createdAt = Date.parse(evt.created_at || '');
    if (evt.created_at_inferred) {
      const graceCutoff = Date.now() - INFERRED_GRACE_HOURS * 60 * 60 * 1000;
      if (!createdAt || createdAt > graceCutoff) {
        return;
      }
    }
    if (!createdAt || createdAt > cutoff) return;
    const photos = listPhotosForEvent(evt.id);
    if (!photos.length) {
      deletions.push(evt.id);
    }
  });
  for (const eventId of deletions) {
    await deleteEventById(eventId);
  }
}

async function recordPhoto(eventId, filePath, meta = {}) {
  if (!pool) return;
  await pool.query(
    'INSERT INTO photos (event_id, path, size_bytes, device_id, device_alias) VALUES ($1, $2, $3, $4, $5)',
    [eventId, filePath, meta.sizeBytes || 0, meta.deviceId || null, meta.deviceAlias || null]
  );
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const eventId = (req.event && req.event.id) || req.body.eventId || req.query.event;
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

function getEventFileStats(eventId) {
  return getEventFileStatsCached(eventId);
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

async function getStatsForEvents(events) {
  if (pool) {
    const perEventRows = await pool.query(`
      SELECT event_id,
             COUNT(*)::int AS photos,
             COALESCE(SUM(size_bytes), 0)::bigint AS bytes,
             COUNT(DISTINCT device_id)::int AS devices
      FROM photos
      GROUP BY event_id
    `);
    const perEvent = {};
    perEventRows.rows.forEach((row) => {
      perEvent[row.event_id] = {
        photos: Number(row.photos),
        bytes: Number(row.bytes),
        devices: Number(row.devices)
      };
    });
    const totalRow = await pool.query(`
      SELECT COUNT(*)::int AS photos,
             COALESCE(SUM(size_bytes), 0)::bigint AS bytes,
             COUNT(DISTINCT device_id)::int AS devices
      FROM photos
    `);
    const totals = totalRow.rows[0] || { photos: 0, bytes: 0, devices: 0 };
    return { totals, perEvent };
  }

  const uploads = getUploadsStore();
  const perEvent = {};
  let totalPhotos = 0;
  let totalBytes = 0;
  const totalDevices = new Set();

  events.forEach((evt) => {
    const stats = getEventFileStatsCached(evt.id);
    totalPhotos += stats.photos;
    totalBytes += stats.bytes;
    const deviceMap = uploads.events?.[evt.id]?.devices || {};
    Object.keys(deviceMap).forEach((id) => totalDevices.add(id));
    perEvent[evt.id] = {
      photos: stats.photos,
      bytes: stats.bytes,
      devices: Object.keys(deviceMap).length
    };
  });

  return { totals: { photos: totalPhotos, bytes: totalBytes, devices: totalDevices.size }, perEvent };
}

async function getDeviceListForEvent(eventId) {
  if (pool) {
    const result = await pool.query(
      `SELECT DISTINCT device_alias
       FROM photos
       WHERE event_id = $1 AND device_alias IS NOT NULL AND device_alias <> ''
       ORDER BY device_alias`,
      [eventId]
    );
    return result.rows.map((row) => row.device_alias);
  }

  const uploads = getUploadsStore();
  const deviceMap = uploads.events?.[eventId]?.devices || {};
  return Object.values(deviceMap)
    .map((entry) => entry.alias)
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b));
}

async function getQrDataUrl(url) {
  const now = Date.now();
  const cached = qrCache.get(url);
  if (cached && cached.expiresAt > now) {
    return cached.value;
  }
  const value = await qrcode.toDataURL(url, { margin: 1, width: 240 });
  qrCache.set(url, { value, expiresAt: now + QR_CACHE_TTL_MS });
  if (qrCache.size > 500) {
    const [firstKey] = qrCache.keys();
    if (firstKey) qrCache.delete(firstKey);
  }
  return value;
}

async function loadEventFromRequest(req, res, next, options = {}) {
  const wantsJson = options.json;
  const eventId = req.query.event || req.body.eventId || req.body.event;
  if (!eventId) {
    if (wantsJson) {
      res.status(400).json({ ok: false, error: 'Missing event id' });
    } else {
      res.status(400).send('Missing event id.');
    }
    return;
  }
  const event = await getEvent(eventId);
  if (!event) {
    if (wantsJson) {
      res.status(404).json({ ok: false, error: 'Event not found' });
    } else {
      res.status(404).send('Event not found.');
    }
    return;
  }
  req.event = event;
  next();
}


app.get('/', async (req, res) => {
  const eventId = req.query.event;
  if (!eventId) {
    res.send(renderLandingPage());
    return;
  }

  const event = await getEvent(eventId);
  if (!event) {
    res.status(404).send(renderPage('Event Not Found', `<p class="muted">Event not found.</p>`));
    return;
  }

  const device = ensureDeviceCookie(req, res);
  res.send(renderCapturePage(eventId, device.alias));
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

  const device = ensureDeviceCookie(req, res);
  const stats = (await getStatsForEvents([event])).perEvent[eventId] || { photos: 0, bytes: 0, devices: 0 };
  const deviceList = await getDeviceListForEvent(eventId);
  const baseUrl = baseUrlFromRequest(req);
  const eventUrl = `${baseUrl}/?event=${event.id}`;
  const qr = await getQrDataUrl(eventUrl);
  const pendingPassword = pendingEventCredentials.get(eventId);
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
      <p class="muted">Photos: ${stats.photos} · Devices: ${stats.devices} · Storage: ${formatBytes(stats.bytes)}</p>
      <p class="muted">Your device alias: ${escapeHtml(device.alias)}</p>
      <details class="device-list">
        <summary>View device aliases (${deviceList.length})</summary>
        ${deviceList.length ? `
        <ul>
          ${deviceList.map((alias) => `<li>${escapeHtml(alias)}</li>`).join('')}
        </ul>
        ` : '<p class="muted">No uploads yet.</p>'}
      </details>
    </section>
    <section class="panel">
      <h3>Share this event</h3>
      <img src="${qr}" alt="QR code for ${escapeHtml(event.name)}" />
      <p class="muted"><a href="${eventUrl}">${eventUrl}</a></p>
    </section>
    ${pendingPassword ? `
    <section class="panel alert-panel">
      <h3>Event Login</h3>
      <p class="muted">Username: ${escapeHtml(event.event_user)}</p>
      <p class="muted">Password: ${escapeHtml(pendingPassword)}</p>
      <p class="alert-text">Copy this now; it will not be shown again.</p>
    </section>
    ` : ''}
    <section class="panel">
      <div class="row">
        <a href="/event/download?event=${encodeURIComponent(eventId)}">
          <button type="button">Download all photos</button>
        </a>
        <a href="/?event=${encodeURIComponent(eventId)}">
          <button type="button">Back to camera</button>
        </a>
        <a href="/logout?event=${encodeURIComponent(eventId)}">
          <button type="button">Log out</button>
        </a>
        <form method="POST" action="/event/delete" onsubmit="return confirm('Delete this event and all photos?');">
          <input type="hidden" name="event" value="${escapeHtml(eventId)}" />
          <button type="submit">Delete event</button>
        </form>
      </div>
    </section>
    <section class="gallery">
      ${gallery || '<p class="muted">No photos yet.</p>'}
    </section>
  `;

  res.send(renderPage('Event Dashboard', content));
  if (pendingPassword) {
    pendingEventCredentials.delete(eventId);
  }
});

app.get('/start', async (req, res) => {
  const device = ensureDeviceCookie(req, res);
  const ipKey = `ip:${getClientIp(req)}`;
  const deviceKey = `device:${device.id}`;
  if (isStartEventLimited(ipKey) || isStartEventLimited(deviceKey)) {
    res.redirect('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
    return;
  }
  recordStartEvent(ipKey);
  recordStartEvent(deviceKey);

  const event = await createEvent(DEFAULT_EVENT_NAME);
  const payload = {
    eventId: event.id,
    user: event.event_user,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 7
  };
  setAuthCookie(req, res, encodeAuthToken(payload));
  res.redirect(`/event/dashboard?event=${encodeURIComponent(event.id)}`);
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

app.post('/event/delete', async (req, res) => {
  const eventId = req.body.event || req.query.event;
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

  await deleteEventById(eventId);

  clearAuthCookie(req, res);
  res.redirect('/');
});

app.get('/admin', requireAdmin, async (req, res) => {
  const events = await listEvents();
  const baseUrl = baseUrlFromRequest(req);
  const stats = await getStatsForEvents(events);
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
    const qr = await getQrDataUrl(url);
    const galleryUrl = `/admin/photos?event=${evt.id}`;
    const eventStats = stats.perEvent[evt.id] || { photos: 0, bytes: 0, devices: 0 };
    return `
      <div class="card">
        <h3>${escapeHtml(evt.name)}</h3>
        <p class="muted">Event ID: ${evt.id}</p>
        <p class="muted">Login user: ${escapeHtml(evt.event_user || '')}</p>
        <p class="muted">Photos: ${eventStats.photos} · Devices: ${eventStats.devices} · Storage: ${formatBytes(eventStats.bytes)}</p>
        <img src="${qr}" alt="QR code for ${escapeHtml(evt.name)}" />
        <p><a href="${url}">${url}</a></p>
        <p><a href="${galleryUrl}">View photos</a></p>
        <form method="POST" action="/admin/regenerate">
          <input type="hidden" name="eventId" value="${escapeHtml(evt.id)}" />
          <button type="submit">Regenerate login</button>
        </form>
        <form method="POST" action="/admin/delete" onsubmit="return confirm('Delete this event and all photos?');">
          <input type="hidden" name="eventId" value="${escapeHtml(evt.id)}" />
          <button type="submit">Delete event</button>
        </form>
      </div>
    `;
  }));

  const pendingList = Array.from(pendingEventCredentials.entries()).map(([eventId, password]) => {
    const eventName = events.find((evt) => evt.id === eventId)?.name || eventId;
    const eventUser = events.find((evt) => evt.id === eventId)?.event_user || '';
    return `
      <div class="card">
        <h3>${escapeHtml(eventName)}</h3>
        <p class="muted">Event ID: ${escapeHtml(eventId)}</p>
        <p class="muted">Login: ${escapeHtml(eventUser)} / ${escapeHtml(password)}</p>
        <p class="muted">Copy this now; it will not be shown again after you refresh.</p>
      </div>
    `;
  });

  const content = `
    <section class="hero">
      <h1>EventCam Admin</h1>
      <p>Create an event and share its QR code with guests.</p>
    </section>
    <section class="panel">
      <p class="muted">All events: ${stats.totals.photos} photos · ${stats.totals.devices} devices · ${formatBytes(stats.totals.bytes)} stored</p>
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
      <div class="row">
        <a href="/admin/logout">
          <button type="button">Log out</button>
        </a>
      </div>
    </section>
    ${pendingList.length ? `
    <section class="panel">
      <h3>New Event Credentials</h3>
      <div class="grid">
        ${pendingList.join('')}
      </div>
    </section>
    ` : ''}
    <section class="grid">
      ${cards.join('') || '<p class="muted">No events yet.</p>'}
    </section>
  `;

  res.send(renderPage('EventCam Admin', content));
  pendingEventCredentials.clear();
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

app.post('/admin/delete', requireAdmin, async (req, res) => {
  const eventId = String(req.body.eventId || '');
  if (!eventId) {
    res.redirect('/admin');
    return;
  }
  await deleteEventById(eventId);
  res.redirect('/admin');
});

app.get('/admin/logout', (req, res) => {
  res.set('WWW-Authenticate', 'Basic realm="EventCam Admin"');
  res.status(401).send('Logged out.');
});

app.post('/admin/regenerate', requireAdmin, async (req, res) => {
  const eventId = String(req.body.eventId || '');
  if (!eventId) {
    res.redirect('/admin');
    return;
  }
  const event = await getEvent(eventId);
  if (!event) {
    res.redirect('/admin');
    return;
  }
  const creds = generateEventCredentials();
  const hashed = hashPassword(creds.password);
  if (pool) {
    await pool.query(
      `UPDATE events
       SET event_user = $1,
           event_password_hash = $2,
           event_password_salt = $3,
           event_password_iterations = $4
       WHERE id = $5`,
      [creds.username, hashed.hash, hashed.salt, hashed.iterations, eventId]
    );
  } else {
    const events = loadEventsLocal();
    const next = events.map((evt) => {
      if (evt.id !== eventId) return evt;
      return {
        ...evt,
        event_user: creds.username,
        event_password_hash: hashed.hash,
        event_password_salt: hashed.salt,
        event_password_iterations: hashed.iterations
      };
    });
    saveEventsLocal(next);
  }
  rememberEventPassword(eventId, creds.password);
  res.redirect('/admin');
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
  ensureDeviceCookie(req, res);
  res.send(renderLoginPage(eventId, event.name, error));
});

app.get('/logout', (req, res) => {
  clearAuthCookie(req, res);
  res.redirect('/');
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
  if (username !== event.event_user || !verifyEventPassword(password, event)) {
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

app.post('/upload', (req, res, next) => loadEventFromRequest(req, res, next, { json: true }), (req, res, next) => {
  if (!ALLOW_GUEST_UPLOADS && !isAuthorizedForEvent(req, req.event)) {
    res.status(401).json({ ok: false, error: 'Authentication required' });
    return;
  }
  next();
}, upload.single('photo'), async (req, res) => {
  if (!req.file) {
    res.status(400).json({ ok: false, error: 'No file uploaded' });
    return;
  }

  const device = ensureDeviceCookie(req, res);
  await recordPhoto(req.event.id, req.file.path, {
    sizeBytes: req.file.size || 0,
    deviceId: device.id,
    deviceAlias: device.alias
  });
  if (!pool) {
    recordUploadLocal(req.event.id, device);
  }

  res.json({ ok: true, path: req.file.path });
});

function renderPage(title, body, bodyClass = '') {
  const classAttr = bodyClass ? ` class="${bodyClass}"` : '';
  return `<!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body${classAttr}>
    <main>
      ${body}
    </main>
  </body>
  </html>`;
}

function renderCapturePage(eventId, deviceAlias) {
  return `<!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>EventCam</title>
    <link rel="stylesheet" href="/styles.css" />
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
        <a href="/logout?event=${encodeURIComponent(eventId)}">
          <button type="button">Log out</button>
        </a>
      </section>
      <section class="status" id="status">Ready.</section>
      <section class="muted">Device alias: ${escapeHtml(deviceAlias || '')}</section>
    </main>
    <script>
      window.EVENT_ID = ${JSON.stringify(eventId)};
    </script>
    <script src="/app.js"></script>
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

function renderLandingPage() {
  const content = `
    <section class="landing-hero">
      <div class="landing-orbs">
        <span class="orb orb-one"></span>
        <span class="orb orb-two"></span>
        <span class="orb orb-three"></span>
      </div>
      <div class="landing-content">
        <p class="eyebrow">EventCam</p>
        <h1>Turn every guest into a photographer.</h1>
        <p class="lead">
          QR-powered event capture, instant uploads, and private dashboards for every event.
          No apps. No accounts. Just cameras and memories.
        </p>
        <div class="cta-row">
          <a href="/start" class="cta primary">Open dashboard</a>
          <a href="#features" class="cta ghost">See how it works</a>
        </div>
        <div class="stats">
          <div>
            <p class="stat-value">1 tap</p>
            <p class="stat-label">Join via QR</p>
          </div>
          <div>
            <p class="stat-value">Private</p>
            <p class="stat-label">Event dashboards</p>
          </div>
          <div>
            <p class="stat-value">Live</p>
            <p class="stat-label">Photo flow</p>
          </div>
        </div>
      </div>
      <div class="landing-cards">
        <div class="frame-card">
          <div class="frame-header">
            <span class="dot"></span><span class="dot"></span><span class="dot"></span>
          </div>
          <div class="frame-body">
            <div class="camera-mock">
              <div class="lens"></div>
              <p>Guest camera ready</p>
            </div>
            <div class="upload-strip">
              <span>Uploading...</span>
              <span class="pulse"></span>
            </div>
          </div>
        </div>
        <div class="frame-card mini">
          <h3>Event dashboard</h3>
          <p>Download all photos, track devices, and stay private.</p>
          <div class="sparkline">
            <span></span><span></span><span></span><span></span><span></span>
          </div>
        </div>
      </div>
    </section>

    <section id="features" class="landing-grid">
      <div class="feature-card">
        <h3>QR-first onboarding</h3>
        <p>Guests scan once and the camera opens instantly. Keep the line moving.</p>
      </div>
      <div class="feature-card">
        <h3>Private event control</h3>
        <p>Event login protects dashboards, downloads, and deletion controls.</p>
      </div>
      <div class="feature-card">
        <h3>Stats that matter</h3>
        <p>See total uploads, storage used, and unique device activity.</p>
      </div>
      <div class="feature-card">
        <h3>Self-hosted</h3>
        <p><a href="https://github.com/CrackerFormula/eventcam" target="_blank" rel="noopener">Run on your own hardware with Docker, Unraid, or a VPS.</a></p>
      </div>
    </section>

    <section class="landing-footer">
      <h2>Ready for your next event?</h2>
      <p>Spin up EventCam and share your first QR in minutes.</p>
      <a href="/start" class="cta primary">Open dashboard</a>
      <p class="admin-link">
        <a href="/admin">Admin login</a>
      </p>
    </section>
  `;

  return renderPage('EventCam', content, 'landing-body');
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
    cleanupStaleEvents().catch((err) => console.error('Cleanup failed:', err));
    setInterval(() => {
      cleanupStaleEvents().catch((err) => console.error('Cleanup failed:', err));
    }, 60 * 60 * 1000);
    setInterval(() => {
      flushUploadsLocal();
    }, 5000);

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
