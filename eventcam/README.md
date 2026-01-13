# EventCam (minimal)

Self-hosted event camera app with QR join and uploads to a shared album folder.

## Local run

1. Install deps: `npm install`
2. Start: `npm start`
3. Visit `http://localhost:5000/admin`

## Environment variables

- `PORT` (default 5000)
- `BASE_URL` (optional, used for QR codes)
- `DEFAULT_EVENT_NAME`
- `ALLOW_GUEST_UPLOADS` (true/false)
- `PHOTOS_DIR` (default /photos)
- `CONFIG_DIR` (default /config)
- Postgres:
  - `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_SSLMODE`

## Docker

Build: `docker build -t yourrepo/eventcam:latest .`
Run:
```
docker run -p 5000:5000 \
  -v /path/to/config:/config \
  -v /path/to/photos:/photos \
  -e BASE_URL="http://your-host:5000" \
  -e DB_HOST="postgres-host" \
  -e DB_USER="eventcam" \
  -e DB_PASSWORD="password" \
  yourrepo/eventcam:latest
```
