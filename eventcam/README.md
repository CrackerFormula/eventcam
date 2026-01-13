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

## Release checklist (Docker Hub)

1) Build the image:
```
docker build -t crackerformula/eventcam:ai .
```
2) Log in to Docker Hub:
```
docker login
```
3) Push the image:
```
docker push crackerformula/eventcam:ai
```
4) Update Unraid template `Repository` to match the tag if it changes.

## First run checklist (Unraid)

1) Deploy Postgres with `unraid-template-eventcam-postgres.xml` (br0 recommended).
2) Note the Postgres container IP on br0.
3) Deploy EventCam with `unraid-template-eventcam.xml`.
4) Set `DB_HOST` to the Postgres IP, `BASE_URL` to your public/lan URL, and map `/photos` to your share.
5) Open `http://<host>:5000/admin`, create an event, and print/share the QR code.
