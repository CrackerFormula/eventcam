# EventCam (minimal)

Self-hosted event camera app with QR join and uploads to a shared album folder.

## Local run

1. Install deps: `npm install`
2. Start: `npm start`
3. Visit `http://localhost:5001/admin`
4. Each event gets a unique login; new credentials show once in the admin view (use Regenerate login to rotate).

## Local HTTPS (phone camera support)

Self-signed certs require trust on the phone before the camera will work.

1) Generate a cert (replace `<LAN_IP>` with your Mac IP):
```
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/key.pem -out certs/cert.pem \
  -subj "/CN=eventcam.local" \
  -addext "subjectAltName=DNS:localhost,IP:<LAN_IP>"
```
2) Run with HTTPS:
```
SSL_CERT_PATH=certs/cert.pem SSL_KEY_PATH=certs/key.pem npm start
```
3) On your phone, open `https://<LAN_IP>:5001/admin` and trust the cert.

## Environment variables

- `PORT` (default 5001)
- `BASE_URL` (optional, used for QR codes)
- `DEFAULT_EVENT_NAME`
- `ALLOW_GUEST_UPLOADS` (true/false)
- `PHOTOS_DIR` (default /photos)
- `CONFIG_DIR` (default /config)
- `SSL_CERT_PATH` / `SSL_KEY_PATH` (enable HTTPS)
- `ADMIN_USER` / `ADMIN_PASSWORD` (protects `/admin` with Basic auth, defaults admin/admin)
- Postgres:
  - `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_SSLMODE`

## Docker

Build: `docker build -t yourrepo/eventcam:latest .`
Run:
```
docker run -p 5001:5001 \
  -v /path/to/config:/config \
  -v /path/to/photos:/photos \
  -e BASE_URL="http://your-host:5001" \
  -e DB_HOST="postgres-host" \
  -e DB_USER="eventcam" \
  -e DB_PASSWORD="password" \
  yourrepo/eventcam:latest
```

Optional HTTPS (mount certs into the container):
```
docker run -p 5001:5001 \
  -v /path/to/config:/config \
  -v /path/to/photos:/photos \
  -v /path/to/certs:/certs \
  -e SSL_CERT_PATH="/certs/cert.pem" \
  -e SSL_KEY_PATH="/certs/key.pem" \
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
5) Open `http://<host>:5001/admin`, create an event, and print/share the QR code.
