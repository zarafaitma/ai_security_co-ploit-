# HTTPS / SSL Setup (Phase 6, Part D)

`nginx.conf` ships with HTTPS fully written out but commented out, because
nginx will refuse to start if it's told to load certificate files that
don't exist yet. This doc is the missing piece: how to actually get those
certificates and turn HTTPS on.

This assumes you're running the `docker-compose.yml` stack from this
project, with a real domain name already pointed at your server's public
IP address (an A record). Let's Encrypt cannot issue a certificate for
`localhost` or a bare IP address — you need a domain.

## 1. Get a certificate with Certbot

The simplest approach for this stack: run Certbot's official Docker image
once, sharing the same `./certs` volume nginx already mounts.

```bash
# Make sure nginx is already running on port 80 (the plain HTTP block,
# which is what's active by default) -- Certbot's HTTP-01 challenge needs
# port 80 reachable from the internet for your domain.
docker compose up -d nginx

docker run -it --rm \
  -v "$(pwd)/certs:/etc/letsencrypt" \
  -v "$(pwd)/certbot-www:/var/www/certbot" \
  -p 80:80 \
  certbot/certbot certonly --standalone \
  -d your-domain.com \
  --email you@example.com \
  --agree-tos --no-eff-email
```

If nginx is already bound to port 80 from `docker compose up`, stop it
first (`docker compose stop nginx`) before running the standalone Certbot
command above, then start nginx again afterward — `--standalone` needs
port 80 free to answer the challenge itself. (The webroot method, using
the `/.well-known/acme-challenge/` location already wired into both the
HTTP and HTTPS server blocks in `nginx.conf`, avoids this stop/start dance
once you're past the very first certificate issuance — see step 4.)

This writes your certificate to:

```
./certs/live/your-domain.com/fullchain.pem
./certs/live/your-domain.com/privkey.pem
```

which are exactly the paths `nginx.conf`'s commented HTTPS block already
references (update `your-domain.com` in both places to match your real
domain).

## 2. Enable the HTTPS block

In `nginx.conf`:

1. Uncomment the entire `server { listen 443 ssl; ... }` block.
2. Uncomment the small HTTP `server { ... return 301 https://...; }`
   redirect block right after it.
3. Replace the *existing* plain `server { listen 80; ... }` block (the
   one active by default, near the top) with that redirect block instead
   — so port 80 now only serves the ACME challenge path and redirects
   everything else to HTTPS, rather than proxying directly.
4. Replace every `your-domain.com` placeholder with your real domain.

## 3. Restart nginx

```bash
docker compose restart nginx
```

Visit `https://your-domain.com` — you should get a valid certificate (no
browser warning) and be redirected automatically if you try plain HTTP.

## 4. Renewal

Let's Encrypt certificates expire every 90 days. Set up a cron job (or
systemd timer) on the host running Docker:

```bash
# crontab -e
0 3 * * * cd /path/to/project && docker run --rm \
  -v "$(pwd)/certs:/etc/letsencrypt" \
  -v "$(pwd)/certbot-www:/var/www/certbot" \
  certbot/certbot renew --webroot -w /var/www/certbot --quiet \
  && docker compose restart nginx
```

This uses the webroot method (via the `/.well-known/acme-challenge/`
location already in both server blocks) instead of `--standalone`, so it
doesn't need to stop nginx to renew — it just writes the challenge file
where nginx is already configured to serve it from.

## What's already hardened once HTTPS is on

These are all already written into the HTTPS server block in
`nginx.conf` — nothing further to configure once you've completed the
steps above:

- **HSTS** (`Strict-Transport-Security`) — tells browsers to never even
  try plain HTTP for this domain again, for up to 2 years.
- **Modern TLS only** — TLS 1.2 and 1.3, with a conservative cipher list
  (Mozilla's "Intermediate" profile).
- **OCSP stapling** — faster certificate validation for visitors.
- **Security headers** — `X-Frame-Options`, `X-Content-Type-Options`,
  `X-XSS-Protection`, `Referrer-Policy`, a baseline `Content-Security-Policy`.
- **Cookie hardening** — `proxy_cookie_flags` forces `Secure`/`HttpOnly`/
  `SameSite=Strict` on any cookie passing through, at the proxy layer.
  Worth noting honestly: this app's API authentication (Phase 5) is
  Bearer-token based, not cookie based, so there's no session cookie in
  play today for this directive to actually harden — it's here so the
  proxy is already correctly configured the moment a cookie-based flow
  (e.g. a future browser-session layer) gets added, instead of that being
  one more thing to remember at that point.

## Local development / self-signed certs

If you just want HTTPS locally to test the nginx config itself (not a
real public deployment), generate a self-signed certificate instead of
using Certbot:

```bash
mkdir -p certs/live/localhost
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/live/localhost/privkey.pem \
  -out certs/live/localhost/fullchain.pem \
  -subj "/CN=localhost"
```

Your browser will show a certificate warning (expected and harmless for
local testing — self-signed certs aren't trusted by any browser by
default), but the HTTPS connection, headers, and proxying will all
function exactly as they would with a real certificate.
