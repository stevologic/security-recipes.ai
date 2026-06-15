# Nginx + Let's Encrypt for security-recipes.ai

This repository's Docker image serves the site over plain HTTP inside the
container. The public TLS endpoint belongs on the host reverse proxy, not in
the app container.

That split is intentional:

- Docker keeps serving `http://127.0.0.1:8080`.
- Host nginx owns ports `80` and `443`.
- Certbot obtains and renews the certificate for your public domain.
- nginx forwards requests back to the loopback app container.

## Quick start

1. Point your domain's DNS `A` record at the droplet.
2. Start the app stack on loopback:

```bash
cp .env.example .env
sudo bash scripts/install_docker_compose_v2.sh
docker compose up -d --build
```

3. Configure nginx and Let's Encrypt on the host:

```bash
sudo bash scripts/configure_nginx_letsencrypt.sh \
  --domain security-recipes.ai \
  --email admin@security-recipes.ai
```

The helper script assumes the site is already reachable locally at
`http://127.0.0.1:8080/`. That is the default in `.env.example`.

## What the script does

1. Installs `nginx`, `certbot`, and the nginx Certbot plugin if needed.
2. Writes an HTTP reverse-proxy site for your domain.
3. Validates and reloads nginx.
4. Runs `certbot --nginx` to request a certificate and add HTTPS redirect
   rules.
5. Installs a renewal hook that reloads nginx after certificate renewals.

## Script options

```text
--domain DOMAIN             Public hostname. Required.
--email EMAIL               Let's Encrypt account email. Required.
--upstream HOST:PORT        App upstream. Default: 127.0.0.1:8080
--site-name NAME            nginx site filename prefix. Default: security-recipes
--webroot PATH              ACME challenge directory. Default: /var/www/letsencrypt
--skip-package-install      Reuse an existing nginx/certbot install.
--staging                   Use the Let's Encrypt staging environment.
```

## How renewal works

Certbot installs its normal renewal timer on Ubuntu/Debian. This repo's helper
adds a deploy hook at:

```text
/etc/letsencrypt/renewal-hooks/deploy/security-recipes-reload-nginx.sh
```

That hook reloads nginx after a renewed certificate is written so the live
proxy picks up the new files.

You can verify renewal end to end with:

```bash
sudo certbot renew --dry-run
```

## Docker image note

The runtime image also carries the helper and this README so operators pulling
the published image can inspect the deployment assets without cloning the repo:

```text
/opt/security-recipes/scripts/configure_nginx_letsencrypt.sh
/opt/security-recipes/README.nginx-letsencrypt.md
```

## Troubleshooting

- If Certbot fails, confirm DNS already points at the droplet and ports `80`
  and `443` are reachable from the internet.
- If nginx comes up but the site is blank, check the local upstream first:

```bash
curl -I http://127.0.0.1:8080/
docker compose ps
docker compose logs --tail=100 security-recipes
```

- If you want the existing one-shot host bootstrapper with automatic HTTPS,
  `scripts/setup_digitalocean_droplet.sh` still supports the Caddy path.
