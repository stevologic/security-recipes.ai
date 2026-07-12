# Deploying to a droplet with Caddy + automatic Let's Encrypt

This is the recommended deployment path: the whole stack — static site, MCP
server, and TLS — runs from one `docker compose up -d --build`. Caddy lives in
the compose stack, terminates HTTPS on ports 80/443, obtains the Let's Encrypt
certificate for your domain automatically, and renews it in the background.
Certificates persist in the `caddy_data` volume across rebuilds and redeploys.

The alternative host-level flows still exist: nginx + certbot
([README.nginx-letsencrypt.md](README.nginx-letsencrypt.md)) and host Caddy via
`scripts/setup_digitalocean_droplet.sh`. Use exactly one proxy — whichever owns
ports 80/443.

## First deploy

DNS for the domain must already point at the droplet, with ports 80 and 443
reachable (Let's Encrypt validates over them).

```bash
git clone https://github.com/stevologic/security-recipes.ai /opt/security-recipes.ai
cd /opt/security-recipes.ai
cp .env.example .env          # COMPOSE_PROFILES=caddy is on by default here
# edit .env if your domain/email differ from security-recipes.ai defaults
sudo bash scripts/install_docker_compose_v2.sh   # if compose v2 is missing
docker compose up -d --build
```

That's it. Caddy requests the certificate on first start; give it a few
seconds, then:

```bash
curl -I https://security-recipes.ai/
curl -sS https://security-recipes.ai/mcp -X POST   # MCP proxies through the same origin
docker compose logs --tail=50 caddy                # ACME progress lives here
```

If a host-level nginx or Caddy already runs on this droplet, stop it first so
the container can bind 80/443: `sudo systemctl disable --now nginx caddy`.

## Staying up to date: deploy.sh on cron

[deploy.sh](deploy.sh) keeps the droplet tracking `main` without downtime:

- exits quietly when `origin/main` hasn't moved (cheap enough for frequent cron);
- builds images **before** touching the running stack, so the only interruption
  is the ~1-2s container swap — which Caddy bridges by holding and retrying
  requests (`lb_try_duration` in [docker/caddy/Caddyfile](docker/caddy/Caddyfile)),
  so clients see a brief delay, never an error;
- health-checks the site after the swap and **rolls back automatically** if the
  new build never answers; a failed commit is remembered and skipped until a
  new commit lands (or `deploy.sh --force`);
- preserves `.env` and `mcp-server.toml`, and prunes dangling images.

Install the cron job:

```bash
sudo crontab -e
# every 15 minutes, with a log:
*/15 * * * * /opt/security-recipes.ai/deploy.sh >> /var/log/security-recipes-deploy.log 2>&1
```

Watch a deploy happen:

```bash
tail -f /var/log/security-recipes-deploy.log
```

## Notes

- Caddy only recreates when its own config changes, so redeploys never touch
  the TLS session or certificates.
- The site container keeps its loopback bind (`127.0.0.1:8080`) for debugging:
  `curl -I http://127.0.0.1:8080/` tests the app without the proxy.
- To serve `www.` too, add DNS for it and uncomment the block at the bottom of
  [docker/caddy/Caddyfile](docker/caddy/Caddyfile).
- `scripts/redeploy_from_github.sh` is the older cron redeployer; deploy.sh
  supersedes it (adds health gating, rollback, and failed-commit memory).
