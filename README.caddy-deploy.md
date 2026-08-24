# Deploying to a droplet with Caddy + automatic Let's Encrypt

This is the recommended deployment path: two static-site slots run behind
Caddy, which terminates HTTPS on ports 80/443, obtains the Let's Encrypt
certificate for your domain automatically, and renews it in the background.
The blue slot, `security-recipes`, binds to `127.0.0.1:8080`; the green slot,
`security-recipes-green`, binds to `127.0.0.1:8081`. Only Caddy is public.
Certificates persist in the `caddy_data` volume across site releases. Caddy's
API-loaded blue/green route order is autosaved in `caddy_config` and resumed
after a Caddy restart.

The bundled Caddy container is the simplest option. The alternative host-level
flows still exist: nginx + certbot
([README.nginx-letsencrypt.md](README.nginx-letsencrypt.md)) and host Caddy via
`scripts/setup_digitalocean_droplet.sh`. Zero-downtime releases through
`deploy.sh` require either bundled Caddy or the managed host Caddy
configuration; nginx is not currently a supported cutover controller. Use
exactly one proxy — whichever owns ports 80/443.

## First deploy

DNS for the domain must already point at the droplet, with ports 80 and 443
reachable (Let's Encrypt validates over them).

```bash
sudo -i                         # use a root shell for host deployment
git clone https://github.com/stevologic/security-recipes.ai /opt/security-recipes.ai
cd /opt/security-recipes.ai
cp .env.example .env          # COMPOSE_PROFILES=caddy is on by default here
# edit .env if your domain/email differ from security-recipes.ai defaults
sudo chown -R root:root /opt/security-recipes.ai
sudo chmod -R go-w /opt/security-recipes.ai
sudo chmod 750 /opt/security-recipes.ai
sudo chmod 600 /opt/security-recipes.ai/.env
sudo apt-get update && sudo apt-get install -y jq
sudo bash scripts/install_docker_compose_v2.sh   # if compose v2 is missing
docker compose up -d --build
./deploy.sh --force             # initialize an exact-revision blue/green release
sudo bash scripts/setup_digitalocean_droplet.sh \
  --automation-only --app-dir /opt/security-recipes.ai
```

The initial Compose command starts both slots and starts Caddy with
`caddy run --resume`. The forced deploy builds one commit-tagged slot, verifies
its revision marker, switches Caddy gracefully, and creates the version 2
`.git/deploy-state`. Caddy requests the certificate on first start; give it a
few seconds, then:

```bash
curl -I https://security-recipes.ai/
curl -fsS https://security-recipes.ai/.well-known/deploy-revision
curl -sS https://security-recipes.ai/mcp -X POST   # MCP proxies through the same origin
docker compose logs --tail=50 caddy                # ACME progress lives here
```

If a host-level nginx or Caddy already runs on this droplet, stop it first so
the container can bind 80/443: `sudo systemctl disable --now nginx caddy`.

## Search discovery after an SEO release

Deployment and search discovery are separate gates. Do not submit changed URLs
while production still serves an older revision. First compare the public
marker with the exact merge commit and verify the priority search surfaces:

```bash
git fetch origin main
merge_sha="$(git rev-parse origin/main)"
test "$(curl -fsS https://security-recipes.ai/.well-known/deploy-revision)" = "${merge_sha}"
curl -fsSI https://security-recipes.ai/agentic-security/
curl -fsSI https://security-recipes.ai/security-remediation/
curl -fsSI https://security-recipes.ai/cve-database/
curl -fsSI https://security-recipes.ai/cve/CVE-2026-14956/
curl -fsS https://security-recipes.ai/sitemap.xml
```

Then use a Google Search Console **Domain property** for
`security-recipes.ai`; Google requires DNS verification for that property type.
The DNS record comes from the Search Console account and must not be invented
or committed as a placeholder. In the verified property:

1. Submit `https://security-recipes.ai/sitemap.xml` in the Sitemaps report.
2. Inspect `/agentic-security/`, `/security-remediation/`, `/cve-database/`, and
   the small set of reviewed priority CVE URLs. Run **Test live URL** and confirm
   that crawling is allowed, the fetch succeeds, indexing is allowed, and the
   declared and Google-selected canonicals agree.
3. Use **Request indexing** for those priority pages after the live test passes.
   Use the sitemap for the broader qualified set rather than manually requesting
   every catalog record.
4. Monitor Page indexing and Search performance separately for exact CVE IDs,
   AI vulnerability-remediation queries, and AI-agent-security queries. Record
   impressions, indexed URL, Google-selected canonical, title rewriting, CTR,
   and position before making another content change.

Google documents sitemap submission as a discovery hint, not an indexing or
ranking guarantee. See the official
[sitemap submission guide](https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap),
[URL Inspection guide](https://support.google.com/webmasters/answer/12482179),
and [Domain property guide](https://support.google.com/webmasters/answer/34592).
Relevant external citations and links remain necessary for competitive queries;
do not respond to slow recrawling by publishing thin or duplicate CVE pages.

## Staying up to date: deploy.sh on a managed timer

The same droplet also serves the `development` branch at
`https://dev.security-recipes.ai/`. Add a DigitalOcean A record for
`dev.security-recipes.ai` pointing at the production droplet
(`64.227.98.210`) so Caddy can obtain the staging certificate. If a
`DIGITALOCEAN_ACCESS_TOKEN` is available in GitHub Actions or on the
droplet (`/etc/security-recipes/deploy.env` or doctl config),
`deploy.sh`, `python scripts/upsert_dev_dns_record.py`, or the
`Dev DNS record` workflow will create or repair that record. After DNS
exists, `deploy.sh` keeps pulling `:SHA-development`
images whenever `origin/development` advances. Staging is a single extra
nginx slot that shares the live MCP process; it is `noindex` at the edge.

[deploy.sh](deploy.sh) keeps the droplet tracking `main` without downtime:

- fetches `origin/main` and exits quietly when the commit recorded in
  `.git/deploy-state` is already active;
- waits for every `push` workflow, GitHub default-CodeQL (`dynamic`) run, and
  CVE-automation-qualified exact-SHA `workflow_dispatch` run from `build.yml`
  on the target commit to complete without a failure, and requires the
  repository's `Build` workflow to succeed; scheduled production watchdog and
  catalog jobs remain independent so they cannot deadlock the deployment that
  repairs them;
- resets the deployment checkout only after CI passes while preserving `.env`
  and `mcp-server.toml`;
- pulls the CI-built, commit-tagged site and MCP images for the inactive slot
  without touching the active site/MCP pair;
- gracefully withdraws the inactive slot from Caddy, verifies that the active
  revision still serves through HTTPS, and atomically records the no-fallback
  state before recreating the inactive container;
- starts only that withdrawn site/MCP pair, checks both containers through their
  loopback paths, and requires `/.well-known/deploy-revision` to contain the
  exact 40-character target commit before making the slot eligible for any
  traffic;
- validates and gracefully reloads Caddy with the candidate as the primary and
  the previous release as the fallback only when that previous release still
  serves its exact recorded marker, without restarting Caddy;
- verifies the exact revision again through the local HTTPS listener and
  restores the previous route if that post-cutover check fails;
- atomically records version 2 state — active service/SHA and, when verified,
  fallback service/SHA — in `.git/deploy-state`, then alternates slots on the
  next release; and
- refuses to pull and replace an inactive pair without configured disk and
  memory headroom, prunes unused site/MCP images while retaining the images used
  by both running pairs, and bounds old BuildKit cache; and
- verifies that the live CVE catalog timestamp is recent before sending an
  optional dead-man success heartbeat.

Caddy's first-upstream policy, active health checks, passive failure detection,
and request retries let it use a verified warm previous release if the primary
later fails. A root-healthy container with no valid exact revision marker is
never admitted as a fallback. This means a legacy blue container may remain
running but ineligible after the first migration; it becomes a trusted fallback
only after a later deploy rebuilds and verifies that slot.

A normal scheduled deploy never runs a project-wide `docker compose up`, never
rebuilds the active site slot, and never recreates the public Caddy edge. On an
unchanged commit, it checks that the recorded active revision is still served
by both its slot and Caddy; when state and routing agree, it exits without
force-reloading Caddy.

If a candidate container starts but fails its revision or proxy checks, its
commit is remembered and not rebuilt until a new commit lands or
`deploy.sh --force` is used. Scheduled checks continue returning failure for
that undeployed commit, so systemd and a missing success heartbeat expose the
stuck release. Site rollback is a routing change: the previous commit-tagged
container is already running, so no rollback image build is needed. The
checkout is also restored to the previously deployed commit.

### Bundled versus host Caddy

`DEPLOY_PROXY_MODE=auto`, the default, uses a running bundled Caddy container
first and otherwise looks for the systemd-managed host Caddy service. Set
`DEPLOY_PROXY_MODE=bundled` or `DEPLOY_PROXY_MODE=host` in
`/etc/security-recipes/deploy.env` if the choice should be explicit.

- **Bundled Caddy:** keep `COMPOSE_PROFILES=caddy` in `.env`. Caddy addresses the
  slots as `security-recipes:80` and `security-recipes-green:80` on the Compose
  network. `deploy.sh` sends the repository Caddyfile into the running
  container, validates it, and performs a graceful in-process reload. Compose
  runs Caddy with `--resume`, so the API-loaded configuration in the
  `caddy_config` volume — including active/fallback order — survives a
  container or host restart.
- **Host Caddy:** remove `COMPOSE_PROFILES=caddy` from `.env` and use the
  Caddyfile managed by `scripts/setup_digitalocean_droplet.sh`. The host proxy
  addresses the slots through `127.0.0.1:8080` and `127.0.0.1:8081`.
  The setup script installs
  `/etc/systemd/system/caddy.service.d/20-security-recipes-resume.conf`, which
  starts Caddy with `--resume`. `deploy.sh` refuses to cut over if either that
  restart-durable command or the blue/green placeholders in
  `/etc/caddy/Caddyfile` are missing.

Set `DEPLOY_PROXY_HEALTH_URL` only when the default local HTTPS verification is
not appropriate. Otherwise the script derives the domain from `.env` and
resolves that hostname to `127.0.0.1` for the post-cutover check.

Each paired MCP service reads its recipe index directly from its matching site
container over the Compose network. This avoids depending on public DNS,
hairpin routing, or the edge proxy for tool calls and keeps each pair on the
same release. The transitional singleton reads from the blue site by default.
Operators can override these sources with `RECIPES_MCP_BLUE_SOURCE_INDEX_URL`,
`RECIPES_MCP_GREEN_SOURCE_INDEX_URL`, or the singleton
`RECIPES_MCP_SOURCE_INDEX_URL`.

### One-time migration from the old single slot

Pause the deploy timer or legacy cron before migrating so the old and new
scripts cannot run at the same time. Confirm that server-only settings live in `.env` or
`mcp-server.toml`, then update the checkout with a fast-forward pull. Do not run
a project-wide `docker compose up` during this migration; the old
`security-recipes` container can keep serving on port 8080.

```bash
sudo -i
cd /opt/security-recipes.ai
git status --short
git fetch origin main
git pull --ff-only origin main
grep -q '^SECURITY_RECIPES_GREEN_HTTP_PORT=' .env ||
  printf '\nSECURITY_RECIPES_GREEN_HTTP_PORT=127.0.0.1:8081\n' >> .env
docker compose config --quiet
```

For **bundled Caddy**, an existing container must be recreated once so it uses
the new Compose `--resume` command and directory mount. This briefly interrupts
the only public edge, so schedule a maintenance window or use a redundant
front proxy. Recreate Caddy alone; do not restart either site slot:

```bash
docker compose up -d --no-deps --force-recreate caddy
docker inspect --format '{{json .Config.Cmd}}' "$(docker compose ps -q caddy)" |
  grep -- '--resume'
DEPLOY_PROXY_MODE=bundled ./deploy.sh --force
```

This one-time recreation is intentional. Until it has happened, `deploy.sh`
refuses an old bundled Caddy process rather than installing a route order that
would be lost on its next restart.

For **host Caddy**, first replace the old single-upstream `reverse_proxy`
directive in `/etc/caddy/Caddyfile` with the following block. Keep the rest of
the existing site configuration unchanged.

```caddyfile
reverse_proxy {$SECURITY_RECIPES_PRIMARY_UPSTREAM:http://127.0.0.1:8080} {$SECURITY_RECIPES_FALLBACK_UPSTREAM:http://127.0.0.1:8081} {
	lb_policy first
	health_uri /
	health_interval 5s
	health_timeout 2s
	health_status 200
	health_fails 1
	health_passes 2
	fail_duration 30s
	max_fails 1
	unhealthy_status 5xx
	lb_try_duration 5s
	lb_try_interval 100ms
	stream_close_delay 5m
}
```

Then install the managed systemd override. Applying a new `ExecStart` requires
one Caddy restart, so this also belongs in the maintenance window:

```bash
install -d -m 0755 /etc/systemd/system/caddy.service.d
cat >/etc/systemd/system/caddy.service.d/20-security-recipes-resume.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/caddy run --environ --resume --config /etc/caddy/Caddyfile
ExecReload=
EOF
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl daemon-reload
systemctl restart caddy
systemctl show --property=ExecStart --value caddy | grep -- '--resume'
test -z "$(systemctl show --property=ExecReload --value caddy)"
DEPLOY_PROXY_MODE=host ./deploy.sh --force
```

Clearing the distro unit's file-based `ExecReload` is intentional. Route
changes are applied through `deploy.sh` and Caddy's API; a later
`systemctl reload caddy` must not replace the autosaved active/fallback order
with static Caddyfile defaults.

Once Caddy is back, the fallback on port 8081 can remain unavailable because
the existing primary on port 8080 is healthy. The forced deploy then builds and
verifies port 8081 before routing any traffic to it. Verify the migration and
re-enable scheduling only after these checks pass:

```bash
curl -fsS https://security-recipes.ai/.well-known/deploy-revision
docker compose ps security-recipes security-recipes-green
cat .git/deploy-state
```

The setup script writes this host Caddy configuration for new droplets.
Existing production hosts should use the staged procedure above rather than
rerunning the entire provisioning script, because provisioning also starts the
whole Compose project. After either migration, each API-loaded route order is
autosaved and resumed after later Caddy restarts.

### Edge and MCP availability boundaries

The deploy automatically pulls a newer Caddy image but deliberately does not
recreate the sole Caddy container. Replacing a single process that owns ports
80/443 cannot be guaranteed downtime-free. Apply Caddy image upgrades in a
maintenance window, or put a redundant proxy/load balancer in front of two
edges and rotate them one at a time. With `--resume`, the autosaved API
configuration preserves the active/fallback order across the planned restart;
version 2 `.git/deploy-state` gives `deploy.sh` an independent record to verify
and reconcile.

The static website, its images, and `/mcp` remain available throughout a normal
deploy. Each site slot has a paired MCP service (`mcp-server-blue` or
`mcp-server-green`). `deploy.sh` pulls and verifies the inactive pair before
cutover, then keeps the previous verified pair available as the warm fallback.
Legacy hosts can briefly retain the transitional singleton `mcp-server`; each
slot migrates to its paired MCP service when that slot next becomes the
candidate.

The CI gate uses GitHub's public REST API and `jq`. This public repository does
not require a token. Private repositories must configure non-interactive Git
credentials and set `GH_TOKEN` (or `GITHUB_TOKEN`) in
`/etc/security-recipes/deploy.env`; login profiles and the Compose `.env` file
are not loaded by the systemd service. This token is separate from the CVE
enrichment key stored in GitHub Actions secrets. The polling defaults are a
30-minute timeout, 60-second interval, and 30-second stable-green window;
override them with `DEPLOY_CI_TIMEOUT`, `DEPLOY_CI_POLL_SECONDS`, and
`DEPLOY_CI_SETTLE_SECONDS`. The gate queries the `push` and `dynamic` event
classes plus CVE catalog dispatches from the `Build` workflow independently,
rejects truncated or mismatched results, then evaluates their merged run set.
The CVE fallback title embeds its expected full SHA; only the newest exact-SHA
fallback run is evaluated. Dependabot graph updates, other manually dispatched
runs, and all scheduled workflows remain outside the gate. Git fetches and
individual GitHub requests also have timeouts so a network stall cannot hold
the deployment lock indefinitely.

Ancillary service updates are not part of the site routing rollback. In
particular, a refreshed MCP container is not rebuilt from the old checkout when
a later site candidate fails. Pin third-party images by digest and give
stateful or API services their own release strategy if byte-for-byte rollback
is required.

### Install scheduling without restarting the site

The provisioning script installs systemd oneshot services and timers by
default. For an existing droplet, its automation-only mode changes no
containers, proxy routes, firewall rules, packages, or checkout contents:

```bash
sudo bash /opt/security-recipes.ai/scripts/setup_digitalocean_droplet.sh \
  --automation-only \
  --app-dir /opt/security-recipes.ai
systemctl list-timers 'security-recipes-*'
```

The deploy timer waits 15 minutes after a check finishes before scheduling the
next one, and systemd will not run a second instance of the same service. The
script retains its own non-blocking file lock as defense in depth. During
installation, only root-crontab lines that invoke this checkout's `deploy.sh`
or legacy `redeploy_from_github.sh` are removed; unrelated cron jobs are
preserved. This prevents an old cron entry and the new timer from deploying at
the same time.

The service runs as root because Docker access is effectively root access. The
checkout must remain root-owned and not group/world writable so another
account cannot replace the script the service executes.

```bash
# Run once now, inspect recent output, and inspect the next scheduled run.
sudo systemctl start security-recipes-deploy.service
sudo journalctl -u security-recipes-deploy.service -n 100 --no-pager
systemctl status security-recipes-deploy.timer
```

Systemd stores output in the bounded journal instead of a separate unbounded
cron log. Compose also uses Docker's rotating `local` log driver for every
container. Defaults are 10 MB times five files per container and can be
changed with `SECURITY_RECIPES_LOG_MAX_SIZE` and
`SECURITY_RECIPES_LOG_MAX_FILES` in `.env`.

### Resource headroom, freshness, and dead-man monitoring

Before pulling a candidate release, `deploy.sh` requires at least 2048 MB free
on the deployment filesystem. If space is low it removes only unused site/MCP
image tags, dangling images, and build cache older than seven days. It reads the
running slot image references first and never asks Docker to remove them. After
a successful release it performs the same bounded cleanup.

The deploy also requires at least 256 MB of `MemAvailable + SwapFree` before
replacing the inactive pair. This is a fail-before-replacement guard: a small
Droplet without enough RAM or swap keeps serving the current release instead
of risking host pressure while Docker pulls and starts the CI-built images.
Configure these limits in `/etc/security-recipes/deploy.env`:

```ini
DEPLOY_MIN_FREE_MB=2048
# Optional override; the default is Docker's reported root directory.
DEPLOY_DISK_PATH=
DEPLOY_MIN_AVAILABLE_MEMORY_MB=256
DEPLOY_BUILD_CACHE_MAX_AGE=168h
DEPLOY_BUILD_CACHE_KEEP_STORAGE=5GB
DEPLOY_CATALOG_MAX_AGE_HOURS=36
```

For a small existing Droplet, add persistent swap once before enabling the
timer (or resize the Droplet). These commands leave an existing `/swapfile`
untouched and make a newly created one survive reboot:

```bash
if [ ! -f /swapfile ]; then
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
fi
swapon --show=NAME --noheadings | grep -qx /swapfile || swapon /swapfile
grep -qF '/swapfile none swap sw 0 0' /etc/fstab ||
  printf '/swapfile none swap sw 0 0\n' >> /etc/fstab
free -h
```

Do not lower the memory threshold merely to make a failed deploy proceed. Leave
capacity for Caddy and both site/MCP pairs, inspect container memory during a
manual deploy, and prefer a larger Droplet when releases cause sustained
swapping.

Every successful unchanged or updated run checks the public
`/api/cve-catalog/manifest.json` and rejects a missing, malformed,
future-dated, or older-than-36-hours `catalog_updated_at`. Configure a
Healthchecks.io, Uptime Kuma, or equivalent dead-man URL to make missing
successful checks externally visible:

```ini
# /etc/security-recipes/deploy.env (mode 0600)
DEPLOY_SUCCESS_HEARTBEAT_URL=https://your-monitor.example/ping/private-id
```

The heartbeat is sent only after the public revision and catalog pass. A
monitoring-provider outage is logged but does not roll back a healthy release;
the missing ping is expected to alert through the provider. Also configure an
independent public HTTP monitor for `/`, TLS expiry, and
`/.well-known/deploy-revision`, plus Droplet alerts for disk, memory, CPU, and
container restart loops. Those external monitors require provider accounts and
cannot be provisioned safely from this repository.

### Automated recovery bundles and restore drill

`security-recipes-backup.timer` creates a root-only configuration bundle each
day under `/var/backups/security-recipes` and retains 14 days. The bundle
contains `.env`, optional `mcp-server.toml`, deploy state for diagnosis, Caddy
configuration, and the managed service/environment files. Generated site data
and images are excluded because Git plus `deploy.sh --force` rebuild them.

Run and inspect a backup:

```bash
sudo systemctl start security-recipes-backup.service
sudo journalctl -u security-recipes-backup.service -n 100 --no-pager
sudo ls -lh /var/backups/security-recipes/
latest="$(sudo find /var/backups/security-recipes -maxdepth 1 -type f \
  -name 'security-recipes-config-*.tar.gz' -printf '%T@ %p\n' |
  sort -nr | head -1 | cut -d' ' -f2-)"
sudo tar -tzf "${latest}"
```

A local bundle does not protect against Droplet or regional loss. Enable
DigitalOcean Droplet backups separately, and configure an encrypted off-host
copy in `/etc/security-recipes/backup.env`. Off-host upload is deliberately
refused until both an age public recipient and rclone destination are set:

```ini
SECURITY_RECIPES_BACKUP_RCLONE_DESTINATION=remote:security-recipes-backups
SECURITY_RECIPES_BACKUP_AGE_RECIPIENT=age1replace_with_your_public_recipient
SECURITY_RECIPES_BACKUP_HEARTBEAT_URL=https://your-monitor.example/ping/backup-id
```

Configure and test `rclone` as root, and escrow the age private key and rclone
recovery credentials somewhere other than the Droplet. A replacement-host
restore is:

1. Clone `main` into `/opt/security-recipes.ai` and install Docker/Caddy.
2. Decrypt an off-host bundle with `age --decrypt`, then extract it into a
   temporary root-only directory rather than over `/`.
3. Restore `app/.env`, optional `app/mcp-server.toml`,
   `etc/security-recipes/*.env`, and the applicable Caddy configuration.
4. Keep the archived deploy state for diagnosis; do not blindly install it on
   a host whose containers were rebuilt.
5. Run the setup script's automation-only mode, then `deploy.sh --force`.
6. Verify `/`, `/.well-known/deploy-revision`, the CVE manifest timestamp, both
   timers, and external alerts before declaring the restore complete.

Perform this restore drill at least quarterly. Whole-Droplet backups are
separate from these bundles and still require a provider-side restore test.

## Notes

- A release that changes the active slot reloads Caddy gracefully but does not
  recreate it, so the TLS process and certificate volumes remain in place.
  An unchanged, already-consistent timer run does not reload it.
- Both site containers keep loopback-only binds for direct checks:
  `curl -I http://127.0.0.1:8080/` tests blue and
  `curl -I http://127.0.0.1:8081/` tests green without the proxy.
- `.git/deploy-state` is version 2 runtime state, not source control. It records
  the active service/SHA and the separately verified fallback service/SHA. Do
  not delete or hand-edit it while deployment scheduling is active.
- To serve `www.` too, add DNS for it and uncomment the block at the bottom of
  [docker/caddy/Caddyfile](docker/caddy/Caddyfile).
- `scripts/redeploy_from_github.sh` is the older cron redeployer; `deploy.sh`
  supersedes it (adds exact-commit CI gating, blue/green health checks, routing
  rollback, and failed-commit memory).
