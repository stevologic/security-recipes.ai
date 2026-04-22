# syntax=docker/dockerfile:1.7
# ============================================================================
# Agentic Remediation Recipes — container build
#
# Multi-stage build:
#   1. `builder`  — Hugo extended + Go, fetches Hextra module, builds static site
#   2. `runtime`  — nginx:alpine, serves the compiled output
#
# Usage
# -----
#   # Build (from the directory containing hugo.yaml):
#   docker build -t agentic-remediation-recipes .
#
#   # Run:
#   docker run --rm -p 3000:80 agentic-remediation-recipes
#   # → http://localhost:3000
#
#   # Override baseURL / repoURL at build time (e.g. when deploying behind
#   # a subpath or forking under a different GitHub org):
#   docker build \
#     --build-arg BASE_URL="https://example.com/docs/" \
#     --build-arg REPO_URL="https://github.com/your-org/your-repo" \
#     -t agentic-remediation-recipes .
# ============================================================================


# ----- Stage 1 : builder ----------------------------------------------------
# NOTE: Debian-based (bookworm), NOT alpine. Hugo *extended* is dynamically
# linked against glibc + libstdc++ (for the embedded SCSS transpiler). On
# alpine it fails with "Error loading shared library libstdc++.so.6".
# Debian ships both by default, so the extended binary runs out of the box.
FROM golang:1.22-bookworm AS builder

# Match the Hugo version pinned in .github/workflows/hugo.yml
# (Hextra v0.12.2+ requires Hugo ≥ 0.146.0 for the `try` template function.)
ARG HUGO_VERSION=0.147.6
ARG TARGETARCH=amd64

# Build-time overrides — both are threaded into the same Hugo params used by
# the GitHub Actions workflow, so `docker build` and `hugo deploy` produce
# identical output.
#
# BASE_URL defaults to a plain-root host (http://localhost/) so the image
# works out of the box when served from `/` — e.g. `docker run -p 3000:80`
# maps cleanly to http://localhost:3000/. Override for subpath deploys:
#   --build-arg BASE_URL=https://example.com/docs/
ARG BASE_URL="http://localhost/"
ARG REPO_URL=""

# HUGO_ENABLEGITINFO=false overrides `enableGitInfo: true` from hugo.yaml *for
# container builds only*. We intentionally exclude `.git/` via .dockerignore to
# keep the image small, which means Hugo can't read the git log to populate
# .GitInfo / .Lastmod. CI builds (GitHub Actions) keep GitInfo enabled because
# the full repo is checked out there.
ENV HUGO_ENVIRONMENT=production \
    HUGO_CACHEDIR=/tmp/hugo_cache \
    HUGO_ENABLEGITINFO=false \
    CGO_ENABLED=0 \
    DEBIAN_FRONTEND=noninteractive

# Install Hugo extended from the official tarball. Everything Hugo extended
# needs (glibc, libstdc++, libgcc_s) is already present in the base image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL \
        "https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_extended_${HUGO_VERSION}_linux-${TARGETARCH}.tar.gz" \
        -o /tmp/hugo.tgz \
    && tar -xzf /tmp/hugo.tgz -C /usr/local/bin hugo \
    && rm /tmp/hugo.tgz \
    && hugo version

WORKDIR /src

# Copy module manifests first so `hugo mod get` caches well when only content
# or layouts change.
COPY go.mod go.sum* ./
RUN hugo mod get -u github.com/imfing/hextra

# Now pull in the rest of the project.
COPY . .

# If REPO_URL was passed, rewrite any `stevologic/agentic-remediation-recipes`
# reference in hugo.yaml AND in content markdown (matches the CI approach).
# Covers: editURL base, Contribute menu URL, sidebar Contribute, and
# CONTRIBUTING.md links inside Prompt Library copy.
RUN if [ -n "${REPO_URL}" ]; then \
        OWNER_REPO=$(printf '%s' "${REPO_URL%/}" | sed 's|^https\?://github.com/||') ; \
        sed -i "s|stevologic/agentic-remediation-recipes|${OWNER_REPO}|g" hugo.yaml ; \
        find content -type f -name "*.md" -exec sed -i \
            "s|stevologic/agentic-remediation-recipes|${OWNER_REPO}|g" {} + ; \
    fi

# Rewrite absolute card links so Hextra's `{{< card link="/..." >}}` shortcode
# resolves to the correct subpath when the image is served behind one (e.g.
# --build-arg BASE_URL=https://example.com/docs/). Hextra's card shortcode
# emits the `link=` value verbatim into the anchor's `href` — if we don't
# prepend the base path, internal card links 404 on non-root deploys.
#
# When BASE_URL has no path (the default http://localhost/, or any root-host
# deploy), BASE_PATH is empty and this step is a no-op.
RUN BASE_PATH=$(printf '%s' "${BASE_URL}" | sed -E 's|^https?://[^/]+||; s|/$||') ; \
    if [ -n "${BASE_PATH}" ]; then \
        echo "Prepending BASE_PATH=${BASE_PATH} to card link=\"/...\" paths" ; \
        find content -type f -name "*.md" -exec sed -i -E \
            "s|link=\"/|link=\"${BASE_PATH}/|g" {} + ; \
        find content -type f -name "*.md" -exec sed -i -E \
            "s|link=\"${BASE_PATH}${BASE_PATH}/|link=\"${BASE_PATH}/|g" {} + ; \
    fi

# Build. `HUGO_PARAMS_REPOURL` surfaces the repo URL to the landing page
# template. `--baseURL` overrides the value in hugo.yaml so the image's
# generated links don't carry the GitHub Pages subpath (`/agentic-...`)
# into a container that's served from `/`.
RUN HUGO_PARAMS_REPOURL="${REPO_URL:-https://github.com/stevologic/agentic-remediation-recipes}" \
    hugo --gc --minify \
        --baseURL="${BASE_URL}" \
    && touch public/.nojekyll


# ----- Stage 2 : runtime ----------------------------------------------------
FROM nginx:1.27-alpine AS runtime

LABEL org.opencontainers.image.title="Agentic Remediation Recipes" \
      org.opencontainers.image.description="Community-driven recipes for agentic remediation across AI coding tools." \
      org.opencontainers.image.source="https://github.com/stevologic/agentic-remediation-recipes"

# Minimal nginx config — static site, gzip on, SPA-friendly fallbacks off
# (Hugo outputs real files for every route).
RUN rm /etc/nginx/conf.d/default.conf
COPY <<'EOF' /etc/nginx/conf.d/default.conf
server {
    listen       80;
    listen  [::]:80;
    server_name  _;

    root   /usr/share/nginx/html;
    index  index.html;

    # Hugo outputs pretty URLs like /claude/, /prompt-library/, etc.
    # Try the literal path, then with trailing slash, then 404.
    location / {
        try_files $uri $uri/ $uri.html =404;
    }

    # Long-cache fingerprinted assets; short-cache HTML.
    location ~* \.(css|js|svg|png|jpg|jpeg|gif|webp|ico|woff2?)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    location ~* \.html$ {
        add_header Cache-Control "public, max-age=300, must-revalidate";
    }

    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css text/javascript application/javascript
               application/json application/xml image/svg+xml;

    # Friendly 404
    error_page 404 /404.html;
}
EOF

COPY --from=builder /src/public /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --spider http://localhost/ || exit 1
