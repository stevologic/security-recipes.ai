# syntax=docker/dockerfile:1.7
# ============================================================================
# security-recipes.ai — container build
#
# Multi-stage build:
#   1. `builder`  — Node.js + Eleventy, builds the static site into public/
#   2. `runtime`  — nginx:alpine, serves the compiled output
#
# Usage
# -----
#   # Build (from the repository root):
#   docker build -t security-recipes .
#
#   # Run:
#   docker run --rm -p 3000:80 security-recipes
#   # → http://localhost:3000
#
#   # Override baseURL / repoURL at build time (e.g. when deploying behind
#   # a subpath or forking under a different GitHub org):
#   docker build \
#     --build-arg BASE_URL="https://example.com/docs/" \
#     --build-arg REPO_URL="https://github.com/your-org/your-repo" \
#     -t security-recipes .
# ============================================================================


# ----- Stage 1 : builder ----------------------------------------------------
FROM node:22-bookworm-slim AS builder

# BASE_URL defaults to a plain-root host (http://localhost/) so the image
# works out of the box when served from `/` — e.g. `docker run -p 3000:80`
# maps cleanly to http://localhost:3000/. Override for subpath deploys:
#   --build-arg BASE_URL=https://example.com/docs/
# Subpath deploys are handled by Eleventy's HTML base plugin, which rewrites
# every root-relative URL in the generated HTML.
ARG BASE_URL="http://localhost/"
ARG REPO_URL=""

# .dockerignore excludes .git/ to keep the build context small, so git-based
# last-modified dates are unavailable inside the container; the build falls
# back to front-matter dates. CI builds keep git info because the full repo
# is checked out there.
ENV SECURITY_RECIPES_NO_GITINFO=1

WORKDIR /src

# Install dependencies first so the layer caches well when only content
# changes. The npm cache mount persists downloads across builds, so a
# lockfile change re-resolves from the local cache instead of the network.
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund

# Copy only the Eleventy build inputs, least-churn first: edits to Python
# tooling, tests, or docker config never reach these layers, so they can't
# invalidate the site build below.
COPY eleventy.config.js ./
COPY _includes ./_includes
COPY lib ./lib
COPY assets ./assets
COPY static ./static
COPY data ./data
COPY content ./content

# If REPO_URL points at a fork, rewrite canonical repo references in content
# markdown (matches the CI approach for forks under a different org). The
# canonical repo skips the sweep — sed over every markdown file is the
# slowest step in the build and would be a no-op.
RUN if [ -n "${REPO_URL}" ]; then \
        OWNER_REPO=$(printf '%s' "${REPO_URL%/}" | sed 's|^https\?://github.com/||') ; \
        if [ "${OWNER_REPO}" != "stevologic/security-recipes.ai" ]; then \
            find content -type f -name "*.md" -exec sed -i \
                -e "s|stevologic/security-recipes.ai|${OWNER_REPO}|g" \
                -e "s|stevologic/agentic-remediation-recipes|${OWNER_REPO}|g" {} + ; \
        fi ; \
    fi

# Build the site. SECURITY_RECIPES_BASE_URL drives canonical URLs, feeds,
# and the path prefix for subpath deploys.
RUN SECURITY_RECIPES_BASE_URL="${BASE_URL}" \
    SECURITY_RECIPES_REPO_URL="${REPO_URL:-https://github.com/stevologic/security-recipes.ai}" \
    npx eleventy \
    && touch public/.nojekyll


# ----- Stage 2 : runtime ----------------------------------------------------
FROM nginx:1.27-alpine AS runtime

LABEL org.opencontainers.image.title="security-recipes.ai" \
      org.opencontainers.image.description="Community-driven recipes for agentic remediation across AI coding tools." \
      org.opencontainers.image.source="https://github.com/stevologic/security-recipes.ai"

# Minimal nginx config — static site, gzip on, SPA-friendly fallbacks off
# (the build outputs real files for every route).
RUN rm /etc/nginx/conf.d/default.conf
COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /src/public /usr/share/nginx/html
COPY scripts/configure_nginx_letsencrypt.sh /opt/security-recipes/scripts/configure_nginx_letsencrypt.sh
COPY README.nginx-letsencrypt.md /opt/security-recipes/README.nginx-letsencrypt.md
RUN chmod 755 /opt/security-recipes/scripts/configure_nginx_letsencrypt.sh

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1
