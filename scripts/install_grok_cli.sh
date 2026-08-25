#!/usr/bin/env bash
# Install a pinned Grok Build CLI release for headless GitHub Actions jobs.
set -euo pipefail

GROK_VERSION="${GROK_CLI_VERSION:-1.0.5}"
export GROK_BIN_DIR="${GROK_BIN_DIR:-${HOME}/.grok/bin}"

curl -fsSL https://x.ai/cli/install.sh | bash -s "${GROK_VERSION}"

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "${GROK_BIN_DIR}" >> "${GITHUB_PATH}"
fi

export PATH="${GROK_BIN_DIR}:${PATH}"

if ! command -v grok >/dev/null 2>&1; then
  echo "Grok CLI did not land on PATH after install (${GROK_BIN_DIR})." >&2
  exit 1
fi

grok --version
