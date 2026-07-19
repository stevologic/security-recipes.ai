#!/bin/sh
set -eu

LOG_FILE="${TRAFFIC_LOG_FILE:-/logs/access.log}"
REPORT_DIR="${TRAFFIC_REPORT_DIR:-/report}"
REPORT_FILE="${REPORT_DIR}/index.html"
HEALTH_FILE="${REPORT_DIR}/.generator-healthy"
PLACEHOLDER_FILE="${TRAFFIC_REPORT_PLACEHOLDER:-/opt/security-recipes/traffic-initializing.html}"
THEME_FILE="${TRAFFIC_REPORT_THEME:-/opt/security-recipes/traffic-theme.css}"
THEME_NAME="${TRAFFIC_REPORT_THEME_NAME:-traffic-theme.css}"
INTERVAL="${TRAFFIC_REPORT_INTERVAL_SECONDS:-60}"

case "${INTERVAL}" in
  ''|*[!0-9]*|0)
    printf 'TRAFFIC_REPORT_INTERVAL_SECONDS must be a positive integer, got: %s\n' "${INTERVAL}" >&2
    exit 1
    ;;
esac

mkdir -p "${REPORT_DIR}"

if [ ! -s "${THEME_FILE}" ]; then
  printf 'Traffic report theme is missing or empty: %s\n' "${THEME_FILE}" >&2
  exit 1
fi

case "${THEME_NAME}" in
  ''|*/*|.*)
    printf 'TRAFFIC_REPORT_THEME_NAME must be a plain visible filename, got: %s\n' "${THEME_NAME}" >&2
    exit 1
    ;;
esac

publish_theme() {
  theme_target="${REPORT_DIR}/${THEME_NAME}"
  theme_next="${REPORT_DIR}/.${THEME_NAME}.$$"
  cp "${THEME_FILE}" "${theme_next}"
  chmod 0644 "${theme_next}"
  mv -f "${theme_next}" "${theme_target}"
}

publish_placeholder() {
  [ -s "${REPORT_FILE}" ] && return 0

  placeholder="${REPORT_DIR}/.index.placeholder.$$"
  cp "${PLACEHOLDER_FILE}" "${placeholder}"
  chmod 0644 "${placeholder}"
  mv -f "${placeholder}" "${REPORT_FILE}"
  printf 'Published the traffic report initialization page.\n'
}

mark_healthy() {
  health_marker="${REPORT_DIR}/.generator-healthy.$$"
  date -u +%Y-%m-%dT%H:%M:%SZ > "${health_marker}"
  chmod 0644 "${health_marker}"
  mv -f "${health_marker}" "${HEALTH_FILE}"
}

generate_report() {
  if [ ! -s "${LOG_FILE}" ]; then
    printf 'Traffic access log is not available yet; retaining the current report.\n'
    mark_healthy
    return 0
  fi

  # GoAccess validates the output extension, so keep .html on the temporary
  # file while still publishing it atomically as the stable index path.
  next_report="${REPORT_DIR}/.index.next.$$.html"
  rm -f "${next_report}"
  rm -f "${HEALTH_FILE}"

  if goaccess "${LOG_FILE}" \
    --log-format=CADDY \
    --anonymize-ip \
    --anonymize-level=3 \
    --no-query-string \
    --ignore-crawlers \
    --ignore-panel=HOSTS \
    --ignore-panel=REFERRERS \
    --ignore-panel=REFERRING_SITES \
    --ignore-panel=KEYPHRASES \
    --ignore-panel=REMOTE_USER \
    --html-report-title='security-recipes.ai traffic' \
    --html-custom-css="${THEME_NAME}" \
    --html-prefs='{"theme":"darkGray","perPage":10,"layout":"wide","showTables":true}' \
    --output="${next_report}"; then
    sed -i \
      's#</head>#<meta name="robots" content="noindex, nofollow, noarchive"></head>#' \
      "${next_report}"
    if ! grep -q 'name="robots" content="noindex, nofollow, noarchive"' "${next_report}"; then
      rm -f "${next_report}"
      printf 'GoAccess report is missing the required noindex metadata.\n' >&2
      return 1
    fi
    chmod 0644 "${next_report}"
    mv -f "${next_report}" "${REPORT_FILE}"
    mark_healthy
    printf 'Published an updated traffic report.\n'
    return 0
  fi

  rm -f "${next_report}"
  printf 'GoAccess could not refresh the traffic report; retaining the last good report.\n' >&2
  return 1
}

publish_theme
publish_placeholder

if [ "${1:-}" = "--once" ]; then
  generate_report
  exit $?
fi

while true; do
  generate_report || true
  sleep "${INTERVAL}"
done
