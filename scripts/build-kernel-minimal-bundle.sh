#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_ROOT="${WORKSPACE_ROOT:-$(cd "${ROOT_DIR}/.." && pwd)}"

OUT_DIR="${1:-"${ROOT_DIR}/dist"}"
BUNDLE_NAME="${2:-blackcat-kernel-minimal-bundle}"

TEMPLATE_DIR="${ROOT_DIR}/templates/kernel-minimal"
DEST="${OUT_DIR}/${BUNDLE_NAME}"

CORE_DIR="${WORKSPACE_ROOT}/blackcat-core"
CONFIG_DIR="${WORKSPACE_ROOT}/blackcat-config"

echo "[build] template: ${TEMPLATE_DIR}"
echo "[build] output:   ${DEST}"
echo "[build] core:     ${CORE_DIR}"
echo "[build] config:   ${CONFIG_DIR}"

rm -rf "${DEST}"
mkdir -p "${DEST}"

# Copy template skeleton
cp -R "${TEMPLATE_DIR}/site" "${DEST}/site"
mkdir -p "${DEST}/.blackcat"

if command -v composer >/dev/null 2>&1; then
  echo "[build] running composer install (no-dev) in a temp project..."
  BUILD_DIR="$(mktemp -d)"
  trap 'rm -rf "${BUILD_DIR}"' EXIT

  cat > "${BUILD_DIR}/composer.json" <<JSON
{
  "name": "blackcatacademy/blackcat-kernel-minimal-bundle-build",
  "type": "project",
  "license": "proprietary",
  "require": {
    "blackcatacademy/blackcat-core": "dev-main",
    "blackcatacademy/blackcat-config": "dev-main"
  },
  "repositories": [
    { "type": "path", "url": "${CORE_DIR}", "options": { "symlink": false } },
    { "type": "path", "url": "${CONFIG_DIR}", "options": { "symlink": false } }
  ],
  "config": {
    "optimize-autoloader": true,
    "sort-packages": true
  },
  "minimum-stability": "dev",
  "prefer-stable": true
}
JSON

  (cd "${BUILD_DIR}" && composer install --no-dev --optimize-autoloader --classmap-authoritative)

  rm -rf "${DEST}/site/vendor"
  cp -R "${BUILD_DIR}/vendor" "${DEST}/site/vendor"
else
  echo "[build] composer not found; skipping vendor build."
  echo "[build] You must provide \`site/vendor/\` before uploading the bundle."
fi

if command -v python3 >/dev/null 2>&1; then
  echo "[build] creating zip..."
  (cd "${OUT_DIR}" && python3 -m zipfile -c "${BUNDLE_NAME}.zip" "${BUNDLE_NAME}")
  echo "[build] zip: ${OUT_DIR}/${BUNDLE_NAME}.zip"
else
  echo "[build] python3 not found; skipping zip."
fi

echo "[build] done"
