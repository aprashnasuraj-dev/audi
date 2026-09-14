#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="${HOME}/.local/bin"
TOOLS_DIR="${HOME}/.local/share/minly-audit-tools"
mkdir -p "$BIN_DIR" "$TOOLS_DIR"

# JADX 1.5.6 — pinned release and independently published SHA-256.
JADX_VERSION="1.5.6"
JADX_SHA256="545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"
JADX_ZIP="${RUNNER_TEMP:-/tmp}/jadx-${JADX_VERSION}.zip"
JADX_ROOT="${TOOLS_DIR}/jadx-${JADX_VERSION}"
if [ ! -x "${JADX_ROOT}/bin/jadx" ]; then
  curl --fail --silent --show-error --location \
    "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    --output "$JADX_ZIP"
  printf '%s  %s\n' "$JADX_SHA256" "$JADX_ZIP" | sha256sum -c -
  rm -rf "$JADX_ROOT"
  mkdir -p "$JADX_ROOT"
  unzip -q "$JADX_ZIP" -d "$JADX_ROOT"
  rm -f "$JADX_ZIP"
fi
ln -sf "${JADX_ROOT}/bin/jadx" "${BIN_DIR}/jadx"

# Gitleaks 8.30.1 — pinned release and SHA-256. Used only against local, decoded artifacts.
GITLEAKS_VERSION="8.30.1"
GITLEAKS_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
GITLEAKS_TGZ="${RUNNER_TEMP:-/tmp}/gitleaks-${GITLEAKS_VERSION}.tar.gz"
if [ ! -x "${BIN_DIR}/gitleaks" ] || ! "${BIN_DIR}/gitleaks" version 2>/dev/null | grep -q "$GITLEAKS_VERSION"; then
  curl --fail --silent --show-error --location \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    --output "$GITLEAKS_TGZ"
  printf '%s  %s\n' "$GITLEAKS_SHA256" "$GITLEAKS_TGZ" | sha256sum -c -
  tar -xzf "$GITLEAKS_TGZ" -C "$BIN_DIR" gitleaks
  chmod 0755 "${BIN_DIR}/gitleaks"
  rm -f "$GITLEAKS_TGZ"
fi

# Retire.js 5.7.0 — offline client-side dependency context for naturally observed JS only.
RETIRE_ROOT="${TOOLS_DIR}/retire-js"
mkdir -p "$RETIRE_ROOT"
if [ ! -x "${RETIRE_ROOT}/node_modules/.bin/retire" ]; then
  npm install --silent --prefix "$RETIRE_ROOT" 'retire@5.7.0'
fi
ln -sf "${RETIRE_ROOT}/node_modules/.bin/retire" "${BIN_DIR}/retire"

export PATH="${BIN_DIR}:${PATH}"

printf 'jadx=%s\n' "$(jadx --version 2>/dev/null | head -1)"
printf 'gitleaks=%s\n' "$(gitleaks version 2>/dev/null | head -1)"
printf 'retire=%s\n' "$(retire --version 2>/dev/null | head -1)"
