#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-all}"
case "$MODE" in
  web|android|ios|all) ;;
  *) echo "usage: $0 [web|android|ios|all]" >&2; exit 2 ;;
esac

BIN_DIR="${HOME}/.local/bin"
TOOLS_DIR="${HOME}/.local/share/minly-audit-tools"
mkdir -p "$BIN_DIR" "$TOOLS_DIR"
export PATH="${BIN_DIR}:${PATH}"

checksum_verify() {
  local expected="$1" file="$2" actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  fi
  if [ "${actual,,}" != "${expected,,}" ]; then
    echo "SHA-256 mismatch for $file: expected=$expected actual=$actual" >&2
    exit 3
  fi
}

install_jadx() {
  local version="1.5.6"
  local expected="545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"
  local zip="${RUNNER_TEMP:-/tmp}/jadx-${version}.zip"
  local root="${TOOLS_DIR}/jadx-${version}"
  if [ ! -x "${root}/bin/jadx" ]; then
    curl --fail --silent --show-error --location \
      "https://github.com/skylot/jadx/releases/download/v${version}/jadx-${version}.zip" \
      --output "$zip"
    checksum_verify "$expected" "$zip"
    rm -rf "$root"
    mkdir -p "$root"
    unzip -q "$zip" -d "$root"
    rm -f "$zip"
  fi
  ln -sf "${root}/bin/jadx" "${BIN_DIR}/jadx"
}

install_gitleaks() {
  local version="8.30.1" os arch asset expected tgz
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os/$arch" in
    Linux/x86_64)
      asset="linux_x64"
      expected="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
      ;;
    Linux/aarch64|Linux/arm64)
      asset="linux_arm64"
      expected="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
      ;;
    Darwin/x86_64)
      asset="darwin_x64"
      expected="dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"
      ;;
    Darwin/arm64)
      asset="darwin_arm64"
      expected="b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
      ;;
    *) echo "unsupported platform for pinned gitleaks: $os/$arch" >&2; exit 4 ;;
  esac
  tgz="${RUNNER_TEMP:-/tmp}/gitleaks-${version}-${asset}.tar.gz"
  if [ ! -x "${BIN_DIR}/gitleaks" ] || ! "${BIN_DIR}/gitleaks" version 2>/dev/null | grep -q "$version"; then
    curl --fail --silent --show-error --location \
      "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_${asset}.tar.gz" \
      --output "$tgz"
    checksum_verify "$expected" "$tgz"
    tar -xzf "$tgz" -C "$BIN_DIR" gitleaks
    chmod 0755 "${BIN_DIR}/gitleaks"
    rm -f "$tgz"
  fi
}

install_retire() {
  local root="${TOOLS_DIR}/retire-js"
  mkdir -p "$root"
  if [ ! -x "${root}/node_modules/.bin/retire" ]; then
    npm install --silent --prefix "$root" 'retire@5.7.0'
  fi
  ln -sf "${root}/node_modules/.bin/retire" "${BIN_DIR}/retire"
}

case "$MODE" in
  web)
    install_gitleaks
    install_retire
    ;;
  android)
    install_jadx
    install_gitleaks
    ;;
  ios)
    install_gitleaks
    ;;
  all)
    install_jadx
    install_gitleaks
    install_retire
    ;;
esac

if command -v jadx >/dev/null 2>&1; then printf 'jadx=%s\n' "$(jadx --version 2>/dev/null | head -1)"; fi
if command -v gitleaks >/dev/null 2>&1; then printf 'gitleaks=%s\n' "$(gitleaks version 2>/dev/null | head -1)"; fi
if command -v retire >/dev/null 2>&1; then printf 'retire=%s\n' "$(retire --version 2>/dev/null | head -1)"; fi
