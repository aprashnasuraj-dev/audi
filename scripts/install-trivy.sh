#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${REPO_ROOT}/config/tool-versions.yml"
CACHE_DIR="${HALO_TOOL_CACHE:-${HOME}/.cache/halo-tools}"
BIN_DIR="${HALO_TOOL_BIN:-${HOME}/.local/bin}"

mkdir -p "${CACHE_DIR}" "${BIN_DIR}"

read_field() {
  local key="$1"
  python3 - "${key}" "${CONFIG}" <<'PY'
import sys, yaml
key, path = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    data = yaml.safe_load(fh) or {}
entry = (data.get("tools") or {}).get("trivy") or {}
value = entry.get(key)
if value is None:
    raise SystemExit(f"missing trivy.{key} in {path}")
print(value)
PY
}

version="$(read_field version)"
platform="$(read_field platform)"
checksums_sha="$(read_field checksums_sha256)"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64|Linux/amd64) ;;
  *) echo "install-trivy: unsupported platform $(uname -s)/$(uname -m); configure an explicit pinned artifact" >&2; exit 2 ;;
esac

base="https://github.com/aquasecurity/trivy/releases/download/v${version}"
checksums="trivy_${version}_checksums.txt"
archive="trivy_${version}_${platform}.tar.gz"
checksums_path="${CACHE_DIR}/${checksums}"
archive_path="${CACHE_DIR}/${archive}"

fetch_if_missing() {
  local url="$1" dest="$2"
  if [ ! -f "${dest}" ]; then
    curl --fail --location --silent --show-error --output "${dest}.partial" "${url}"
    mv "${dest}.partial" "${dest}"
  fi
}

fetch_if_missing "${base}/${checksums}" "${checksums_path}"
printf '%s  %s\n' "${checksums_sha}" "${checksums_path}" | sha256sum -c -

fetch_if_missing "${base}/${archive}" "${archive_path}"
expected="$(awk -v name="${archive}" '$2 == name {print $1}' "${checksums_path}")"
if [ -z "${expected}" ]; then
  echo "install-trivy: ${archive} not present in verified checksum manifest" >&2
  exit 1
fi
printf '%s  %s\n' "${expected}" "${archive_path}" | sha256sum -c -

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT
tar -xzf "${archive_path}" -C "${workdir}" trivy
install -m 0755 "${workdir}/trivy" "${BIN_DIR}/trivy"
"${BIN_DIR}/trivy" --version
