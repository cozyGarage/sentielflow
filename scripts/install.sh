#!/usr/bin/env bash
# Install SentinelFlow from GitHub Releases into ./bin (or INSTALL_DIR).
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/cozyGarage/sentielflow/main/scripts/install.sh | bash
#   VERSION=1.0.0 ./scripts/install.sh
set -euo pipefail

REPO="${REPO:-cozyGarage/sentielflow}"
INSTALL_DIR="${INSTALL_DIR:-${PWD}/bin}"
VERSION="${VERSION:-}"

detect_os() {
  case "$(uname -s)" in
    Linux*) echo linux ;;
    Darwin*) echo darwin ;;
    MINGW*|MSYS*|CYGWIN*) echo windows ;;
    *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
  esac
}

if [[ -z "${VERSION}" ]]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name":[[:space:]]*"v\?\([^"]*\)".*/\1/p' \
    | head -n1)"
fi
if [[ -z "${VERSION}" ]]; then
  echo "Could not resolve latest release version. Set VERSION=x.y.z" >&2
  exit 1
fi

OS="$(detect_os)"
ARCH="$(detect_arch)"
EXT="tar.gz"
[[ "${OS}" == "windows" ]] && EXT="zip"

ASSET="sentinelflow_${VERSION}_${OS}_${ARCH}.${EXT}"
URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET}"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "Downloading ${URL}"
curl -fsSL "${URL}" -o "${TMP}/${ASSET}"

mkdir -p "${INSTALL_DIR}"
if [[ "${EXT}" == "zip" ]]; then
  if command -v unzip >/dev/null 2>&1; then
    unzip -qo "${TMP}/${ASSET}" -d "${TMP}/extract"
  else
    echo "unzip is required for Windows archives" >&2
    exit 1
  fi
else
  mkdir -p "${TMP}/extract"
  tar -xzf "${TMP}/${ASSET}" -C "${TMP}/extract"
fi

BIN_SRC="$(find "${TMP}/extract" -type f \( -name sentinelflow -o -name sentinelflow.exe \) | head -n1)"
if [[ -z "${BIN_SRC}" ]]; then
  echo "sentinelflow binary not found in archive" >&2
  exit 1
fi

BIN_NAME="$(basename "${BIN_SRC}")"
install -m 0755 "${BIN_SRC}" "${INSTALL_DIR}/${BIN_NAME}"
echo "Installed ${INSTALL_DIR}/${BIN_NAME}"
"${INSTALL_DIR}/${BIN_NAME}" version || true
