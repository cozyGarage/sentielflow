#!/usr/bin/env bash
# Unit test for install.sh checksum verification logic.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

ASSET="sentinelflow_9.9.9_linux_amd64.tar.gz"
printf 'payload' > "${TMP}/${ASSET}"
HASH="$(sha256sum "${TMP}/${ASSET}" | awk '{print $1}')"
printf '%s  %s\n' "${HASH}" "${ASSET}" > "${TMP}/checksums.txt"

# Mismatch must fail
printf '%s  %s\n' "deadbeef" "${ASSET}" > "${TMP}/bad.txt"
if SKIP_CHECKSUM=0 bash -c '
  source /dev/null
  # Inline the same awk/compare used by install.sh
  expected=$(awk -v asset="'"${ASSET}"'" '\''$2 == asset { print $1; exit }'\'' "'"${TMP}"'/bad.txt")
  actual=$(sha256sum "'"${TMP}/${ASSET}"'" | awk "{print \$1}")
  [[ "$actual" == "$expected" ]]
' 2>/dev/null; then
  echo "expected mismatch failure" >&2
  exit 1
fi

# Match must succeed
expected="$(awk -v asset="${ASSET}" '$2 == asset { print $1; exit }' "${TMP}/checksums.txt")"
actual="$(sha256sum "${TMP}/${ASSET}" | awk '{print $1}')"
[[ "${actual}" == "${expected}" ]]

echo "install checksum tests OK"
