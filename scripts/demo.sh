#!/usr/bin/env bash
# Run a local SentinelFlow demo against examples/demo-project.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="${ROOT}/examples/demo-project"
OUT_DIR="${ROOT}/demo-out"
BIN="${ROOT}/sentinelflow"

mkdir -p "${OUT_DIR}"

if [[ ! -x "${BIN}" ]]; then
  echo "Building SentinelFlow..."
  (cd "${ROOT}" && go build -ldflags "-X main.version=demo -X main.commit=local -X main.date=$(date -u +%Y-%m-%d)" -o sentinelflow ./cmd/sentinelflow)
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  SentinelFlow demo — scanning examples/demo-project"
echo "═══════════════════════════════════════════════════"
echo ""

set +e
"${BIN}" scan \
  --secrets --iac --sast \
  --config "${DEMO_DIR}/.sentinelflow.yaml" \
  --format text \
  "${DEMO_DIR}"
TEXT_RC=$?
set -e

"${BIN}" scan \
  --secrets --iac --sast \
  --config "${DEMO_DIR}/.sentinelflow.yaml" \
  --format markdown -o "${OUT_DIR}/report.md" \
  "${DEMO_DIR}" >/dev/null 2>&1 || true

"${BIN}" scan \
  --secrets --iac --sast \
  --config "${DEMO_DIR}/.sentinelflow.yaml" \
  --format html -o "${OUT_DIR}/report.html" \
  "${DEMO_DIR}" >/dev/null 2>&1 || true

"${BIN}" scan \
  --secrets --iac --sast \
  --config "${DEMO_DIR}/.sentinelflow.yaml" \
  --format sarif -o "${OUT_DIR}/report.sarif" \
  "${DEMO_DIR}" >/dev/null 2>&1 || true

echo ""
echo "Reports written to ${OUT_DIR}/"
echo "  - report.md"
echo "  - report.html"
echo "  - report.sarif"
echo ""
echo "Open the HTML report:"
echo "  open ${OUT_DIR}/report.html   # macOS"
echo "  xdg-open ${OUT_DIR}/report.html  # Linux"
echo ""

# Demo exits 0 so make demo is convenient; findings are expected.
exit 0
