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

SCAN_ARGS=(
  --secrets --iac --sast
  --config "${DEMO_DIR}/.sentinelflow.yaml"
  "${DEMO_DIR}"
)

set +e
"${BIN}" scan --format text "${SCAN_ARGS[@]}"
TEXT_RC=$?
set -e

for fmt in markdown html sarif; do
  ext="${fmt}"
  [[ "${fmt}" == "markdown" ]] && ext="md"
  set +e
  "${BIN}" scan --format "${fmt}" -o "${OUT_DIR}/report.${ext}" "${SCAN_ARGS[@]}" >/dev/null 2>&1
  set -e
done

echo ""
if [[ "${TEXT_RC}" -ne 0 ]]; then
  echo "Demo gate failed as expected (exit ${TEXT_RC}) — intentional findings in examples/demo-project."
fi
echo "Reports written to ${OUT_DIR}/"
echo "  - report.md"
echo "  - report.html"
echo "  - report.sarif"
echo ""
echo "Open the HTML report:"
echo "  open ${OUT_DIR}/report.html        # macOS"
echo "  xdg-open ${OUT_DIR}/report.html    # Linux"
echo ""

# Demo exits 0 so make demo is convenient; findings are expected.
exit 0
