#!/usr/bin/env bash
# Count findings in SentinelFlow JSON or SARIF reports.
# Safe under `set -e` / `pipefail`: zero matches exits 0 with count 0.
set -euo pipefail

usage() {
  echo "usage: count-findings.sh <json|sarif> <report-file>" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
format="$1"
file="$2"

if [[ ! -f "$file" ]]; then
  echo "0"
  exit 0
fi

pattern=""
case "$format" in
  json) pattern='"severity"' ;;
  sarif) pattern='"ruleId"' ;;
  *) usage ;;
esac

# grep exits 1 on no match; keep the pipeline green under pipefail.
count=$( { grep -o "$pattern" "$file" || true; } | wc -l | tr -d ' ')
echo "${count:-0}"
