#!/usr/bin/env bash
# CI gate: run PRO red-team scan, fail if risk score exceeds threshold.
# Usage: ci/redteam_ci.sh [BASE_URL] [API_KEY] [MODEL] [MAX_RISK] [REPORT_OUT]
set -euo pipefail

# repo root = parent of this script's dir
cd "$(dirname "$0")/.."

BASE_URL="${1:-}"
API_KEY="${2:-}"
MODEL="${3:-gpt-4o-mini}"
MAX_RISK="${4:-60}"
REPORT_OUT="${5:-redteam-pro-report.md}"

PY="${PYTHON:-python3}"

if [ -z "$BASE_URL" ]; then
  echo "[ci] no BASE_URL -> running --demo (offline self-check)"
  "$PY" -m redteam --demo --pro --max-risk "$MAX_RISK" --report "$REPORT_OUT"
else
  echo "[ci] live scan: $BASE_URL ($MODEL), max_risk=$MAX_RISK"
  "$PY" -m redteam --base-url "$BASE_URL" --api-key "$API_KEY" --model "$MODEL" \
    --pro --max-risk "$MAX_RISK" --report "$REPORT_OUT"
fi

echo "[ci] report: $REPORT_OUT"
echo "[ci] gate PASSED (risk <= $MAX_RISK)"
