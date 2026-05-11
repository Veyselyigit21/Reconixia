#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Reconixia Project Status"
echo "========================"

echo
printf "%-32s %s\n" "go.mod" "$(test -f go.mod && echo OK || echo MISSING)"
printf "%-32s %s\n" "cmd/reconixia-v06" "$(test -d cmd/reconixia-v06 && echo OK || echo MISSING)"
printf "%-32s %s\n" "cmd/reconixia-report" "$(test -d cmd/reconixia-report && echo OK || echo MISSING)"
printf "%-32s %s\n" "cmd/reconixia-augment" "$(test -d cmd/reconixia-augment && echo OK || echo MISSING)"
printf "%-32s %s\n" "cmd/reconixia-diff" "$(test -d cmd/reconixia-diff && echo OK || echo MISSING)"
printf "%-32s %s\n" "cmd/reconixia-ai-structured" "$(test -d cmd/reconixia-ai-structured && echo OK || echo MISSING)"

echo
printf "%-32s %s\n" "internal/safety" "$(test -d internal/safety && echo OK || echo MISSING)"
printf "%-32s %s\n" "internal/checkpoint" "$(test -d internal/checkpoint && echo OK || echo MISSING)"
printf "%-32s %s\n" "internal/secrets" "$(test -d internal/secrets && echo OK || echo MISSING)"
printf "%-32s %s\n" "internal/aianalysis" "$(test -d internal/aianalysis && echo OK || echo MISSING)"
printf "%-32s %s\n" "internal/runtimectx" "$(test -d internal/runtimectx && echo OK || echo MISSING)"
printf "%-32s %s\n" "internal/tools" "$(test -d internal/tools && echo OK || echo MISSING)"
printf "%-32s %s\n" "internal/cloudsafe" "$(test -d internal/cloudsafe && echo OK || echo MISSING)"
printf "%-32s %s\n" "internal/modules" "$(test -d internal/modules && echo OK || echo MISSING)"

echo
printf "%-32s %s\n" "full_scan.sh" "$(test -f scripts/full_scan.sh && echo OK || echo MISSING)"
printf "%-32s %s\n" "full_scan_resume.sh" "$(test -f scripts/full_scan_resume.sh && echo OK || echo MISSING)"
printf "%-32s %s\n" "module_naabu.sh" "$(test -f scripts/module_naabu.sh && echo OK || echo MISSING)"
printf "%-32s %s\n" "module_gowitness.sh" "$(test -f scripts/module_gowitness.sh && echo OK || echo MISSING)"
printf "%-32s %s\n" "module_params.sh" "$(test -f scripts/module_params.sh && echo OK || echo MISSING)"
printf "%-32s %s\n" "module_403_candidates.sh" "$(test -f scripts/module_403_candidates.sh && echo OK || echo MISSING)"
printf "%-32s %s\n" "ci_local.sh" "$(test -f scripts/ci_local.sh && echo OK || echo MISSING)"

echo
if command -v go >/dev/null 2>&1; then
  echo "Go: $(go version)"
else
  echo "Go: MISSING"
fi

echo
for bin in subfinder httpx nuclei gau naabu gowitness; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf "%-12s %s\n" "$bin" OK
  else
    printf "%-12s %s\n" "$bin" OPTIONAL_MISSING
  fi
done

echo
echo "Suggested checks:"
echo "  make status"
echo "  make ci"
echo "  make build"
echo "  go test ./..."
echo "  make validate TARGET=example.com"
