#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f scripts/lib/preflight.sh ]]; then
  # shellcheck disable=SC1091
  source scripts/lib/preflight.sh
else
  echo "error: scripts/lib/preflight.sh not found" >&2
  exit 1
fi

TARGET="${1:-}"

ok=0
warn=0
fail=0

check_cmd() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "[OK] command: $cmd"
    ok=$((ok+1))
  else
    echo "[WARN] missing command: $cmd"
    warn=$((warn+1))
  fi
}

check_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    echo "[OK] file: $path"
    ok=$((ok+1))
  else
    echo "[FAIL] missing file: $path"
    fail=$((fail+1))
  fi
}

check_exec_optional() {
  local path="$1"
  if [[ -x "$path" ]]; then
    echo "[OK] executable: $path"
    ok=$((ok+1))
  else
    echo "[WARN] not executable yet: $path"
    warn=$((warn+1))
  fi
}

check_env_optional() {
  local name="$1"
  if [[ -n "${!name:-}" ]]; then
    echo "[OK] env: $name"
    ok=$((ok+1))
  else
    echo "[INFO] optional env not set: $name"
  fi
}

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
  echo "[OK] .env loaded"
else
  echo "[INFO] .env not found; AI/cloud integrations will ask or stay disabled"
fi

echo
printf '%s\n' "== Core commands =="
check_cmd go
check_cmd git
check_cmd tar
check_cmd ssh
check_cmd scp
check_cmd curl
check_cmd python3

echo
printf '%s\n' "== Recon tools =="
check_cmd subfinder
check_cmd httpx
check_cmd nuclei
check_cmd gau

echo
printf '%s\n' "== Project files =="
check_file go.mod
check_file scripts/install_tools.sh
check_file scripts/build_all.sh
check_file scripts/full_scan.sh
check_file scripts/remote_existing.sh
check_file scripts/reconixia_auto.sh
check_file scripts/lib/preflight.sh

echo
printf '%s\n' "== Built binaries =="
check_exec_optional ./reconixia
check_exec_optional ./reconixia-report
check_exec_optional ./reconixia-augment
check_exec_optional ./reconixia-diff

echo
printf '%s\n' "== Optional integrations =="
check_env_optional OPENROUTER_API_KEY
check_env_optional OPENAI_API_KEY
check_env_optional DEEPSEEK_API_KEY
check_env_optional ANTHROPIC_API_KEY
check_env_optional DIGITALOCEAN_TOKEN
check_env_optional HETZNER_TOKEN

if [[ -n "$TARGET" ]]; then
  echo
  printf '%s\n' "== Target validation =="
  if normalized="$(rx_validate_target "$TARGET")"; then
    echo "[OK] target: $normalized"
    ok=$((ok+1))
  else
    echo "[FAIL] invalid target: $TARGET"
    fail=$((fail+1))
  fi
fi

echo
printf '%s\n' "== Summary =="
echo "OK:   $ok"
echo "WARN: $warn"
echo "FAIL: $fail"

if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
