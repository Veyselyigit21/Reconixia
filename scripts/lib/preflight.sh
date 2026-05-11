#!/usr/bin/env bash
# Shared preflight validation helpers for Reconixia scripts.
# Source this file from scripts; do not execute directly.

set -euo pipefail

rx_error() {
  echo "error: $*" >&2
}

rx_warn() {
  echo "warning: $*" >&2
}

rx_require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    rx_error "required command not found: $cmd"
    return 1
  fi
}

rx_require_file() {
  local path="$1"
  local label="${2:-file}"
  if [[ -z "$path" ]]; then
    rx_error "$label path is empty"
    return 1
  fi
  if [[ ! -f "$path" ]]; then
    rx_error "$label not found: $path"
    return 1
  fi
}

rx_require_executable() {
  local path="$1"
  if [[ ! -x "$path" ]]; then
    rx_error "executable not found or not executable: $path"
    return 1
  fi
}

rx_validate_target() {
  local raw="$1"
  if [[ -z "$raw" ]]; then
    rx_error "target is required"
    return 1
  fi

  local target="$raw"
  target="${target#http://}"
  target="${target#https://}"
  target="${target%%/*}"
  target="${target%%:*}"

  if [[ -z "$target" ]]; then
    rx_error "target became empty after normalization: $raw"
    return 1
  fi

  if [[ "$target" =~ [[:space:]] ]]; then
    rx_error "target contains whitespace: $raw"
    return 1
  fi

  if [[ "$target" =~ [\;\|\&\`\$\(\)\{\}\[\]\<\>\"\'] ]]; then
    rx_error "target contains unsafe shell character: $raw"
    return 1
  fi

  if [[ ! "$target" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]; then
    rx_error "target is not a valid hostname: $raw"
    return 1
  fi

  echo "$target"
}

rx_validate_profile() {
  local profile="$1"
  case "$profile" in
    stealth|balanced|fast) return 0 ;;
    *) rx_error "invalid profile: $profile. Use stealth, balanced or fast"; return 1 ;;
  esac
}

rx_validate_scope_optional() {
  local scope="${1:-}"
  if [[ -n "$scope" && ! -f "$scope" ]]; then
    rx_error "scope file not found: $scope"
    return 1
  fi
}

rx_validate_identity_optional() {
  local identity="${1:-}"
  if [[ -n "$identity" ]]; then
    if [[ ! -f "$identity" ]]; then
      rx_error "SSH identity file not found: $identity"
      return 1
    fi
    chmod 600 "$identity" >/dev/null 2>&1 || true
  fi
}

rx_safe_result_dir() {
  local prefix="$1"
  local target="$2"
  local stamp="$3"
  echo "results/${prefix}-${target}-${stamp}"
}

rx_confirm_or_exit() {
  local prompt="$1"
  local answer=""
  read -r -p "$prompt [y/N]: " answer || true
  case "$answer" in
    y|Y|yes|YES|evet|EVET|e|E) return 0 ;;
    *) echo "cancelled"; exit 1 ;;
  esac
}
