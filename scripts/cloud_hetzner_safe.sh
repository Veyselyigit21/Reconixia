#!/usr/bin/env bash
set -euo pipefail

TARGET=""
PROFILE="balanced"
SCOPE=""
IDENTITY=""
SSH_KEY=""
PASSTHROUGH=()

usage() {
  cat <<'EOF'
Usage:
  HETZNER_TOKEN=... ./scripts/cloud_hetzner_safe.sh -t hedef.com --ssh-key KEY_NAME [options]

This wrapper validates input before delegating to cloud_hetzner_worker.sh.
It exists to keep preflight logic separate from cloud lifecycle logic.
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/preflight.sh"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="${2:-}"; PASSTHROUGH+=("$1" "$2"); shift 2 ;;
    --ssh-key) SSH_KEY="${2:-}"; PASSTHROUGH+=("$1" "$2"); shift 2 ;;
    -i|--identity) IDENTITY="${2:-}"; PASSTHROUGH+=("$1" "$2"); shift 2 ;;
    -p|--profile) PROFILE="${2:-balanced}"; PASSTHROUGH+=("$1" "$2"); shift 2 ;;
    -s|--scope) SCOPE="${2:-}"; PASSTHROUGH+=("$1" "$2"); shift 2 ;;
    --location|--type|--image) PASSTHROUGH+=("$1" "${2:-}"); shift 2 ;;
    --with-nuclei) PASSTHROUGH+=("$1"); shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${HETZNER_TOKEN:-}" ]]; then
  rx_error "HETZNER_TOKEN env var required"
  exit 1
fi
if [[ -z "$SSH_KEY" ]]; then
  rx_error "Hetzner ssh-key is required"
  exit 1
fi

TARGET_NORMALIZED="$(rx_validate_target "$TARGET")"
rx_validate_profile "$PROFILE"
rx_validate_scope_optional "$SCOPE"
rx_validate_identity_optional "$IDENTITY"
rx_require_cmd curl
rx_require_cmd python3
rx_require_cmd ssh
rx_require_cmd scp
rx_require_file "$ROOT_DIR/scripts/cloud_hetzner_worker.sh" "Hetzner worker script"
rx_require_file "$ROOT_DIR/scripts/remote_existing.sh" "existing VPS worker script"

chmod +x "$ROOT_DIR/scripts/cloud_hetzner_worker.sh" "$ROOT_DIR/scripts/remote_existing.sh"

echo "[preflight] Hetzner worker input validated for target: $TARGET_NORMALIZED"
exec "$ROOT_DIR/scripts/cloud_hetzner_worker.sh" "${PASSTHROUGH[@]}"
