#!/usr/bin/env bash
set -euo pipefail

PROVIDER=""
DRY_RUN="true"
MAX_AGE_HOURS="6"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/cloud_cleanup.sh --provider digitalocean [--max-age-hours 6] [--apply]
  ./scripts/cloud_cleanup.sh --provider hetzner [--max-age-hours 6] [--apply]

Purpose:
  Lists or deletes old Reconixia temporary workers.

Safety:
  - Default mode is dry-run.
  - Only resources tagged/labeled as Reconixia temporary workers are targeted.
  - Use --apply only after reviewing dry-run output.
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: command not found: $1" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider) PROVIDER="${2:-}"; shift 2 ;;
    --max-age-hours) MAX_AGE_HOURS="${2:-6}"; shift 2 ;;
    --apply) DRY_RUN="false"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$PROVIDER" ]]; then
  echo "error: provider required" >&2
  usage
  exit 1
fi

require_cmd curl
require_cmd python3

case "$PROVIDER" in
  digitalocean)
    if [[ -z "${DIGITALOCEAN_TOKEN:-}" ]]; then
      echo "error: DIGITALOCEAN_TOKEN required" >&2
      exit 1
    fi
    JSON="$(curl -fsS -H "Authorization: Bearer $DIGITALOCEAN_TOKEN" "https://api.digitalocean.com/v2/droplets?tag_name=temporary-worker&per_page=200")"
    python3 - <<PY
import json, datetime, subprocess, os, sys
j=json.loads('''$JSON''')
max_age=int('$MAX_AGE_HOURS')
dry='$DRY_RUN' == 'true'
now=datetime.datetime.now(datetime.timezone.utc)
for d in j.get('droplets', []):
    name=d.get('name','')
    tags=set(d.get('tags') or [])
    if 'reconixia' not in tags or 'temporary-worker' not in tags:
        continue
    created=d.get('created_at','')
    try:
        dt=datetime.datetime.fromisoformat(created.replace('Z','+00:00'))
    except Exception:
        dt=now
    age=(now-dt).total_seconds()/3600
    if age < max_age:
        print(f"KEEP  do:{d['id']} {name} age={age:.1f}h")
        continue
    print(f"DELETE do:{d['id']} {name} age={age:.1f}h" if not dry else f"DRY   do:{d['id']} {name} age={age:.1f}h")
    if not dry:
        subprocess.run(['curl','-fsS','-X','DELETE',f"https://api.digitalocean.com/v2/droplets/{d['id']}",'-H',f"Authorization: Bearer {os.environ['DIGITALOCEAN_TOKEN']}"], check=False)
PY
    ;;
  hetzner)
    if [[ -z "${HETZNER_TOKEN:-}" ]]; then
      echo "error: HETZNER_TOKEN required" >&2
      exit 1
    fi
    JSON="$(curl -fsS -H "Authorization: Bearer $HETZNER_TOKEN" "https://api.hetzner.cloud/v1/servers?label_selector=tool=reconixia,temporary=true")"
    python3 - <<PY
import json, datetime, subprocess, os
j=json.loads('''$JSON''')
max_age=int('$MAX_AGE_HOURS')
dry='$DRY_RUN' == 'true'
now=datetime.datetime.now(datetime.timezone.utc)
for s in j.get('servers', []):
    name=s.get('name','')
    created=s.get('created','')
    try:
        dt=datetime.datetime.fromisoformat(created.replace('Z','+00:00'))
    except Exception:
        dt=now
    age=(now-dt).total_seconds()/3600
    if age < max_age:
        print(f"KEEP  hc:{s['id']} {name} age={age:.1f}h")
        continue
    print(f"DELETE hc:{s['id']} {name} age={age:.1f}h" if not dry else f"DRY   hc:{s['id']} {name} age={age:.1f}h")
    if not dry:
        subprocess.run(['curl','-fsS','-X','DELETE',f"https://api.hetzner.cloud/v1/servers/{s['id']}",'-H',f"Authorization: Bearer {os.environ['HETZNER_TOKEN']}"], check=False)
PY
    ;;
  *)
    echo "error: unknown provider: $PROVIDER" >&2
    exit 1
    ;;
esac
