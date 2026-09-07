#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib/preflight.sh"

SCAN_TARGET=""
SCAN_PROFILE="balanced"
SCAN_SCOPE=""
SCAN_NUCLEI="hayir"
SCAN_RESET="hayir"
SCAN_H1_USER=""

require_scripts() {
  chmod +x \
    scripts/install_tools.sh \
    scripts/build_all.sh \
    scripts/full_scan.sh \
    scripts/full_scan_resume.sh \
    scripts/snapshot.sh \
    scripts/remote_existing.sh \
    scripts/cloud_do_worker.sh \
    scripts/cloud_hetzner_worker.sh \
    scripts/cloud_do_safe.sh \
    scripts/cloud_hetzner_safe.sh \
    scripts/cloud_cleanup.sh \
    scripts/module_naabu.sh \
    scripts/module_gowitness.sh \
    scripts/module_params.sh \
    scripts/module_403_candidates.sh \
    scripts/validate_setup.sh \
    scripts/project_status.sh
}

ask() {
  local prompt="$1"
  local default="${2:-}"
  local value
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " value || true
    echo "${value:-$default}"
  else
    read -r -p "$prompt: " value || true
    echo "$value"
  fi
}

is_yes() {
  local value="${1:-}"
  case "$value" in
    evet|e|E|yes|y|Y) return 0 ;;
    *) return 1 ;;
  esac
}

pause() {
  echo
  read -r -p "Devam etmek icin Enter..." _ || true
}

build_if_needed() {
  require_scripts
  if [[ ! -x ./reconixia || ! -x ./reconixia-augment || ! -x ./reconixia-report || ! -x ./reconixia-diff || ! -x ./reconixia-ai-structured ]]; then
    echo "[i] Binary dosyalar yok, build ediliyor..."
    ./scripts/build_all.sh
  fi
}

install_build_doctor() {
  require_scripts
  ./scripts/install_tools.sh
  ./scripts/build_all.sh
  ./scripts/validate_setup.sh || true
}

prompt_scan_base() {
  local default_profile="$1"
  local default_nuclei="$2"
  local default_reset="$3"
  local target

  target="$(ask "Hedef domain")"
  [[ -z "$target" ]] && echo "Hedef bos olamaz" && return 1
  SCAN_TARGET="$(rx_validate_target "$target")"

  SCAN_PROFILE="$(ask "Profil: stealth/balanced/fast" "$default_profile")"
  rx_validate_profile "$SCAN_PROFILE"

  SCAN_SCOPE="$(ask "Scope dosyasi yolu, yoksa bos birak")"
  rx_validate_scope_optional "$SCAN_SCOPE"

  SCAN_NUCLEI="$(ask "Nuclei calissin mi? evet/hayir" "$default_nuclei")"
  SCAN_RESET="$(ask "Resume checkpoint sifirlansin mi? evet/hayir" "$default_reset")"
  SCAN_H1_USER="$(ask "HackerOne username header icin, yoksa bos birak" "${RECONIXIA_H1_USERNAME:-}")"
}

run_full_scan_resume() {
  build_if_needed
  local args=(-t "$SCAN_TARGET" -p "$SCAN_PROFILE")
  [[ -n "$SCAN_SCOPE" ]] && args+=(-s "$SCAN_SCOPE")
  if ! is_yes "$SCAN_NUCLEI"; then
    args+=(--no-nuclei)
  fi
  if is_yes "$SCAN_RESET"; then
    args+=(--reset)
  fi
  [[ -n "$SCAN_H1_USER" ]] && args+=(--h1-user "$SCAN_H1_USER")
  ./scripts/full_scan_resume.sh "${args[@]}"
}

quick_scan() {
  echo
  echo "Quick scan: stealth profil, nuclei kapali, resume acik."
  prompt_scan_base "stealth" "hayir" "hayir" || return
  run_full_scan_resume
}

standard_full_scan() {
  echo
  echo "Standard full scan: balanced profil, resume acik, HTML rapor uretir."
  prompt_scan_base "balanced" "hayir" "hayir" || return
  run_full_scan_resume
}

run_ports() {
  local target="$1"
  local rate top_ports
  rate="$(ask "Naabu rate" "50")"
  top_ports="$(ask "Top ports" "1000")"
  ./scripts/module_naabu.sh -t "$target" --rate "$rate" --top-ports "$top_ports"
}

run_screenshots() {
  local target="$1"
  local timeout
  timeout="$(ask "Screenshot timeout" "10")"
  ./scripts/module_gowitness.sh -t "$target" --timeout "$timeout"
}

run_params() {
  local target="$1"
  local limit
  limit="$(ask "Param URL limit" "500")"
  ./scripts/module_params.sh -t "$target" --limit "$limit"
}

run_403_candidates() {
  local target="$1"
  local limit
  limit="$(ask "403 candidate limit" "200")"
  ./scripts/module_403_candidates.sh -t "$target" --limit "$limit"
}

run_structured_ai() {
  local target="$1"
  build_if_needed
  ./reconixia-ai-structured -target "$target"
}

run_provider_ai() {
  local target="$1"
  local provider model
  build_if_needed
  provider="$(ask "AI provider: local/openrouter/openai/deepseek" "${RECONIXIA_AI_PROVIDER:-openrouter}")"
  model="$(ask "Model, default icin bos birak" "${OPENROUTER_MODEL:-}")"
  local args=(analyze -target "$target" -provider "$provider")
  [[ -n "$model" ]] && args+=(-model "$model")
  ./reconixia "${args[@]}"
}

optional_modules_menu() {
  require_scripts
  local target choice
  target="$(ask "Mevcut results hedefi")"
  [[ -z "$target" ]] && echo "Hedef bos olamaz" && return
  target="$(rx_validate_target "$target")"

  while true; do
    cat <<'EOF'

Opsiyonel Modul Menusu
======================
1) Passive params
2) 401/403 candidates
3) Structured local AI
4) Screenshots
5) Ports
6) Passive triage paketi (params + 403 + structured AI)
7) Bounty paketi (params + 403 + screenshots + ports + structured AI)
8) Provider AI analizi
0) Geri
EOF
    choice="$(ask "Secim")"
    case "$choice" in
      1) run_params "$target"; pause ;;
      2) run_403_candidates "$target"; pause ;;
      3) run_structured_ai "$target"; pause ;;
      4) run_screenshots "$target"; pause ;;
      5) run_ports "$target"; pause ;;
      6) run_params "$target"; run_403_candidates "$target"; run_structured_ai "$target"; pause ;;
      7) run_params "$target"; run_403_candidates "$target"; run_screenshots "$target"; run_ports "$target"; run_structured_ai "$target"; pause ;;
      8) run_provider_ai "$target"; pause ;;
      0) return ;;
      *) echo "Gecersiz secim"; pause ;;
    esac
  done
}

bounty_workflow() {
  echo
  echo "Bounty workflow: full scan resume + triage modulleri."
  prompt_scan_base "balanced" "hayir" "hayir" || return
  run_full_scan_resume

  echo
  if is_yes "$(ask "Passive triage modulleri calissin mi? params + 403 + structured AI" "evet")"; then
    run_params "$SCAN_TARGET"
    run_403_candidates "$SCAN_TARGET"
    run_structured_ai "$SCAN_TARGET"
  fi
  if is_yes "$(ask "Screenshots calissin mi? live hedeflere browser istegi atar" "evet")"; then
    run_screenshots "$SCAN_TARGET"
  fi
  if is_yes "$(ask "Port scan calissin mi? daha aktif/noisy olabilir" "hayir")"; then
    run_ports "$SCAN_TARGET"
  fi
  if is_yes "$(ask "OpenRouter/OpenAI/DeepSeek provider AI analizi calissin mi?" "hayir")"; then
    run_provider_ai "$SCAN_TARGET"
  fi
}

existing_vps_scan() {
  require_scripts
  local host user identity target profile scope nuclei known_hosts strict accept args
  host="$(ask "VPS IP/hostname")"
  [[ -z "$host" ]] && echo "Host bos olamaz" && return
  user="$(ask "SSH kullanici" "root")"
  identity="$(ask "SSH private key yolu, yoksa bos birak")"
  rx_validate_identity_optional "$identity"
  target="$(rx_validate_target "$(ask "Hedef domain")")"
  profile="$(ask "Profil: stealth/balanced/fast" "balanced")"
  rx_validate_profile "$profile"
  scope="$(ask "Scope dosyasi yolu, yoksa bos birak")"
  rx_validate_scope_optional "$scope"
  nuclei="$(ask "Nuclei calissin mi? evet/hayir" "hayir")"
  known_hosts="$(ask "known_hosts dosyasi" ".reconixia_known_hosts")"
  strict="$(ask "Strict host key? yes/no" "yes")"
  accept="$(ask "Yeni host key otomatik kabul edilsin mi? ephemeral degilse hayir onerilir" "hayir")"

  args=(--host "$host" --user "$user" -t "$target" -p "$profile" --known-hosts "$known_hosts" --strict-host-key "$strict")
  [[ -n "$identity" ]] && args+=(--identity "$identity")
  [[ -n "$scope" ]] && args+=(-s "$scope")
  is_yes "$nuclei" && args+=(--with-nuclei)
  is_yes "$accept" && args+=(--accept-host-key)
  ./scripts/remote_existing.sh "${args[@]}"
}

digitalocean_scan() {
  require_scripts
  local token target ssh_key identity profile scope region size image ssh_cidr nuclei args
  token="${DIGITALOCEAN_TOKEN:-}"
  if [[ -z "$token" ]]; then
    token="$(ask "DigitalOcean token")"
    [[ -z "$token" ]] && echo "Token bos olamaz" && return
    export DIGITALOCEAN_TOKEN="$token"
  fi
  target="$(rx_validate_target "$(ask "Hedef domain")")"
  ssh_key="$(ask "DigitalOcean SSH key ID/fingerprint")"
  [[ -z "$ssh_key" ]] && echo "SSH key ID bos olamaz" && return
  identity="$(ask "SSH private key yolu, yoksa bos birak")"
  rx_validate_identity_optional "$identity"
  profile="$(ask "Profil: stealth/balanced/fast" "balanced")"
  rx_validate_profile "$profile"
  scope="$(ask "Scope dosyasi yolu, yoksa bos birak")"
  rx_validate_scope_optional "$scope"
  region="$(ask "Region" "fra1")"
  size="$(ask "Size" "s-1vcpu-1gb")"
  image="$(ask "Image" "ubuntu-24-04-x64")"
  ssh_cidr="$(ask "SSH izinli CIDR, otomatik icin bos birak")"
  nuclei="$(ask "Nuclei calissin mi? evet/hayir" "hayir")"

  args=(-t "$target" --ssh-key-id "$ssh_key" -p "$profile" --region "$region" --size "$size" --image "$image")
  [[ -n "$identity" ]] && args+=(-i "$identity")
  [[ -n "$scope" ]] && args+=(-s "$scope")
  [[ -n "$ssh_cidr" ]] && args+=(--ssh-cidr "$ssh_cidr")
  is_yes "$nuclei" && args+=(--with-nuclei)
  ./scripts/cloud_do_safe.sh "${args[@]}"
}

hetzner_scan() {
  require_scripts
  local token target ssh_key identity profile scope location server_type image ssh_cidr nuclei args
  token="${HETZNER_TOKEN:-}"
  if [[ -z "$token" ]]; then
    token="$(ask "Hetzner token")"
    [[ -z "$token" ]] && echo "Token bos olamaz" && return
    export HETZNER_TOKEN="$token"
  fi
  target="$(rx_validate_target "$(ask "Hedef domain")")"
  ssh_key="$(ask "Hetzner SSH key name/id")"
  [[ -z "$ssh_key" ]] && echo "SSH key bos olamaz" && return
  identity="$(ask "SSH private key yolu, yoksa bos birak")"
  rx_validate_identity_optional "$identity"
  profile="$(ask "Profil: stealth/balanced/fast" "balanced")"
  rx_validate_profile "$profile"
  scope="$(ask "Scope dosyasi yolu, yoksa bos birak")"
  rx_validate_scope_optional "$scope"
  location="$(ask "Location" "fsn1")"
  server_type="$(ask "Server type" "cx22")"
  image="$(ask "Image" "ubuntu-24.04")"
  ssh_cidr="$(ask "SSH izinli CIDR, otomatik icin bos birak")"
  nuclei="$(ask "Nuclei calissin mi? evet/hayir" "hayir")"

  args=(-t "$target" --ssh-key "$ssh_key" -p "$profile" --location "$location" --type "$server_type" --image "$image")
  [[ -n "$identity" ]] && args+=(-i "$identity")
  [[ -n "$scope" ]] && args+=(-s "$scope")
  [[ -n "$ssh_cidr" ]] && args+=(--ssh-cidr "$ssh_cidr")
  is_yes "$nuclei" && args+=(--with-nuclei)
  ./scripts/cloud_hetzner_safe.sh "${args[@]}"
}

cloud_menu() {
  local choice
  while true; do
    cat <<'EOF'

Remote / Cloud Menusu
=====================
1) Mevcut VPS uzerinde tara
2) DigitalOcean gecici worker
3) Hetzner gecici worker
4) Cloud worker cleanup
0) Geri
EOF
    choice="$(ask "Secim")"
    case "$choice" in
      1) existing_vps_scan; pause ;;
      2) digitalocean_scan; pause ;;
      3) hetzner_scan; pause ;;
      4) cloud_cleanup; pause ;;
      0) return ;;
      *) echo "Gecersiz secim"; pause ;;
    esac
  done
}

cloud_cleanup() {
  require_scripts
  local provider token age apply args
  provider="$(ask "Provider: digitalocean/hetzner" "digitalocean")"
  age="$(ask "Kac saatten eski workerlar listelensin/silinsin" "6")"
  apply="$(ask "Gercekten silinsin mi? evet/hayir" "hayir")"

  case "$provider" in
    digitalocean)
      token="${DIGITALOCEAN_TOKEN:-}"
      if [[ -z "$token" ]]; then
        token="$(ask "DigitalOcean token")"
        [[ -z "$token" ]] && echo "Token bos olamaz" && return
        export DIGITALOCEAN_TOKEN="$token"
      fi
      args=(--provider digitalocean --max-age-hours "$age")
      ;;
    hetzner)
      token="${HETZNER_TOKEN:-}"
      if [[ -z "$token" ]]; then
        token="$(ask "Hetzner token")"
        [[ -z "$token" ]] && echo "Token bos olamaz" && return
        export HETZNER_TOKEN="$token"
      fi
      args=(--provider hetzner --max-age-hours "$age")
      ;;
    *)
      echo "Gecersiz provider"
      return
      ;;
  esac

  is_yes "$apply" && args+=(--apply)
  ./scripts/cloud_cleanup.sh "${args[@]}"
}

snapshot_result() {
  require_scripts
  local target label args
  target="$(rx_validate_target "$(ask "Snapshot alinacak hedef")")"
  label="$(ask "Etiket, yoksa bos birak")"
  args=(-t "$target")
  [[ -n "$label" ]] && args+=(-l "$label")
  ./scripts/snapshot.sh "${args[@]}"
}

diff_reports() {
  build_if_needed
  local old_report new_report html output args
  old_report="$(ask "Eski report.json yolu")"
  new_report="$(ask "Yeni report.json yolu")"
  [[ -z "$old_report" || -z "$new_report" ]] && echo "Iki report yolu da gerekli" && return
  html="$(ask "HTML diff uretilecek mi? evet/hayir" "evet")"
  args=(-old "$old_report" -new "$new_report")
  if is_yes "$html"; then
    output="$(ask "HTML output" "diff.html")"
    args+=(-html -output "$output")
  fi
  ./reconixia-diff "${args[@]}"
}

snapshot_diff_menu() {
  local choice
  while true; do
    cat <<'EOF'

Snapshot / Diff Menusu
======================
1) Snapshot al
2) Iki report.json diff
0) Geri
EOF
    choice="$(ask "Secim")"
    case "$choice" in
      1) snapshot_result; pause ;;
      2) diff_reports; pause ;;
      0) return ;;
      *) echo "Gecersiz secim"; pause ;;
    esac
  done
}

ai_menu() {
  local target choice
  target="$(ask "Hedef domain")"
  [[ -z "$target" ]] && echo "Hedef bos olamaz" && return
  target="$(rx_validate_target "$target")"
  while true; do
    cat <<'EOF'

AI Menusu
=========
1) Local structured AI
2) Provider AI (OpenRouter/OpenAI/DeepSeek)
0) Geri
EOF
    choice="$(ask "Secim")"
    case "$choice" in
      1) run_structured_ai "$target"; pause ;;
      2) run_provider_ai "$target"; pause ;;
      0) return ;;
      *) echo "Gecersiz secim"; pause ;;
    esac
  done
}

show_status() {
  require_scripts
  ./scripts/validate_setup.sh || true
  ./scripts/project_status.sh || true
}

while true; do
  clear || true
  cat <<'EOF'
Reconixia Otomasyon Menusu
==========================
1) Hazirlik: install + build + doctor
2) Quick scan (stealth, resume, no nuclei)
3) Standard full scan (balanced, resume)
4) Bug bounty workflow (full scan + triage modulleri)
5) Mevcut sonuca opsiyonel modul calistir
6) AI analizi
7) Snapshot / diff
8) Remote / cloud scan
9) Validate / proje durumu
0) Cikis
EOF
  choice="$(ask "Secim")"
  case "$choice" in
    1) install_build_doctor; pause ;;
    2) quick_scan; pause ;;
    3) standard_full_scan; pause ;;
    4) bounty_workflow; pause ;;
    5) optional_modules_menu; pause ;;
    6) ai_menu; pause ;;
    7) snapshot_diff_menu; pause ;;
    8) cloud_menu; pause ;;
    9) show_status; pause ;;
    0) exit 0 ;;
    *) echo "Gecersiz secim"; pause ;;
  esac
done
