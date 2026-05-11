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

require_scripts() {
  chmod +x \
    scripts/install_tools.sh \
    scripts/build_all.sh \
    scripts/full_scan.sh \
    scripts/snapshot.sh \
    scripts/remote_existing.sh \
    scripts/cloud_do_worker.sh \
    scripts/cloud_hetzner_worker.sh \
    scripts/cloud_do_safe.sh \
    scripts/cloud_hetzner_safe.sh \
    scripts/cloud_cleanup.sh \
    scripts/validate_setup.sh
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
  [[ "$value" == "evet" || "$value" == "e" || "$value" == "yes" || "$value" == "y" || "$value" == "E" || "$value" == "Y" ]]
}

pause() {
  echo
  read -r -p "Devam etmek için Enter..." _ || true
}

build_if_needed() {
  require_scripts
  if [[ ! -x ./reconixia || ! -x ./reconixia-augment || ! -x ./reconixia-report || ! -x ./reconixia-diff ]]; then
    echo "[i] Binary dosyalar yok, build ediliyor..."
    ./scripts/build_all.sh
  fi
}

install_and_build() {
  require_scripts
  ./scripts/install_tools.sh
  ./scripts/build_all.sh
}

local_scan() {
  build_if_needed
  local target profile scope nuclei
  target="$(ask "Hedef domain")"
  [[ -z "$target" ]] && echo "Hedef boş olamaz" && return
  profile="$(ask "Profil: stealth/balanced/fast" "balanced")"
  scope="$(ask "Scope dosyası yolu, yoksa boş bırak")"
  nuclei="$(ask "Nuclei çalışsın mı? evet/hayır" "hayır")"

  local args=(-t "$target" -p "$profile")
  [[ -n "$scope" ]] && args+=(-s "$scope")
  if ! is_yes "$nuclei"; then
    args+=(--no-nuclei)
  fi
  ./scripts/full_scan.sh "${args[@]}"
}

existing_vps_scan() {
  require_scripts
  local host user identity target profile scope nuclei
  host="$(ask "VPS IP/hostname")"
  [[ -z "$host" ]] && echo "Host boş olamaz" && return
  user="$(ask "SSH kullanıcı" "root")"
  identity="$(ask "SSH private key yolu, yoksa boş bırak")"
  target="$(ask "Hedef domain")"
  [[ -z "$target" ]] && echo "Hedef boş olamaz" && return
  profile="$(ask "Profil: stealth/balanced/fast" "balanced")"
  scope="$(ask "Scope dosyası yolu, yoksa boş bırak")"
  nuclei="$(ask "Nuclei çalışsın mı? evet/hayır" "hayır")"

  local args=(--host "$host" --user "$user" -t "$target" -p "$profile")
  [[ -n "$identity" ]] && args+=(--identity "$identity")
  [[ -n "$scope" ]] && args+=(-s "$scope")
  is_yes "$nuclei" && args+=(--with-nuclei)
  ./scripts/remote_existing.sh "${args[@]}"
}

digitalocean_scan() {
  require_scripts
  local token target ssh_key identity profile scope region size image nuclei
  token="${DIGITALOCEAN_TOKEN:-}"
  if [[ -z "$token" ]]; then
    token="$(ask "DigitalOcean token")"
    [[ -z "$token" ]] && echo "Token boş olamaz" && return
    export DIGITALOCEAN_TOKEN="$token"
  fi
  target="$(ask "Hedef domain")"
  [[ -z "$target" ]] && echo "Hedef boş olamaz" && return
  ssh_key="$(ask "DigitalOcean SSH key ID/fingerprint")"
  [[ -z "$ssh_key" ]] && echo "SSH key ID boş olamaz" && return
  identity="$(ask "SSH private key yolu, yoksa boş bırak")"
  profile="$(ask "Profil: stealth/balanced/fast" "balanced")"
  scope="$(ask "Scope dosyası yolu, yoksa boş bırak")"
  region="$(ask "Region" "fra1")"
  size="$(ask "Size" "s-1vcpu-1gb")"
  image="$(ask "Image" "ubuntu-24-04-x64")"
  nuclei="$(ask "Nuclei çalışsın mı? evet/hayır" "hayır")"

  local args=(-t "$target" --ssh-key-id "$ssh_key" -p "$profile" --region "$region" --size "$size" --image "$image")
  [[ -n "$identity" ]] && args+=(-i "$identity")
  [[ -n "$scope" ]] && args+=(-s "$scope")
  is_yes "$nuclei" && args+=(--with-nuclei)
  ./scripts/cloud_do_safe.sh "${args[@]}"
}

hetzner_scan() {
  require_scripts
  local token target ssh_key identity profile scope location server_type image nuclei
  token="${HETZNER_TOKEN:-}"
  if [[ -z "$token" ]]; then
    token="$(ask "Hetzner token")"
    [[ -z "$token" ]] && echo "Token boş olamaz" && return
    export HETZNER_TOKEN="$token"
  fi
  target="$(ask "Hedef domain")"
  [[ -z "$target" ]] && echo "Hedef boş olamaz" && return
  ssh_key="$(ask "Hetzner SSH key name/id")"
  [[ -z "$ssh_key" ]] && echo "SSH key boş olamaz" && return
  identity="$(ask "SSH private key yolu, yoksa boş bırak")"
  profile="$(ask "Profil: stealth/balanced/fast" "balanced")"
  scope="$(ask "Scope dosyası yolu, yoksa boş bırak")"
  location="$(ask "Location" "fsn1")"
  server_type="$(ask "Server type" "cx22")"
  image="$(ask "Image" "ubuntu-24.04")"
  nuclei="$(ask "Nuclei çalışsın mı? evet/hayır" "hayır")"

  local args=(-t "$target" --ssh-key "$ssh_key" -p "$profile" --location "$location" --type "$server_type" --image "$image")
  [[ -n "$identity" ]] && args+=(-i "$identity")
  [[ -n "$scope" ]] && args+=(-s "$scope")
  is_yes "$nuclei" && args+=(--with-nuclei)
  ./scripts/cloud_hetzner_safe.sh "${args[@]}"
}

cloud_cleanup() {
  require_scripts
  local provider token age apply args
  provider="$(ask "Provider: digitalocean/hetzner" "digitalocean")"
  age="$(ask "Kaç saatten eski workerlar listelensin/silinsin" "6")"
  apply="$(ask "Gerçekten silinsin mi? evet/hayır" "hayır")"

  case "$provider" in
    digitalocean)
      token="${DIGITALOCEAN_TOKEN:-}"
      if [[ -z "$token" ]]; then
        token="$(ask "DigitalOcean token")"
        [[ -z "$token" ]] && echo "Token boş olamaz" && return
        export DIGITALOCEAN_TOKEN="$token"
      fi
      args=(--provider digitalocean --max-age-hours "$age")
      ;;
    hetzner)
      token="${HETZNER_TOKEN:-}"
      if [[ -z "$token" ]]; then
        token="$(ask "Hetzner token")"
        [[ -z "$token" ]] && echo "Token boş olamaz" && return
        export HETZNER_TOKEN="$token"
      fi
      args=(--provider hetzner --max-age-hours "$age")
      ;;
    *)
      echo "Geçersiz provider"
      return
      ;;
  esac

  if is_yes "$apply"; then
    args+=(--apply)
  fi
  ./scripts/cloud_cleanup.sh "${args[@]}"
}

snapshot_result() {
  require_scripts
  local target label
  target="$(ask "Snapshot alınacak hedef")"
  [[ -z "$target" ]] && echo "Hedef boş olamaz" && return
  label="$(ask "Etiket, yoksa boş bırak")"
  local args=(-t "$target")
  [[ -n "$label" ]] && args+=(-l "$label")
  ./scripts/snapshot.sh "${args[@]}"
}

diff_reports() {
  build_if_needed
  local old_report new_report
  old_report="$(ask "Eski report.json yolu")"
  new_report="$(ask "Yeni report.json yolu")"
  [[ -z "$old_report" || -z "$new_report" ]] && echo "İki report yolu da gerekli" && return
  ./reconixia-diff -old "$old_report" -new "$new_report"
}

show_status() {
  require_scripts
  ./scripts/validate_setup.sh || true
}

while true; do
  clear || true
  cat <<'EOF'
Reconixia Otomasyon Menüsü
==========================
1) Kurulum + build yap
2) Local tam tarama yap
3) Mevcut VPS üzerinde tarama yap
4) DigitalOcean geçici worker ile tarama yap
5) Hetzner geçici worker ile tarama yap
6) Cloud worker cleanup yap
7) Snapshot al
8) İki raporu diff yap
9) Validate / sistem kontrolü
0) Çıkış
EOF
  choice="$(ask "Seçim")"
  case "$choice" in
    1) install_and_build; pause ;;
    2) local_scan; pause ;;
    3) existing_vps_scan; pause ;;
    4) digitalocean_scan; pause ;;
    5) hetzner_scan; pause ;;
    6) cloud_cleanup; pause ;;
    7) snapshot_result; pause ;;
    8) diff_reports; pause ;;
    9) show_status; pause ;;
    0) exit 0 ;;
    *) echo "Geçersiz seçim"; pause ;;
  esac
done
