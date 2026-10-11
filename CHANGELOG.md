# Changelog

## Unreleased

Genişletilmiş keşif modülleri (varsayılan güvenli posture korunarak).

- Pasif subdomain kaynakları genişletildi: `crt.sh` certificate transparency + opsiyonel `assetfinder`, scope/safety filtresinden geçirilerek `subfinder` sonuçlarıyla birleştiriliyor (`-no-subenum` ile kapatılır).
- Cloud object storage exposure tespiti eklendi: S3/GCS/Azure/DO Spaces referansları çıkarılıp yalnızca okuma yapan isteklerle public-listing / dangling-bucket olarak sınıflandırılıyor (`-no-buckets` ile kapatılır).
- Tech priority özeti eklendi: `httpx` JSON teknoloji parmak izleri risk sırasına dizilip rapora (`report.md`/`report.json`) ekleniyor.
- Opsiyonel `-prune-dead`: pasif URL'ler `httpx` ile doğrulanıp ölü/404/5xx olanlar eleniyor.
- Opsiyonel `-katana`: aktif derin crawl ile ek URL/endpoint keşfi (trafik ürettiği için opt-in).
- Opsiyonel `-arjun`: gizli parametre keşfi; sonuçlar `discovered_params.txt` ve `discovered_parameter` bulguları olarak kaydediliyor (opt-in).
- Opsiyonel `-xss`: `dalfox` ile parametreli URL'lerde reflected/DOM XSS tespiti; scope/safety gate, rate-limit, research header, yalnızca tespit amaçlı varsayılan payloadlar (opt-in, aktif).
- Opsiyonel `-dast`: `nuclei -dast` fuzzing/DAST şablonları (opt-in, aktif). `nuclei()` imzası DAST bayrağını alacak şekilde güncellendi.
- Güvenlik sınırı korundu: reverse shell / persistence / destructive-silahlandırılmış payload üretimi hâlâ kapsam dışı; yeni modüller tespit/fuzzing ile sınırlı.
- `-ai`: tarama bitince otomatik AI triyajı (`RECONIXIA_AI_PROVIDER`); `recon→AI` tek komutta, ayrı `analyze` adımı gerekmez.
- Yeni `internal/webchecks` modülü (varsayılan açık, `-no-webchecks` ile kapatılır): tehlikeli HTTP metodları (TRACE/PUT/DELETE, XST), open redirect (owned marker ile doğrulama), host header yansıması, içerik imzasıyla doğrulanmış hassas dosya ifşası (`.git`/`.env`/`web.config`/yedek/DB), ve pasif SSRF/LFI/open-redirect aday-parametre etiketleme.
- `internal/headers` güçlendirildi: `Server`/`X-Powered-By`/`X-AspNet-Version` sürüm ifşası, COOP + Permissions-Policy eksikliği, derinlemesine CSP zayıflıkları (wildcard kaynak, eksik object-src/frame-ancestors).
- `webchecks` için birim testleri (param sınıflama + redirect eşleştirme) eklendi.
- `httpx` artık JSON çıktısı üretip `processed/httpx_detailed.jsonl` dosyasına yazıyor; canlı host listesi buradan türetiliyor.
- `install_tools.sh` ve `doctor` yeni opsiyonel araçları (assetfinder, katana, arjun) kapsayacak şekilde güncellendi.
- Yeni `techrank` ve `cloudbuckets` paketleri için birim testleri eklendi.

## 0.9.0-rc1 - 2026-05-11

Release-candidate hardening pass for Reconixia.

- Added strict SSH host-key workflow with known_hosts support and explicit ephemeral accept mode.
- Added DigitalOcean and Hetzner cloud firewalls with SSH CIDR allowlisting.
- Added workspace locking to protect report files from concurrent scans.
- Added local redaction before reports, logs, and AI analysis.
- Added native Go checkpoint resume for recon steps: subfinder, httpx, passive, js, discover, headers, nuclei, takeover, and report.
- Added interactive HTML report filters for finding type, confidence, high-confidence-only, and search.
- Added HTML diff output via `reconixia-diff -html`.
- Moved takeover indicators into a provider fingerprint database with unit tests.
- Added release checks and reproducible release artifacts with SHA256SUMS and optional GPG signatures.
