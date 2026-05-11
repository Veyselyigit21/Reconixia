# Reconixia Roadmap

Bu dosya aktif geliştirme sırasını net tutmak için eklendi. Aktif entrypoint `cmd/reconixia-v06`.

## Tamamlanan / Eklenen Altyapı

- `internal/checkpoint`: resume/checkpoint state dosyası altyapısı.
- `internal/secrets`: genişletilmiş secret scanner pattern paketi.
- `internal/aianalysis`: JSON tabanlı structured AI analiz şeması ve local fallback.
- `internal/runtimectx`: `signal.NotifyContext` ile graceful shutdown helper.
- `internal/tools`: harici araçları timeout ve context ile çalıştırma helperı.
- `internal/cloudsafe`: cloud worker cleanup/firewall planlama modelleri.
- `internal/modules`: opsiyonel modüller için limit ve enable/disable modeli.
- `scripts/full_scan_resume.sh`: script seviyesinde resumable full scan desteği.
- `scripts/ci_local.sh`: local CI/build/test smoke kontrolü.
- `scripts/project_status.sh`: proje sağlık durumu kontrolü.

## Tamamlanan Bağlama İşleri

- Structured AI JSON çıktısı `cmd/reconixia-ai-structured` ve `make structured-ai` ile bağlandı.
- Opsiyonel modüller `make ports`, `make screenshots`, `make params`, `make 403-candidates` ile bağlandı.
- Full scan resume akışı `make full-scan-resume` ile bağlandı.
- DigitalOcean ve Hetzner worker cleanup sinyal davranışı güçlendirildi.

## Sıradaki Bağlama İşleri

1. `cmd/reconixia-v06` içine native `--resume` flag'i ekle ve `internal/checkpoint` ile 8 iç adımı işaretle.
2. Mevcut `secretScan` fonksiyonunu `internal/secrets.Scan` kullanacak şekilde güncelle.
3. `analyze` komutuna native `--json` veya `--structured` çıktısı ekle.
4. HTTP ve dış araç akışlarını `signal.NotifyContext` ile iptal edilebilir hale getir.
5. DO/Hetzner firewall entegrasyonunu provider bazlı ekle.
6. 403 tarafını varsayılan güvenli aday çıkarımı seviyesinde tut; aktif bypass denemeleri ayrıca açık flag ve düşük limit istemeli.

## Güvenli Geliştirme Notu

Yeni modüller varsayılan olarak agresif çalışmamalı. Port scan, screenshot, param discovery ve 403 bypass gibi modüller açık flag ister ve profile limitlerine uymalıdır.
