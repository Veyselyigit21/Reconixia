# Reconixia Progress

Bu dosya mevcut geliştirme durumunu hızlı görmek için tutulur.

## Genel Durum

```txt
Reconixia genel ilerleme:        85%
Local recon:                     90%
Raporlama / augment / diff:      90%
Opsiyonel modüller:              80%
Cloud worker:                    75%
Resume/checkpoint:               70%
AI structured output:            80%
Proje kontrol / CI:              85%
```

## Tamamlananlar

- Eski `cmd` sürüm karmaşası temizlendi.
- Aktif entrypoint `cmd/reconixia-v06` olarak netleşti.
- Yardımcı binary'ler aktif:
  - `reconixia-report`
  - `reconixia-augment`
  - `reconixia-diff`
  - `reconixia-ai-structured`
- `make status` eklendi.
- `make ci` eklendi.
- `make full-scan-resume` eklendi.
- Structured AI JSON çıktısı eklendi.
- Opsiyonel modüller eklendi:
  - `make ports`
  - `make screenshots`
  - `make params`
  - `make 403-candidates`
- Cloud worker cleanup sinyal davranışı güçlendirildi.
- Roadmap, resume ve cloud safety dokümantasyonu eklendi.

## Aktif Kullanım Komutları

```bash
make status
make ci
make build
make full-scan-resume TARGET=example.com
make full-scan-resume TARGET=example.com RESET=true
make structured-ai TARGET=example.com
make ports TARGET=example.com
make screenshots TARGET=example.com
make params TARGET=example.com
make 403-candidates TARGET=example.com
```

## Kalan Büyük İşler

1. `cmd/reconixia-v06` içine native `--resume` flag eklemek.
2. `cmd/reconixia-v06` içindeki secret scanner akışını `internal/secrets` paketine bağlamak.
3. `analyze` komutuna native structured JSON flag eklemek.
4. HTTP ve dış araç akışlarını signal-aware hale getirmek.
5. DigitalOcean / Hetzner firewall API entegrasyonunu eklemek.
6. Cloud cleanup sonrası silme doğrulamasını worker scriptlerine güvenli şekilde eklemek.

## Kısa Öncelik Sırası

```txt
1. Secret scanner v06 bağlantısı
2. Native --resume
3. Cloud firewall
4. Cleanup doğrulama
5. Native analyze --structured
```
