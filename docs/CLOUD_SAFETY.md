# Reconixia Cloud Safety

Reconixia cloud worker akışı geçici VPS oluşturup tarama bittikten sonra worker'ı silmek üzerine kuruludur.

## Mevcut durum

Desteklenen sağlayıcılar:

```txt
DigitalOcean
Hetzner Cloud
```

İlgili scriptler:

```txt
scripts/cloud_do_safe.sh
scripts/cloud_do_worker.sh
scripts/cloud_hetzner_safe.sh
scripts/cloud_hetzner_worker.sh
scripts/cloud_cleanup.sh
```

## Cleanup hardening

Worker scriptleri şu durumlarda cleanup çağırır:

```txt
normal bitiş
hata ile çıkış
CTRL+C / SIGINT
SIGTERM
```

DigitalOcean:

```txt
scripts/cloud_do_worker.sh
```

Hetzner:

```txt
scripts/cloud_hetzner_worker.sh
```

Her iki scriptte de worker ID boş değilse destroy isteği gönderilir ve sonra ID temizlenir.

## Orphan cleanup

Elle temizlik için:

```bash
make cloud-cleanup-do MAX_AGE_HOURS=6 APPLY=true
make cloud-cleanup-hetzner MAX_AGE_HOURS=6 APPLY=true
```

Dry-run için `APPLY=true` verme:

```bash
make cloud-cleanup-do MAX_AGE_HOURS=6
make cloud-cleanup-hetzner MAX_AGE_HOURS=6
```

## Firewall durumu

Şu an `internal/cloudsafe` içinde firewall planlama modeli vardır, ancak gerçek sağlayıcı API entegrasyonu ayrı adım olarak durmaktadır.

Planlanan davranış:

```txt
1. Worker oluştur.
2. Sadece SSH erişimini izinli CIDR'dan aç.
3. Gereksiz inbound trafiği kapalı tut.
4. Tarama bitince firewall kuralını ve worker'ı temizle.
```

## Güvenli varsayımlar

- Worker geçici olmalıdır.
- Tokenlar `.env` içinde kalmalı, remote host'a yüklenmemelidir.
- SSH private key remote host'a yüklenmemelidir.
- Cloud worker isimleri `reconixia-worker-*` formatını izlemelidir.
- Cleanup scriptleri sadece Reconixia tag/label/isim desenine uyan worker'ları hedeflemelidir.

## Sonraki işler

```txt
1. DigitalOcean firewall API entegrasyonu
2. Hetzner firewall API entegrasyonu
3. Cleanup sonrası doğrulama: worker gerçekten silindi mi kontrolü
4. Firewall cleanup doğrulaması
```
