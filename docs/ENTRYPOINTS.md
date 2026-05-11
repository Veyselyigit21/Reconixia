# Reconixia Entrypoint Kararı

Bu doküman, projedeki aktif binary/entrypoint karmaşasını önlemek için hazırlanmıştır.

## Aktif ana araç

Şu an aktif ve desteklenen ana entrypoint:

```bash
go build -o reconixia ./cmd/reconixia-v06
```

Bu klasör adı tarihsel olarak `v06` kalsa da içerik artık pro seviyesine taşınmış çekirdek local recon akışıdır.

## Yardımcı araçlar

```bash
go build -o reconixia-report ./cmd/reconixia-report
go build -o reconixia-augment ./cmd/reconixia-augment
go build -o reconixia-diff ./cmd/reconixia-diff
go build -o reconixia-ai-structured ./cmd/reconixia-ai-structured
```

## Karar

- `cmd/reconixia-pro` şu an aktif entrypoint değildir.
- `cmd/reconixia-v06` aktif ana entrypoint olarak korunacaktır.
- Kullanıcı tarafında binary adı yine `reconixia` olacaktır.
- Proje v1.0 temizliğinde klasör adı `cmd/reconixia` veya `cmd/reconixia-core` olarak sadeleştirilebilir.

## Neden hemen rename yapılmadı?

Go tarafında import ve build yolları çalışan durumdayken büyük klasör rename işlemi gereksiz kırılma riski yaratır. Önce CI/build stabilitesi korunur, sonra refactor turunda sadeleştirme yapılır.

## Kullanıcı için önerilen giriş noktası

En pratik kullanım:

```bash
make auto
```

Komutlu local kullanım:

```bash
make full-scan-resume TARGET=hedef.com
```

Klasik kullanım:

```bash
make build
./reconixia run -target hedef.com -profile balanced
```
