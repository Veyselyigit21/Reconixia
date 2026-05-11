# Reconixia Resume / Checkpoint

Reconixia'da iki seviyeli resume planı vardır:

1. Script-level resume: bugün kullanılan pratik akış.
2. Native v06 resume: ileride `./reconixia run --resume` olarak eklenecek daha ince taneli akış.

## Script-level resume

Kullanım:

```bash
make full-scan-resume TARGET=example.com
```

Sıfırdan başlatmak için:

```bash
make full-scan-resume TARGET=example.com RESET=true
```

Script:

```txt
scripts/full_scan_resume.sh
```

Checkpoint dosyası:

```txt
results/example.com/checkpoint_full_scan.json
```

## Aşamalar

Script-level resume üç ana aşamayı takip eder:

```txt
1. recon
2. augment
3. report
```

Örnek checkpoint:

```json
{
  "target": "example.com",
  "completed_steps": {
    "recon": true,
    "augment": true,
    "report": true
  },
  "last_step": "report",
  "updated_at": "2026-05-11T00:00:00Z"
}
```

## Davranış

- `recon` tamamlandıysa tekrar çalıştırılmaz.
- `augment` tamamlandıysa tekrar çalıştırılmaz.
- `report` tamamlandıysa tekrar çalıştırılmaz.
- `RESET=true` verilirse checkpoint silinir ve akış baştan başlar.

## Neden script-level resume?

`cmd/reconixia-v06/main.go` şu an tek dosyada yoğun bir akış taşıyor. Native `--resume` doğrudan bu dosyaya büyük patch gerektirir. Script-level resume daha düşük riskli bir ara çözümdür ve bugün kullanılabilir.

## Sonraki native resume planı

İleride `cmd/reconixia-v06` içine şu adımlar için checkpoint eklenecek:

```txt
subdomains
live_hosts
passive_urls
js_endpoints
interesting_paths
headers
nuclei
report
```

Hedef komut:

```bash
./reconixia run -target example.com --resume
```
