# Reconixia

Reconixia, yetkili güvenlik araştırmaları için geliştirilmiş Go tabanlı bir keşif, analiz ve raporlama aracıdır.

Araç; hedef keşfi, scope kontrolü, canlı servis tespiti, pasif URL toplama, JS/API endpoint çıkarımı, CORS/security header analizi, cookie security analizi, subdomain takeover ön analizi, secret göstergesi tarama, raporlama ve AI destekli analiz akışını tek bir yapıda toplar.

## Aktif sürüm

Aktif ve önerilen entrypoint:

```bash
go build -o reconixia ./cmd/reconixia-v06
```

Yardımcı araçlar:

```bash
go build -o reconixia-report ./cmd/reconixia-report
go build -o reconixia-augment ./cmd/reconixia-augment
go build -o reconixia-diff ./cmd/reconixia-diff
go build -o reconixia-ai-structured ./cmd/reconixia-ai-structured
```

Tek komutluk yardımcı scriptler:

```bash
chmod +x scripts/build_all.sh scripts/full_scan.sh
./scripts/build_all.sh
./scripts/full_scan.sh -t hedef.com --no-nuclei
```

Güncel güvenli local recon sürümü `cmd/reconixia-v06` üzerinden ilerler. Eski geliştirme klasörleri varsa dikkate alma.

## Özellikler

- Hedefe özel workspace oluşturur.
- Strict hostname validation uygular.
- SSRF riskine karşı passive URL, GAU, JS fetch ve header/cookie analiz akışını scope + safe URL filtresinden geçirir.
- Private, loopback, link-local, multicast ve metadata IP hedeflerini reddeder.
- Scope allow/deny kurallarını uygular.
- `subfinder`, `httpx`, `nuclei` ve opsiyonel `gau` araçlarını tek merkezden çalıştırır.
- Canlı HTTP/HTTPS servisleri ayıklar.
- `gau --subs` ile Wayback/CommonCrawl tabanlı pasif URL toplayabilir.
- Admin, login, API, GraphQL, Swagger, OpenAPI, robots ve sitemap gibi ilginç pathleri kontrol eder.
- HTML ve JS içinden JS dosyası / endpoint adayları çıkarır.
- API, IDOR ve secret inceleme adaylarını sınıflandırır.
- CORS ve browser security header analizi yapar.
- Cookie security analizi yapar.
- Pasif subdomain takeover ön analizi yapar.
- Report diff ile iki tarama arasındaki yeni yüzeyleri gösterir.
- Nuclei severity override destekler.
- Opsiyonel port scan, screenshot, pasif parametre keşfi ve 401/403 aday çıkarımı destekler.
- Markdown, JSON ve HTML rapor oluşturur.
- OpenRouter, OpenAI, DeepSeek API veya yerel analiz modunu destekler.
- Structured AI JSON çıktısı üretebilir.

## Kurulum

Linux, WSL2 veya VPS önerilir. Windows üzerinde kullanacaksan WSL2 Ubuntu en sorunsuz yoldur.

```bash
git clone https://github.com/Veyselyigit21/Reconixia.git
cd Reconixia
chmod +x scripts/install_tools.sh scripts/build_all.sh scripts/full_scan.sh
./scripts/install_tools.sh
./scripts/build_all.sh
```

Manuel build istersen:

```bash
go build -o reconixia ./cmd/reconixia-v06
go build -o reconixia-report ./cmd/reconixia-report
go build -o reconixia-augment ./cmd/reconixia-augment
go build -o reconixia-diff ./cmd/reconixia-diff
go build -o reconixia-ai-structured ./cmd/reconixia-ai-structured
```

## İlk kurulum

```bash
./reconixia setup
```

Kurulum menüsü:

```txt
1) AI sağlayıcısı / model / API key ayarla
2) Kayıtlı ayarları göster
3) Kaydet ve çık
0) Çıkış
```

## API key zorunlu mu?

Hayır. Temel recon özellikleri API key olmadan çalışır.

```txt
AI key yoksa: local analiz kullanılır.
OpenRouter/OpenAI/DeepSeek key varsa: AI analiz yapılabilir.
```

## Ana menü

```bash
./reconixia
```

```txt
1) Local recon başlat
2) AI analiz yap
3) Setup / API key yönetimi
4) Doctor / sistem kontrolü
0) Çıkış
```

## Tek komutluk tam tarama

En pratik kullanım:

```bash
./scripts/full_scan.sh -t hedef.com --no-nuclei
```

Scope ve profil ile:

```bash
./scripts/full_scan.sh -t hedef.com -p balanced -s examples/scope.example.txt --no-nuclei
```

Bu script şunları sırayla yapar:

```txt
1. Gerekirse aktif araçları build eder.
2. reconixia run çalıştırır.
3. reconixia-augment ile takeover + cookie analizlerini ekler.
4. reconixia-report ile HTML raporu üretir.
```

Çıktılar:

```txt
results/hedef.com/report.md
results/hedef.com/report.json
results/hedef.com/report.html
```

## Önerilen manuel kullanım akışı

```bash
./reconixia doctor
./reconixia run -target hedef.com -no-nuclei
./reconixia-augment -target hedef.com
./reconixia-report -target hedef.com
make structured-ai TARGET=hedef.com
```

## Komutlu kullanım

```bash
./reconixia doctor
./reconixia run -target hedef.com
./reconixia run -target hedef.com -profile fast
./reconixia run -target hedef.com -scope examples/scope.example.txt -profile balanced
./reconixia run -target hedef.com -wordlist wordlists/interesting_paths.txt
./reconixia run -target hedef.com -severity info,low,medium
./reconixia run -target hedef.com -no-gau
./reconixia run -target hedef.com -no-headers
./reconixia run -target hedef.com -no-nuclei
```

## Opsiyonel modüller

Ana tarama bittikten sonra isteğe bağlı modüller çalıştırılabilir:

```bash
make ports TARGET=hedef.com RATE=50 TOP_PORTS=1000
make screenshots TARGET=hedef.com
make params TARGET=hedef.com LIMIT=500
make 403-candidates TARGET=hedef.com LIMIT=200
```

Çıktılar:

```txt
results/hedef.com/processed/naabu_ports.txt
results/hedef.com/screenshots/
results/hedef.com/processed/discovered_params.txt
results/hedef.com/processed/403_candidates.txt
```

Detaylar için `docs/OPTIONAL_MODULES.md` dosyasına bak.

## Augment: takeover + cookie analizi

Normal recon sonrası mevcut rapora ek analizler ekler:

```bash
./reconixia-augment -target hedef.com
```

Opsiyonel kapatma:

```bash
./reconixia-augment -target hedef.com -no-takeover
./reconixia-augment -target hedef.com -no-cookies
```

`reconixia-augment`, `report.json` dosyasını günceller ve varsayılan olarak `report.html` dosyasını da yeniden üretir.

## Report diff

İki farklı taramanın `report.json` dosyalarını karşılaştırır:

```bash
./reconixia-diff \
  -old results/hedef.com-old/report.json \
  -new results/hedef.com/report.json
```

Şunları listeler:

```txt
Yeni subdomain
Yeni canlı hedef
Yeni pasif URL
Yeni JS dosyası
Yeni endpoint
Yeni bulgu
```

## Structured AI JSON

Yerel keyword tabanlı structured JSON analiz üretir:

```bash
make structured-ai TARGET=hedef.com
```

Alternatif manuel kullanım:

```bash
./reconixia-ai-structured -target hedef.com
./reconixia-ai-structured -input results/hedef.com/report.md -output results/hedef.com/ai_analysis.json
```

Çıktı:

```txt
results/hedef.com/ai_analysis.json
```

## Profil seçenekleri

```txt
stealth   = Daha sessiz ve düşük hızlı mod.
balanced  = Varsayılan mod.
fast      = Daha hızlı ama kontrollü mod.
```

## Scope dosyası

```txt
hedef.com
*.hedef.com
!vpn.hedef.com
!internal.hedef.com
```

`!` ile başlayan satırlar deny kuralıdır. Scope dosyası sadece deny kuralı içerirse Reconixia otomatik wildcard allow ekler ve rapora uyarı yazar.

## Çıktılar

```txt
results/hedef.com/
├── raw/subdomains.txt
├── processed/live_hosts.txt
├── processed/passive_urls.txt
├── processed/js_files.txt
├── processed/endpoints.txt
├── processed/interesting_paths.txt
├── processed/nuclei_safe.txt
├── export/targets.txt
├── report.md
├── report.json
├── ai_analysis.json
└── report.html
```

## HTML rapor

Önce recon çalıştır:

```bash
./reconixia run -target hedef.com -no-nuclei
```

Sonra HTML rapor üret:

```bash
./reconixia-report -target hedef.com
```

Alternatif olarak doğrudan input/output verebilirsin:

```bash
./reconixia-report \
  -input results/hedef.com/report.json \
  -output results/hedef.com/report.html
```

## AI analizi

```bash
./reconixia analyze -target hedef.com -provider local
./reconixia analyze -target hedef.com -provider openrouter -model deepseek/deepseek-r1
./reconixia analyze -target hedef.com -provider openai -model gpt-4o-mini
./reconixia analyze -target hedef.com -provider deepseek -model deepseek-reasoner
```

AI analizi `results/hedef.com/ai_analysis.md` dosyasına yazılır. Structured JSON için `make structured-ai TARGET=hedef.com` kullanılabilir.

## Hedef formatı

```txt
hedef.com
sub.hedef.com
https://hedef.com
http://hedef.com/path
```

Önerilen kullanım domain vermektir.

## v0.6 notu

v0.6 güvenli local recon sürümüdür. GAU pasif URL toplama, CORS/security header analizi ve HTML rapor desteği eklenmiştir. `augment` aracıyla cookie security ve takeover ön analizi eklenir. Remote/VPS worker daha sonra bu güvenlik modeline göre tekrar eklenecektir.

## Geliştirme notu

Araç kullanıldıkça yeni ihtiyaçlara göre geliştirilecektir. Hata çıktısı, eksik sonuç veya yeni özellik fikri oluşursa issue açabilir veya doğrudan çıktıyı paylaşabilirsin.

## Güvenli kullanım notu

Reconixia yalnızca test etmeye yetkili olduğun hedeflerde kullanılmalıdır. Scope dosyanı sıkı tut. Araç; keşif, hedef önceliklendirme, güvenli discovery ve raporlama için tasarlanmıştır.
