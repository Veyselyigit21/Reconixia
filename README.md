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
- `subfinder`e ek olarak `crt.sh` (certificate transparency) ve opsiyonel `assetfinder` ile pasif subdomain kapsamını genişletir.
- Opsiyonel `-prune-dead` ile pasif URL'leri `httpx` üzerinden doğrulayıp ölü/404 olanları rapordan eler.
- Opsiyonel `-katana` ile aktif derin crawl yaparak `gau`'nun kaçırdığı URL/endpoint yüzeylerini bulur.
- Opsiyonel `-arjun` ile gizli GET/POST parametrelerini keşfeder (yetkili hedeflerde).
- Opsiyonel `-xss` ile `dalfox` kullanarak parametreli URL'lerde reflected/DOM XSS tespiti yapar (tespit amaçlı varsayılan payloadlar; custom/silahlandırılmış payload yok).
- Opsiyonel `-dast` ile `nuclei -dast` fuzzing/DAST şablonlarını çalıştırır (aktif test).
- Cloud object storage (S3/GCS/Azure/DO Spaces) referanslarını tespit eder ve yalnızca okuma yapan isteklerle public listing / dangling bucket durumunu sınıflandırır.
- `httpx` teknoloji parmak izlerini risk önceliğine göre (`Tech Priority`) sıralayıp rapora ekler.
- Canlı HTTP/HTTPS servisleri ayıklar.
- `gau --subs` ile Wayback/CommonCrawl tabanlı pasif URL toplayabilir.
- Admin, login, API, GraphQL, Swagger, OpenAPI, robots ve sitemap gibi ilginç pathleri kontrol eder.
- HTML ve JS içinden JS dosyası / endpoint adayları çıkarır.
- JS'den çıkan endpointleri güvenli GET/HEAD/OPTIONS probe ile `public_json`, `auth_required`, `method_not_allowed` gibi triage sınıflarına ayırır.
- JSON response içinde `email`, `role`, `token`, `userId`, `balance`, `accountId` gibi hassas alan adlarını değerleri kaydetmeden sınıflandırır ve risk skoru üretir.
- İki sahip olunan test hesabıyla HAR/JSONL tabanlı IDOR/BOLA replay analizi yapar.
- Browser companion extension ile araştırmacı header'ı ekler, owned-account requestleri toplar ve IDOR JSONL export üretir.
- Güvenli OAST/callback helper ile destructive olmayan blind interaction kanıtı üretmeye yardımcı olur.
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
go build -o reconixia-idor ./cmd/reconixia-idor
./reconixia version
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

## Otomasyon menüsü

Terminalden ürün gibi kullanmak için:

```bash
make auto
```

Menüdeki önerilen akışlar:

```txt
Quick scan              stealth + resume + nuclei kapalı
Standard full scan      balanced + resume + HTML rapor
Bug bounty workflow     full scan + params + 403 + structured AI + isteğe bağlı screenshot/port/provider AI
Optional modules        mevcut results klasörüne tek tek modül çalıştırma
Remote / cloud scan     mevcut VPS, DigitalOcean veya Hetzner worker
```

Güvenli başlangıç için önce `Quick scan`, bounty triage için sonra `Bug bounty workflow` kullan.

Production ortamlarında program istiyorsa araştırmacı header'ı ekle:

```bash
make full-scan-resume TARGET=hedef.com H1_USER=hackerone_kullanici_adin
```

Varsayılan header adı `X-HackerOne-Research` değeriyse `H1_USER` olur. Program farklı header adı istiyorsa `RESEARCH_HEADER` ile ezebilirsin.

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

Genişletilmiş keşif bayrakları:

```bash
./reconixia run -target hedef.com -no-subenum        # crt.sh/assetfinder pasif kaynaklarını kapat
./reconixia run -target hedef.com -no-buckets        # cloud bucket exposure analizini kapat
./reconixia run -target hedef.com -prune-dead        # pasif URL'leri httpx ile doğrula, ölüleri ele
./reconixia run -target hedef.com -katana            # aktif derin crawl (hedefe trafik üretir)
./reconixia run -target hedef.com -arjun             # gizli parametre keşfi (hedefe trafik üretir)
./reconixia run -target hedef.com -xss               # dalfox ile aktif XSS tespiti (parametreli URL'ler)
./reconixia run -target hedef.com -dast              # nuclei -dast fuzzing (aktif)
```

Varsayılan davranış:

```txt
crt.sh + assetfinder pasif subdomain       : açık (-no-subenum ile kapatılır)
cloud bucket exposure                      : açık (-no-buckets ile kapatılır)
tech priority özeti                        : açık (ek maliyet yok, lokal)
ölü URL budama / katana / arjun / xss / dast : kapalı (opt-in; aktif trafik ürettikleri için bayrakla açılır)
```

### Aktif test ve güvenlik sınırı

`-xss` (dalfox) ve `-dast` (nuclei) **aktif** modüllerdir: hedefe probe/fuzzing payloadları gönderirler. Bu nedenle opt-in'dir, scope + SSRF filtresinden geçer, rate-limit ve research header uygular, yalnızca tespit amaçlı varsayılan payloadları kullanır. Yalnızca **test etmeye yetkili** (programın scope'undaki) hedeflerde kullan. Reconixia bilinçli olarak **reverse shell, persistence ve destructive/silahlandırılmış payload üretmez**; bu modüller de bu sınırın içindedir.

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

## Release kontrolü

Dağıtım öncesi:

```bash
make release-check
```

Release artifact üretmek için:

```bash
make release-artifacts VERSION=0.9.0-rc1
```

Bu hedef `dist/<version>/` altına platform binary'leri, `SHA256SUMS` ve sistemde `gpg` varsa `SHA256SUMS.asc` detached signature üretir.

Release kapıları için `docs/RELEASE_CHECKLIST.md` dosyasını takip et.

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

HTML triage diff için:

```bash
./reconixia-diff \
  -old results/hedef.com-old/report.json \
  -new results/hedef.com/report.json \
  -html \
  -output results/hedef.com/diff.html
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
├── processed/endpoint_probes.jsonl
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
export OPENROUTER_API_KEY=...
./reconixia analyze -target hedef.com -provider local
./reconixia analyze -target hedef.com -provider openrouter -model deepseek/deepseek-r1
./reconixia analyze -target hedef.com -provider openai -model gpt-4o-mini
./reconixia analyze -target hedef.com -provider deepseek -model deepseek-reasoner
```

AI analizi hem `results/hedef.com/ai_analysis.json` hem de `results/hedef.com/ai_analysis.md` dosyasına yazılır. Remote provider kullanırken rapor önce redaction'dan geçer, büyük raporlar chunk'lara ayrılır ve çıktı sabit JSON şemasına parse edilir.

Opsiyonel ayarlar:

```bash
export RECONIXIA_AI_PROVIDER=openrouter
export OPENROUTER_MODEL=deepseek/deepseek-r1
export RECONIXIA_AI_CHUNK_CHARS=24000
export RECONIXIA_AI_TIMEOUT_SECONDS=90
```

Yerel keyword tabanlı structured JSON için ayrıca `make structured-ai TARGET=hedef.com` kullanılabilir.

## IDOR / BOLA analizi

Bu modül yalnızca sana ait iki yetkili test hesabıyla kullanılmalıdır. Browser veya Burp üzerinden A hesabının isteklerini HAR olarak dışa aktar, sonra A ve B hesabının auth bilgisini env üzerinden ver:

```bash
export RECONIXIA_IDOR_AUTH_A='Authorization: Bearer account-a-token'
export RECONIXIA_IDOR_AUTH_B='Authorization: Bearer account-b-token'

./reconixia-idor \
  -target whatnot.com \
  -har whatnot-owned-account.har \
  -rules examples/program-policies/whatnot.idor-policy.example.json \
  -h1-user hackerone_kullanici_adin \
  -rate 2 \
  -max 50
```

Alternatif JSONL formatı:

```json
{"method":"GET","url":"https://api.whatnot.com/api/example/123","headers":{"Accept":"application/json"}}
```

Varsayılan olarak sadece `GET`, `HEAD` ve `OPTIONS` replay edilir. `POST`, `PUT`, `PATCH`, `DELETE` gibi mutating methodlar ancak `-allow-mutating` ile çalışır ve sadece program kurallarının izin verdiği owned test data üzerinde kullanılmalıdır. Çıktılar `results/<target>/idor_analysis.json` ve `idor_analysis.md` dosyalarına yazılır; response body ve token değerleri saklanmaz.

Programdan programa kural değiştiği için `-rules` ile policy dosyası verebilirsin. Policy içinde target, araştırmacı header'ı, rate/max sınırı, izinli HTTP methodları ve kaçınılacak URL parçaları tanımlanır.

## Browser companion

Chrome/Chromium için lokal extension:

```txt
browser-extension/reconixia-companion
```

Kurulum ve kullanım için [docs/BROWSER_EXTENSION.md](docs/BROWSER_EXTENSION.md) dosyasına bak. Extension, program domainlerinde research header ekleyebilir ve DevTools panelinden owned-account API requestlerini JSONL olarak `reconixia-idor` modülüne aktarır.

Reverse shell, persistence veya destructive payload generator bilinçli olarak eklenmez. Güvenli PoC yaklaşımı için [docs/SAFE_POC_HELPERS.md](docs/SAFE_POC_HELPERS.md) dosyasına bak.

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

## Lisans

Reconixia, [Apache License 2.0](LICENSE) ile lisanslanmıştır.
