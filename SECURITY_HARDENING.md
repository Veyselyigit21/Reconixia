# Reconixia Security Hardening Notes

Bu belge, v0.4 güvenlik sertleştirme ve bug bounty modül geliştirme planını takip etmek için eklendi.

## Uygulanan düzeltmeler

- Cloud provider validation eklendi.
- Boş target / ssh-key kontrolü güçlendirildi.
- Hetzner IP wait loop eklendi.
- JS dosyaları için ikinci tur endpoint çıkarımı eklendi.
- Optional recon araçları installer'a eklendi: gau, naabu, subjack.

## Hemen uygulanacak v0.4 güvenlik düzeltmeleri

- Strict hostname validation.
- Passive URL ve JS fetch akışında SSRF koruması.
- Private, loopback, link-local, multicast ve metadata IP bloklarını engelleme.
- AI HTTP client timeout.
- http.NewRequest error handling.
- Nuclei severity profil sistemi.
- Scope dosyası sadece deny kuralı içerirse otomatik wildcard allow.
- Cloud create timeout durumunda server cleanup.

## Bug bounty modül yol haritası

- Secret/API key regex scanning.
- GAU/Wayback URL toplama.
- Subdomain takeover kontrolü.
- CORS misconfiguration kontrolü.
- Cookie/header security analizi.
- Naabu port discovery.
- HTML rapor.
- Scan resume/checkpoint.
- Report diff.

## Güvenli kullanım

Reconixia yalnızca yetkili hedeflerde kullanılmalıdır. Araç keşif, hedef önceliklendirme ve raporlama için tasarlanmıştır.
