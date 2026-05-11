# Reconixia Optional Modules

Bu modüller varsayılan recon akışını agresifleştirmez. Ana tarama bittikten sonra kullanıcı açıkça çağırır.

## Port Scan / naabu

```bash
make ports TARGET=example.com RATE=50 TOP_PORTS=1000
```

Girdi:

```txt
results/example.com/processed/live_hosts.txt
```

Çıktı:

```txt
results/example.com/processed/naabu_ports.txt
```

Notlar:

- `naabu` yüklü değilse modül çalışmaz.
- Rate düşük tutulmalıdır.
- Yalnızca yetkili hedeflerde kullanılmalıdır.

## Screenshot / gowitness

```bash
make screenshots TARGET=example.com
```

Girdi:

```txt
results/example.com/processed/live_hosts.txt
```

Çıktı:

```txt
results/example.com/screenshots/
```

Notlar:

- `gowitness` ve gerekli browser bağımlılıkları gerekebilir.
- Screenshot çıktıları manuel önceliklendirme içindir.

## Passive Parameter Discovery

```bash
make params TARGET=example.com LIMIT=500
```

Girdi:

```txt
results/example.com/processed/passive_urls.txt
```

Çıktı:

```txt
results/example.com/processed/discovered_params.txt
```

Notlar:

- Bu modül fuzz yapmaz.
- Sadece pasif URL'lerde zaten görünen parametre adlarını çıkarır.

## 401/403 Manual Review Candidates

```bash
make 403-candidates TARGET=example.com LIMIT=200
```

Girdi:

```txt
results/example.com/processed/interesting_paths.txt
```

Çıktı:

```txt
results/example.com/processed/403_candidates.txt
```

Notlar:

- Bu modül bypass denemesi yapmaz.
- Sadece Reconixia'nın zaten gördüğü 401/403 URL'lerini manuel inceleme adayları olarak listeler.
- Daha ileri bypass kontrolleri ileride ayrı, düşük hacimli ve açık flag gerektiren modül olarak eklenmelidir.
