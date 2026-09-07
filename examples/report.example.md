# Reconixia Raporu

Hedef: `example.com`

Profil: `balanced` | Rate: `50/sn` | Threads: `10`

Alt alan adi: **4**  
Canli hedef: **2**  
Pasif URL: **18**  
JS: **3**  
Endpoint: **9**  
Bulgu: **5**

## Uyarilar

- nuclei kullanici tercihiyle atlandi

## Oncelikli Bulgular

- `https://app.example.com/admin` [403] auth_or_admin_surface / medium - manuel inceleme adayi
- `https://api.example.com/graphql` [0] api_endpoint / medium - API manuel inceleme adayi
- `cdn.example.com` [0] possible_subdomain_takeover / medium - CNAME stale.example.netlify.app provider=netlify evidence=Netlify CNAME; no A/AAAA resolution; manual takeover verification required
- `https://static.example.com/app.js` [0] possible_github_token / high - possible_github_token; value redacted
- `https://www.example.com/.well-known/security.txt` [200] interesting_path / high - manuel inceleme adayi
