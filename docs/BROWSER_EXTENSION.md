# Reconixia Companion Browser Extension

Reconixia Companion is a lightweight Chrome/Chromium extension for authorized bug bounty workflows.

It does not generate exploit payloads. It focuses on the parts that usually matter for responsible web and API testing:

- Inject the required research attribution header for matching program domains.
- Capture owned-account API requests from DevTools.
- Strip captured `Authorization` and `Cookie` headers from exports.
- Highlight IDOR/BOLA candidate URLs with object identifiers or account-sensitive route names.
- Score owned-account requests and export replay-safe IDOR/BOLA JSONL for `reconixia-idor`.
- Run local browser-side recon against the active tab: secret patterns, endpoint extraction, web storage, framework fingerprints, media URLs, headers, and DOM security markers.
- Optionally probe a small, rate-limited list of common sensitive paths on the active origin.
- Generate safe OAST/callback helper strings for non-destructive blind interaction checks.

## Install Locally

1. Open `chrome://extensions`.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select `browser-extension/reconixia-companion`.

## Configure Header Injection

Open the extension popup and set:

```txt
Program: Whatnot
Target domains: manually enter only the in-scope domains from the program page
HackerOne username: aello
Research header: X-HackerOne-Research
```

Turn on the switch in the popup. The extension will inject the header only for configured request domains.

## Browser Recon

Open the popup on an authorized target and click `Scan active tab`.

The scan runs locally in the browser and produces JSON with:

- secret candidates in inline scripts, JavaScript bundles, web storage, and known global config objects
- endpoint and route candidates from HTML, scripts, build manifests, and links
- media/document URL candidates such as `.m3u8`, `.mpd`, `.mp4`, `.pdf`, `.docx`, and signed CDN URLs
- technology fingerprints such as Next.js, Nuxt, React, Vue, Webflow, Shopify, Cloudflare, Vercel, Sentry, Datadog, Stripe, and Firebase
- browser storage findings for token, auth, user, account, role, balance, and PII-like keys
- security header notes and DOM sink markers
- first-party endpoints and third-party vendor endpoints separated to reduce false positives

`Safe path probe` is disabled by default. When enabled, it only probes the active origin, uses the configured rate limit and research header, omits browser credentials, and records metadata rather than raw sensitive bodies.

Use `Copy JSON` or `Download` to save the browser recon output for manual review or AI triage.

Third-party script findings, such as public keys or Sentry DSNs inside `js.stripe.com`, are separated under `thirdPartySignals`. Treat those as context, not target-owned findings, unless you can demonstrate impact against the in-scope application itself.

## Capture IDOR Requests

1. Log in with account A.
2. Open DevTools.
3. Open the `Reconixia` DevTools panel.
4. Browse only owned-account pages and safe read-only object-detail surfaces.
5. Prefer pages that load a real private object id: order detail, shipment detail, conversation detail, inventory/listing detail, payout detail, document/detail views, workspace/project/detail views.
6. Use `Object detail` to filter stronger candidates.
7. Use `Copy IDOR` or `Download IDOR` for replay-safe candidates only.
8. Use the popup `REPLAY` section to set the capture file and policy path, then copy the generated command.

```bash
export RECONIXIA_IDOR_COOKIE_A='ACCOUNT_A_COOKIE'
export RECONIXIA_IDOR_COOKIE_B='ACCOUNT_B_COOKIE'

./reconixia-idor \
  -target target.com \
  -input captures/target-account-a-detail.jsonl \
  -rules examples/program-policies/target.idor-policy.json \
  -rate 2 \
  -max 50
```

`Copy JSONL` / `Download` exports the visible filtered list and can include general API traffic for manual analysis. `Copy IDOR` / `Download IDOR` exports only read-only replay candidates: GET/HEAD/OPTIONS and read-only GraphQL query POST requests. Mutations and write-like requests are intentionally excluded from IDOR-only export.

Keep cookies and tokens in your terminal only. Do not paste them into reports, chats, or exported JSONL files.

## Safe Callback Helper

The popup includes a callback helper for your own Burp Collaborator or interactsh domain. It generates URL and DNS-style callback strings that can help verify blind interactions without using reverse shells or destructive payloads.

See [SAFE_POC_HELPERS.md](SAFE_POC_HELPERS.md) for the safety model.
