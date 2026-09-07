# Reconixia Private Beta Runbook

This runbook is the default operating checklist for private, authorized bug bounty use.

## 1. Preflight

Run this before real target work:

```bash
make ci
./reconixia version
./reconixia doctor
```

Keep API keys, cookies, cloud tokens, HAR files, generated reports, and `.env` files out of git.

## 2. Safe Recon Default

Use the resumable low-noise path first:

```bash
make full-scan-resume TARGET=example.com PROFILE=stealth H1_USER=aello RESET=true
```

Use `PROFILE=balanced` only after confirming the program scope and rate limits. Keep `nuclei`, port scans, screenshots, and 403 candidate modules explicit.

## 3. Browser Recon

Load `browser-extension/reconixia-companion` in Chrome Developer Mode.

Configure only the current program's in-scope domains. Scan the active tab and review:

- first-party secrets/configs/endpoints
- third-party signals separately
- browser storage findings
- safe path probe output

Do not report public third-party keys unless you can show in-scope impact.

## 4. IDOR / BOLA

Use only owned accounts and program-approved aliases.

```bash
export RECONIXIA_IDOR_COOKIE_A='account-a-cookie-header'
export RECONIXIA_IDOR_COOKIE_B='account-b-cookie-header'

make idor \
  TARGET=example.com \
  IDOR_INPUT=captures/example-account-a-detail.jsonl \
  IDOR_RULES=examples/program-policies/example.idor-policy.json \
  H1_USER=aello \
  IDOR_RATE=2 \
  IDOR_MAX=50
```

Good captures include object-detail reads: orders, shipments, conversations, listings, inventory, payouts, addresses, seller settings, and account settings. Generic dashboard and `me` queries are weak signals.

Treat `possible_idor` as a lead, not a finished report. Manually confirm with owned accounts, avoid destructive actions, and stop immediately if unrelated user data appears.

## 5. AI Triage

Use local analysis first:

```bash
make structured-ai TARGET=example.com
```

Provider analysis is optional:

```bash
./reconixia analyze -target example.com -provider openrouter -model deepseek/deepseek-r1
```

Before provider upload, confirm reports are redacted and do not include cookies, bearer tokens, private keys, or unrelated user data.

## 6. Report Quality Gate

A finding is reportable only when it has:

- exact affected asset
- reproducible steps
- safe proof of impact
- request/response evidence with secrets redacted
- program rule alignment
- clear expected vs actual behavior

Do not submit missing headers, generic admin paths, empty GraphQL responses, public endpoints, or scanner-only output without concrete impact.

## 7. Cloud Worker Gate

Use cloud only when local scanning is unsuitable.

- Set `SSH_CIDR` to your current `/32`.
- Use strict SSH host key verification when possible.
- Run cleanup after every worker job.
- Verify the provider API no longer lists the worker.

## 8. End Of Run

```bash
make snapshot TARGET=example.com
make report TARGET=example.com
git status --short
```

Delete or move sensitive captures before committing. Keep only sanitized examples and code.
