# Reconixia Lab Testing

Use this mode only against systems you own or intentionally vulnerable local labs.

## HackerOne Test Credentials

For HackerOne programs, use the program's credential/request flow if it is available on the program page. Some programs restrict credentials for new researchers. Do not try to bypass this; without test credentials, stay with public, low-volume recon and self-signup paths explicitly allowed by the program.

## Recommended Aggressive Labs

- OWASP Juice Shop: web app, auth flow, client-side JS, headers, paths.
- OWASP crAPI: API-heavy target for auth, object access and business logic practice.
- WebGoat: training app for controlled vulnerability practice.
- DVWA: classic web vulnerability lab.
- Damn Vulnerable GraphQL Application: GraphQL-specific practice.

## Docker Examples

Juice Shop:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Run Reconixia against the local lab:

```bash
./reconixia run \
  -target localhost \
  -seed-url http://localhost:3000 \
  -profile fast \
  -lab-mode \
  -reset-resume \
  -no-nuclei
```

Generate reports:

```bash
./reconixia-report -target localhost -lab-mode
./reconixia analyze -target localhost -provider local -lab-mode
```

The report includes an `Endpoint Probes` section. It probes endpoints discovered from JavaScript with safe `GET`, `HEAD`, and `OPTIONS` requests, then classifies them as `public_json`, `auth_required`, `method_not_allowed`, `public_html`, and similar triage states.

For JSON responses, Reconixia also runs a sensitive field classifier without storing raw response bodies. Field names such as `email`, `role`, `token`, `userId`, `balance`, `accountId`, and similar identifiers are summarized as categories with a risk score in `report.json`, `report.md`, and `report.html`.

## What Lab Mode Changes

By default Reconixia blocks localhost, private IPs and loopback targets to reduce SSRF-style mistakes. `-lab-mode` allows loopback/private lab targets but still blocks cloud metadata IPs such as `169.254.169.254` and `100.100.100.200`.

Use `-seed-url` for local apps running on custom ports. The normal `-target` value remains the workspace/report name and scope anchor.
