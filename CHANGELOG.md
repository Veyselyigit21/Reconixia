# Changelog

## 0.9.0-rc1 - 2026-05-11

Release-candidate hardening pass for Reconixia.

- Added strict SSH host-key workflow with known_hosts support and explicit ephemeral accept mode.
- Added DigitalOcean and Hetzner cloud firewalls with SSH CIDR allowlisting.
- Added workspace locking to protect report files from concurrent scans.
- Added local redaction before reports, logs, and AI analysis.
- Added native Go checkpoint resume for recon steps: subfinder, httpx, passive, js, discover, headers, nuclei, takeover, and report.
- Added interactive HTML report filters for finding type, confidence, high-confidence-only, and search.
- Added HTML diff output via `reconixia-diff -html`.
- Moved takeover indicators into a provider fingerprint database with unit tests.
- Added release checks and reproducible release artifacts with SHA256SUMS and optional GPG signatures.
