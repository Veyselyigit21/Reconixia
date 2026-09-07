# Reconixia Release Checklist

Release is allowed only when every gate below is green.

## Required Gates

- `go test ./...`
- `go build ./cmd/...`
- `gofmt -l internal cmd` returns no files
- `bash -n scripts/*.sh scripts/lib/*.sh`
- `make release-artifacts VERSION=<release>` completes on a Unix-like shell
- `reconixia version` prints the intended release version
- `dist/<version>/` includes `reconixia-idor` for supported platforms
- `dist/<version>/SHA256SUMS` exists
- `dist/<version>/SHA256SUMS.asc` exists when a GPG signing key is available
- No generated binaries, reports, `.env`, keys, or known-hosts files staged
- Remote worker SSH uses known-hosts or explicit `--accept-host-key`
- Cloud worker SSH is limited with `--ssh-cidr` or auto-detected `/32`
- Reports and AI prompts are redacted before persistence or provider upload

## Bug Bounty Readiness

- Default scan must stay low-noise and authorized-scope only
- Active modules must require explicit flags or Make targets
- New findings should include confidence and manual verification guidance
- High-volume modules must have rate and limit controls
- Any cloud worker must be destroyed and verified after the run

## Stop-Ship Conditions

- CI is red
- A secret appears unredacted in `report.md`, `report.json`, `report.html`, or `ai_analysis.*`
- A scan can write to a workspace while another scan owns `.lock`
- Cloud worker leaves SSH open to `0.0.0.0/0`
- Release artifacts are missing checksums
- A module performs active bypass/exploitation by default
