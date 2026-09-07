# Reconixia Cloud Safety

Reconixia cloud workers are temporary VPS instances. The intended lifecycle is:

```txt
create worker -> attach restrictive firewall -> scan -> download results -> destroy worker and firewall
```

## Supported Providers

```txt
DigitalOcean
Hetzner Cloud
```

Relevant scripts:

```txt
scripts/cloud_do_safe.sh
scripts/cloud_do_worker.sh
scripts/cloud_hetzner_safe.sh
scripts/cloud_hetzner_worker.sh
scripts/cloud_cleanup.sh
```

## Firewall Defaults

Both cloud worker implementations create a temporary firewall before the scan.

Inbound:

```txt
tcp/22 from SSH_CIDR only
```

Outbound:

```txt
tcp/any to 0.0.0.0/0 and ::/0
udp/any to 0.0.0.0/0 and ::/0
icmp to 0.0.0.0/0 and ::/0
```

If `--ssh-cidr` is omitted, scripts try to auto-detect the operator's public IPv4 and normalize it as `/32`.

Examples:

```bash
make cloud-do TARGET=example.com DO_SSH_KEY_ID=123456 IDENTITY=~/.ssh/id_ed25519 SSH_CIDR=203.0.113.10/32
make cloud-hetzner TARGET=example.com HCLOUD_SSH_KEY=my-key IDENTITY=~/.ssh/id_ed25519 SSH_CIDR=203.0.113.10/32
```

## SSH Host Keys

`scripts/remote_existing.sh` supports strict known_hosts mode for long-lived hosts and explicit accept mode for ephemeral workers.

Strict mode:

```bash
./scripts/remote_existing.sh --host 203.0.113.20 --known-hosts .reconixia_known_hosts --strict-host-key yes -t example.com
```

Ephemeral cloud workers use `--accept-host-key` because the server is freshly created and destroyed in the same run.

## Cleanup

Worker scripts call cleanup on:

```txt
normal exit
error exit
CTRL+C / SIGINT
SIGTERM
```

Manual orphan cleanup:

```bash
make cloud-cleanup-do MAX_AGE_HOURS=6 APPLY=true
make cloud-cleanup-hetzner MAX_AGE_HOURS=6 APPLY=true
```

Dry-run cleanup:

```bash
make cloud-cleanup-do MAX_AGE_HOURS=6
make cloud-cleanup-hetzner MAX_AGE_HOURS=6
```

## Safe Assumptions

- Workers are temporary.
- `.env` and SSH private keys are never uploaded to remote hosts.
- Worker names use the `reconixia-worker-*` pattern.
- Cleanup scripts only target Reconixia-tagged or Reconixia-labeled workers.
- Hetzner firewall CIDRs are normalized so they comply with the current API requirement that CIDR host bits are not set.
