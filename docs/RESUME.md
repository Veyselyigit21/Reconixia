# Reconixia Resume / Checkpoint

Reconixia now has two resume layers.

## Native Go Resume

Use native granular resume directly through the active binary:

```bash
./reconixia run -target example.com -profile balanced -resume
```

Reset the native checkpoint and start over:

```bash
./reconixia run -target example.com -profile balanced -resume -reset-resume
```

Native checkpoint file:

```txt
results/example.com/checkpoint_run.json
```

Tracked native steps:

```txt
subfinder
httpx
passive
js
discover
headers
nuclei
takeover
report
```

Each step persists its own output files under `results/<target>/raw` or `results/<target>/processed`, so interrupted scans can reuse prior work instead of repeating the entire recon phase.

## Full Scan Resume

The full-scan wrapper still tracks the higher-level workflow:

```bash
make full-scan-resume TARGET=example.com
```

Reset both the wrapper flow and native Go checkpoint:

```bash
make full-scan-resume TARGET=example.com RESET=true
```

Wrapper checkpoint file:

```txt
results/example.com/checkpoint_full_scan.json
```

Wrapper steps:

```txt
recon
augment
report
```

`scripts/full_scan_resume.sh` calls `./reconixia run ... -resume`, so the `recon` phase itself is granular even when the wrapper is used.
