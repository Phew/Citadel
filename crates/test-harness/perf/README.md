# test-harness/perf — on-demand baselines

Grok-owned. Throughput and latency baselines for the **live compose stack**
on paths that exist today (M2 DM + delivery gateway). Measuring only — no
optimization, no service tuning.

## What it measures

| Scenario | What |
|---|---|
| **F2** | Group create + Welcome delivery (initiator phase, per-joiner join, full e2e) |
| **F4** | Encrypt+submit → foreign fanout decrypt RTT; sustained send throughput |
| **Subscribe** | Concurrent gateway subscribe; fanout to last of N subscribers |
| **Fetch** | `GET /v1/groups/{id}/messages?after=` at ADR-0005 `MESSAGES_PAGE_LIMIT` (500) |

## How to run

Stack must be up first (`just dev`). Missing stack → **hard failure**, never zeros.

```bash
just perf-baseline
# equivalent:
cargo run -p test-harness --bin perf-baseline -- \
  --write crates/test-harness/perf/baseline.json \
  --diff crates/test-harness/perf/baseline.json
```

Useful flags: `--skip-fetch` (skip the 550-message seed), `--f2-runs N`,
`--sub-n N`, `--fetch-seed N` (≥ 500).

This is **not** wired into default `cargo test` or every-push CI. It is a
manual / scheduled tool so it cannot become a flaky gate or a CI time sink.

## Baseline file

`baseline.json` is schema `citadel-perf-baseline-v1`, produced by a successful
`just perf-baseline` against a live stack. It is **not** checked in as zeros —
PLAN §13 forbids a green empty report. A real run is committed with environment
metadata; later runs `--diff` against it.

Every report embeds the environment (hostname, OS, arch, CPU count, rustc, git
SHA, timestamp, stack note). A baseline without its environment is noise; do
not strip it.

`--diff PATH` prints p50 deltas vs a prior report (>25% called out).

## Loud failure contract (PLAN §13)

`require_stack` runs before any scenario. Unreachable health endpoints abort
with a message naming the service and `just dev`. Empty or zeroed reports
are never written on failure.
