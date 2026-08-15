//! On-demand performance baselines for the live compose stack.
//!
//! Measures paths that exist on main today (M2 DM + delivery gateway).
//! Does **not** run in default CI; invoke explicitly:
//!
//! ```text
//! just perf-baseline
//! # or:
//! cargo run -p test-harness --bin perf-baseline -- --write crates/test-harness/perf/baseline.json
//! ```
//!
//! PLAN §13: if the stack is missing, this process fails loudly. It never
//! writes zeros or a green empty report.

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use citadel_core::group::DmGroup;
use citadel_proto::delivery::{GatewayClientFrame, GatewayServerFrame, MESSAGES_PAGE_LIMIT};
use citadel_proto::envelope::EnvelopeKind;
use citadel_proto::ids::GroupId;
use serde::{Deserialize, Serialize};
use test_harness::client::TestClient;
use test_harness::dm::{self, log_anchor, DmClient, GatewaySocket, LiveKtVerifier};
use test_harness::stack::{probe_client, require_stack};

// ---------- environment capture ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Environment {
    hostname: String,
    os: String,
    arch: String,
    cpu_count: usize,
    rustc: String,
    git_sha: String,
    timestamp_utc: String,
    /// How the stack was expected (compose defaults); not a container cgroup dump.
    stack_note: String,
}

fn capture_env() -> Environment {
    let rustc = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let git_sha = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    Environment {
        hostname: std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".into()),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        cpu_count: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        rustc,
        git_sha,
        timestamp_utc: chrono_like_now(),
        stack_note: "docker compose deploy/docker-compose.yml (default published ports; no cgroup limits set by this harness)".into(),
    }
}

fn chrono_like_now() -> String {
    // Avoid pulling chrono into the binary graph solely for a stamp; use SystemTime.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

// ---------- metrics ----------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Percentiles {
    n: usize,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    min_ms: f64,
    max_ms: f64,
    mean_ms: f64,
}

fn percentiles(mut samples_ms: Vec<f64>) -> Percentiles {
    samples_ms.retain(|v| v.is_finite() && *v >= 0.0);
    if samples_ms.is_empty() {
        return Percentiles::default();
    }
    samples_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = samples_ms.len();
    let pct = |p: f64| {
        let idx = ((p * (n as f64 - 1.0)).round() as usize).min(n - 1);
        samples_ms[idx]
    };
    let sum: f64 = samples_ms.iter().sum();
    Percentiles {
        n,
        p50_ms: pct(0.50),
        p95_ms: pct(0.95),
        p99_ms: pct(0.99),
        min_ms: samples_ms[0],
        max_ms: samples_ms[n - 1],
        mean_ms: sum / n as f64,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct F2Baseline {
    /// End-to-end: provision already done; measure create+add+submit Welcome
    /// + all joiners receive Welcome + join + subscribe, per run.
    group_create_and_welcome_ms: Percentiles,
    /// Initiator-only: create_group + add_members + REST submit Welcome.
    initiator_create_submit_ms: Percentiles,
    /// Per-joiner: gateway connect → Welcome → join_from_welcome → subscribe.
    per_joiner_welcome_join_ms: Percentiles,
    clients_per_run: usize,
    runs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct F4Baseline {
    /// Submit encrypt+POST until foreign fanout arrives and decrypts.
    round_trip_ms: Percentiles,
    /// Sustained sends from initiator (no wait for fanout between sends).
    sustained_send_throughput_msg_per_s: f64,
    sustained_send_count: usize,
    sustained_send_wall_ms: f64,
    runs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubscribeBaseline {
    concurrent_subscribers: usize,
    /// Time for all N subscribers to connect + Subscribe + receive Subscribed.
    all_subscribe_ms: Percentiles,
    /// Fanout latency: submit one app msg → last of N subscribers receives it.
    fanout_to_last_subscriber_ms: Percentiles,
    runs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FetchBaseline {
    messages_seeded: usize,
    page_limit: usize,
    /// GET ?after=0 when ≥ page_limit messages exist.
    first_page_ms: Percentiles,
    first_page_count: usize,
    first_page_has_more: bool,
    /// Full catch-up walking pages until has_more is false.
    full_pagination_ms: Percentiles,
    pages_walked: usize,
    runs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineReport {
    schema: String,
    environment: Environment,
    f2: F2Baseline,
    f4: F4Baseline,
    subscribe: SubscribeBaseline,
    fetch: FetchBaseline,
}

// ---------- setup helpers (mirror m2_dm patterns) ----------

async fn provision(
    tag: &str,
    n: usize,
) -> Result<(
    Vec<DmClient>,
    LiveKtVerifier,
    test_harness::stack::StackEndpoints,
)> {
    let http = probe_client().context("harness probe client must build")?;
    let endpoints = require_stack(&http)
        .await
        .context("compose stack must be up (just dev); perf baselines fail loudly without it")?;
    let mut verifier = LiveKtVerifier::new(
        TestClient::new(http.clone(), endpoints.auth.clone()),
        log_anchor(),
    );
    let mut clients = Vec::with_capacity(n);
    for i in 0..n {
        let handle = format!("perf-{tag}-{i}-{}", uuid::Uuid::new_v4().simple());
        let (client, leaf) =
            DmClient::register(http.clone(), &endpoints.auth, &endpoints.delivery, &handle).await?;
        verifier.register_leaf(client.account_id, leaf);
        clients.push(client);
    }
    for c in &clients {
        if !verifier.attest(c.account_id, &c.identity_pubkey).await {
            bail!("KT attestation failed for {}", c.handle);
        }
    }
    Ok((clients, verifier, endpoints))
}

struct Established {
    group_id: GroupId,
    groups: Vec<DmGroup>,
    sockets: Vec<GatewaySocket>,
}

/// Timed F2 establish; returns timings in ms for initiator phase and each joiner.
async fn establish_group_timed(
    clients: &[DmClient],
    verifier: &LiveKtVerifier,
) -> Result<(Established, f64, Vec<f64>)> {
    let (initiator, joiners) = clients.split_first().expect("at least one client");

    for j in joiners {
        j.publish_key_packages(1).await?;
    }
    let mut key_packages = Vec::new();
    for j in joiners {
        key_packages.extend(
            initiator
                .fetch_key_packages(j.auth.base(), j.account_id)
                .await?,
        );
    }

    let t_init = Instant::now();
    let group_id = GroupId::new();
    let mut initiator_group = initiator.create_group(group_id)?;
    let out = initiator.add_members(&mut initiator_group, &key_packages, verifier)?;
    let recipient_ids = joiners.iter().map(|j| j.device_id).collect();
    initiator
        .submit(
            group_id,
            EnvelopeKind::Welcome,
            initiator_group.epoch(),
            &out.welcome_bytes,
            recipient_ids,
        )
        .await?;
    let initiator_ms = t_init.elapsed().as_secs_f64() * 1000.0;

    let mut groups = vec![initiator_group];
    let mut sockets = Vec::with_capacity(clients.len());
    let mut joiner_ms = Vec::with_capacity(joiners.len());

    for j in joiners {
        let t_j = Instant::now();
        let mut ws = j.gateway_connect().await?;
        let welcome = dm::recv_message_for(&mut ws, group_id, EnvelopeKind::Welcome).await?;
        let welcome_bytes = welcome.payload_bytes().context("decode welcome payload")?;
        let group = j.join_from_welcome(&welcome_bytes, verifier)?;
        dm::send_frame(
            &mut ws,
            &GatewayClientFrame::Subscribe {
                group_ids: vec![group_id],
            },
        )
        .await?;
        match dm::recv_frame(&mut ws).await? {
            GatewayServerFrame::Subscribed { .. } => {}
            other => bail!("expected Subscribed, got {other:?}"),
        }
        joiner_ms.push(t_j.elapsed().as_secs_f64() * 1000.0);
        groups.push(group);
        sockets.push(ws);
    }

    let mut ws = initiator.gateway_connect().await?;
    dm::send_frame(
        &mut ws,
        &GatewayClientFrame::Subscribe {
            group_ids: vec![group_id],
        },
    )
    .await?;
    match dm::recv_frame(&mut ws).await? {
        GatewayServerFrame::Subscribed { .. } => {}
        other => bail!("initiator expected Subscribed, got {other:?}"),
    }
    sockets.insert(0, ws);

    Ok((
        Established {
            group_id,
            groups,
            sockets,
        },
        initiator_ms,
        joiner_ms,
    ))
}

// ---------- scenarios ----------

async fn run_f2(runs: usize) -> Result<F2Baseline> {
    let mut e2e = Vec::new();
    let mut init = Vec::new();
    let mut joiners = Vec::new();
    for r in 0..runs {
        let (clients, verifier, _) = provision(&format!("f2{r}"), 3).await?;
        let t0 = Instant::now();
        let (_est, init_ms, joiner_ms) = establish_group_timed(&clients, &verifier).await?;
        e2e.push(t0.elapsed().as_secs_f64() * 1000.0);
        init.push(init_ms);
        joiners.extend(joiner_ms);
        eprintln!(
            "  f2 run {r}: e2e={:.1}ms initiator={:.1}ms",
            e2e[r], init_ms
        );
    }
    Ok(F2Baseline {
        group_create_and_welcome_ms: percentiles(e2e),
        initiator_create_submit_ms: percentiles(init),
        per_joiner_welcome_join_ms: percentiles(joiners),
        clients_per_run: 3,
        runs,
    })
}

async fn run_f4(runs: usize, sustained_count: usize) -> Result<F4Baseline> {
    let mut rtts = Vec::new();
    let mut sustained_rate = 0.0;
    let mut sustained_wall = 0.0;

    for r in 0..runs {
        let (clients, verifier, _) = provision(&format!("f4{r}"), 2).await?;
        let mut est = establish_group_timed(&clients, &verifier).await?.0;
        let (alice, bob) = (&clients[0], &clients[1]);

        // Warm one round-trip.
        for i in 0..runs.max(5) {
            let plain = format!("perf-rtt-{r}-{i}");
            let t0 = Instant::now();
            alice
                .send_text(&mut est.groups[0], est.group_id, plain.as_bytes())
                .await?;
            let env = dm::recv_foreign_message_for(
                &mut est.sockets[1],
                est.group_id,
                EnvelopeKind::Application,
                bob.device_id,
            )
            .await?;
            let outcome = bob
                .process_envelope(&mut est.groups[1], &env, &verifier)?
                .context("expected application outcome")?;
            match outcome {
                citadel_core::group::ReceiveOutcome::Application(plaintext) => {
                    if plaintext != plain.as_bytes() {
                        bail!("plaintext mismatch on rtt sample");
                    }
                }
                other => bail!("expected Application, got {other:?}"),
            }
            rtts.push(t0.elapsed().as_secs_f64() * 1000.0);
        }

        // Sustained send (last run only — expensive).
        if r == runs - 1 {
            let t0 = Instant::now();
            for i in 0..sustained_count {
                let plain = format!("perf-sustained-{i}");
                alice
                    .send_text(&mut est.groups[0], est.group_id, plain.as_bytes())
                    .await?;
            }
            sustained_wall = t0.elapsed().as_secs_f64() * 1000.0;
            sustained_rate = (sustained_count as f64) / (sustained_wall / 1000.0);
            eprintln!(
                "  f4 sustained: {sustained_count} sends in {sustained_wall:.1}ms ({sustained_rate:.1} msg/s)"
            );
        }
    }

    Ok(F4Baseline {
        round_trip_ms: percentiles(rtts),
        sustained_send_throughput_msg_per_s: sustained_rate,
        sustained_send_count: sustained_count,
        sustained_send_wall_ms: sustained_wall,
        runs,
    })
}

async fn run_subscribe(runs: usize, n_subs: usize) -> Result<SubscribeBaseline> {
    let mut all_sub = Vec::new();
    let mut fanout = Vec::new();

    for r in 0..runs {
        // 1 initiator + (n_subs-1) joiners so we have n_subs sockets subscribed.
        let n_clients = n_subs;
        let (clients, verifier, _) = provision(&format!("sub{r}"), n_clients).await?;
        // establish_group already subscribes everyone; measure re-subscribe
        // on fresh sockets for pure subscribe path cost.
        let mut est = establish_group_timed(&clients, &verifier).await?.0;

        // Drop existing sockets and re-open concurrent subscribe.
        est.sockets.clear();
        let t0 = Instant::now();
        let mut sockets = Vec::new();
        for c in &clients {
            let mut ws = c.gateway_connect().await?;
            dm::send_frame(
                &mut ws,
                &GatewayClientFrame::Subscribe {
                    group_ids: vec![est.group_id],
                },
            )
            .await?;
            match dm::recv_frame(&mut ws).await? {
                GatewayServerFrame::Subscribed { .. } => {}
                other => bail!("expected Subscribed, got {other:?}"),
            }
            sockets.push(ws);
        }
        all_sub.push(t0.elapsed().as_secs_f64() * 1000.0);
        est.sockets = sockets;

        // Fanout to last subscriber.
        let plain = format!("perf-fanout-{r}");
        let t1 = Instant::now();
        clients[0]
            .send_text(&mut est.groups[0], est.group_id, plain.as_bytes())
            .await?;
        // Every non-sender must see it.
        for (i, client) in clients.iter().enumerate().skip(1) {
            let _ = dm::recv_foreign_message_for(
                &mut est.sockets[i],
                est.group_id,
                EnvelopeKind::Application,
                client.device_id,
            )
            .await?;
        }
        fanout.push(t1.elapsed().as_secs_f64() * 1000.0);
        eprintln!(
            "  subscribe run {r}: all_sub={:.1}ms fanout_last={:.1}ms",
            all_sub[r], fanout[r]
        );
    }

    Ok(SubscribeBaseline {
        concurrent_subscribers: n_subs,
        all_subscribe_ms: percentiles(all_sub),
        fanout_to_last_subscriber_ms: percentiles(fanout),
        runs,
    })
}

async fn run_fetch(runs: usize, seed_count: usize) -> Result<FetchBaseline> {
    validate_fetch_seed(seed_count)?;

    let mut first_page_ms = Vec::new();
    let mut full_ms = Vec::new();
    let mut first_count = 0usize;
    let mut first_has_more = false;
    let mut pages_walked = 0usize;

    for r in 0..runs {
        let (clients, verifier, _) = provision(&format!("fetch{r}"), 2).await?;
        let mut est = establish_group_timed(&clients, &verifier).await?.0;
        let alice = &clients[0];

        eprintln!("  fetch run {r}: seeding {seed_count} application messages…");
        for i in 0..seed_count {
            let plain = format!("perf-page-seed-{i}");
            alice
                .send_text(&mut est.groups[0], est.group_id, plain.as_bytes())
                .await?;
            if (i + 1) % 100 == 0 {
                eprintln!("    seeded {}", i + 1);
            }
        }

        let t0 = Instant::now();
        let page = alice.sync(est.group_id, 0).await?;
        first_page_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
        first_count = page.messages.len();
        first_has_more = page.has_more;
        if first_count > MESSAGES_PAGE_LIMIT {
            bail!("page returned {first_count} > MESSAGES_PAGE_LIMIT {MESSAGES_PAGE_LIMIT}");
        }
        if !first_has_more {
            bail!("expected has_more=true after seeding {seed_count} messages");
        }

        let t1 = Instant::now();
        let mut after = 0u64;
        let mut pages = 0usize;
        let mut total = 0usize;
        loop {
            let page = alice.sync(est.group_id, after).await?;
            pages += 1;
            total += page.messages.len();
            after = page.next_after;
            if !page.has_more {
                break;
            }
            if pages > 20 {
                bail!("pagination did not terminate after 20 pages");
            }
        }
        full_ms.push(t1.elapsed().as_secs_f64() * 1000.0);
        pages_walked = pages;
        if total < seed_count {
            bail!("pagination returned {total} < seeded {seed_count}");
        }
        eprintln!(
            "  fetch run {r}: first_page={:.1}ms count={first_count} has_more={first_has_more}; full={:.1}ms pages={pages}",
            first_page_ms[r],
            full_ms[r]
        );
    }

    Ok(FetchBaseline {
        messages_seeded: seed_count,
        page_limit: MESSAGES_PAGE_LIMIT,
        first_page_ms: percentiles(first_page_ms),
        first_page_count: first_count,
        first_page_has_more: first_has_more,
        full_pagination_ms: percentiles(full_ms),
        pages_walked,
        runs,
    })
}

// ---------- CLI ----------

#[derive(Debug)]
struct Args {
    write: Option<PathBuf>,
    diff: Option<PathBuf>,
    f2_runs: usize,
    f4_runs: usize,
    sustained: usize,
    sub_runs: usize,
    sub_n: usize,
    fetch_runs: usize,
    /// Messages to seed for pagination (must be ≥ 500).
    fetch_seed: usize,
    skip_fetch: bool,
}

fn parse_args() -> Result<Args> {
    let mut write = None;
    let mut diff = None;
    let mut f2_runs = 3;
    let mut f4_runs = 3;
    let mut sustained = 50;
    let mut sub_runs = 3;
    let mut sub_n = 5;
    let mut fetch_runs = 1;
    let mut fetch_seed = MESSAGES_PAGE_LIMIT + 50; // 550
    let mut skip_fetch = false;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--write" => {
                write = Some(PathBuf::from(args.next().context("--write needs a path")?));
            }
            "--diff" => {
                diff = Some(PathBuf::from(args.next().context("--diff needs a path")?));
            }
            "--f2-runs" => f2_runs = args.next().context("n")?.parse()?,
            "--f4-runs" => f4_runs = args.next().context("n")?.parse()?,
            "--sustained" => sustained = args.next().context("n")?.parse()?,
            "--sub-runs" => sub_runs = args.next().context("n")?.parse()?,
            "--sub-n" => sub_n = args.next().context("n")?.parse()?,
            "--fetch-runs" => fetch_runs = args.next().context("n")?.parse()?,
            "--fetch-seed" => fetch_seed = args.next().context("n")?.parse()?,
            "--skip-fetch" => skip_fetch = true,
            "--help" | "-h" => {
                eprintln!(
                    "perf-baseline — on-demand baselines against the live compose stack\n\
                     \n\
                     Options:\n\
                       --write PATH     write BaselineReport JSON\n\
                       --diff PATH      compare against a prior baseline (warn on large deltas)\n\
                       --f2-runs N      default 3\n\
                       --f4-runs N      default 3\n\
                       --sustained N    sustained send count (default 50)\n\
                       --sub-runs N     default 3\n\
                       --sub-n N        concurrent subscribers (default 5)\n\
                       --fetch-runs N   default 1 (seeding 500+ msgs is slow)\n\
                       --fetch-seed N   default 550 (≥ MESSAGES_PAGE_LIMIT)\n\
                       --skip-fetch     skip pagination scenario\n\
                     \n\
                     Fails loudly if the stack is unreachable (PLAN §13)."
                );
                std::process::exit(0);
            }
            other => bail!("unknown arg {other}; try --help"),
        }
    }

    Ok(Args {
        write,
        diff,
        f2_runs,
        f4_runs,
        sustained,
        sub_runs,
        sub_n,
        fetch_runs,
        fetch_seed,
        skip_fetch,
    })
}

/// One latency metric compared between two reports (p50 ms, percent change).
#[derive(Debug, Clone, PartialEq)]
struct MetricDelta {
    name: &'static str,
    old_ms: f64,
    new_ms: f64,
    /// Percent change: `(new - old) / old * 100`. Only defined when `old_ms > 0`.
    pct: f64,
}

/// Pure comparison of p50 latency metrics. Used by `--diff` and unit-tested so
/// a same-path write-before-load bug cannot silently report all +0.0%.
fn compare_p50_deltas(prev: &BaselineReport, cur: &BaselineReport) -> Vec<MetricDelta> {
    let mut out = Vec::new();
    let mut push = |name: &'static str, old: f64, new: f64| {
        if old > 0.0 {
            out.push(MetricDelta {
                name,
                old_ms: old,
                new_ms: new,
                pct: (new - old) / old * 100.0,
            });
        }
    };
    push(
        "f2 e2e p50",
        prev.f2.group_create_and_welcome_ms.p50_ms,
        cur.f2.group_create_and_welcome_ms.p50_ms,
    );
    push(
        "f4 rtt p50",
        prev.f4.round_trip_ms.p50_ms,
        cur.f4.round_trip_ms.p50_ms,
    );
    push(
        "subscribe all p50",
        prev.subscribe.all_subscribe_ms.p50_ms,
        cur.subscribe.all_subscribe_ms.p50_ms,
    );
    push(
        "fetch first page p50",
        prev.fetch.first_page_ms.p50_ms,
        cur.fetch.first_page_ms.p50_ms,
    );
    out
}

fn diff_reports(prev: &BaselineReport, cur: &BaselineReport) {
    eprintln!(
        "\n=== diff vs prior baseline (git {}) ===",
        prev.environment.git_sha
    );
    for d in compare_p50_deltas(prev, cur) {
        let flag = if d.pct > 25.0 {
            "  << slower"
        } else if d.pct < -25.0 {
            "  << faster"
        } else {
            ""
        };
        eprintln!(
            "  {}: {:.2} -> {:.2} ms ({:+.1}%){flag}",
            d.name, d.old_ms, d.new_ms, d.pct
        );
    }
    eprintln!(
        "  f4 sustained msg/s: {:.1} -> {:.1}",
        prev.f4.sustained_send_throughput_msg_per_s, cur.f4.sustained_send_throughput_msg_per_s
    );
}

/// Refuse decorative fetch baselines that never hit the page limit.
fn validate_fetch_seed(seed_count: usize) -> Result<()> {
    if seed_count < MESSAGES_PAGE_LIMIT {
        bail!(
            "seed_count {seed_count} < MESSAGES_PAGE_LIMIT {MESSAGES_PAGE_LIMIT}; refuse decorative baseline"
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    eprintln!("perf-baseline: requiring live stack…");
    // Loud failure before any scenario if stack is down.
    {
        let http = probe_client()?;
        require_stack(&http).await?;
    }
    eprintln!("stack healthy. environment capture…");
    let environment = capture_env();
    eprintln!(
        "  host={} os={} arch={} cpus={} rustc={} git={}",
        environment.hostname,
        environment.os,
        environment.arch,
        environment.cpu_count,
        environment.rustc,
        environment.git_sha
    );

    eprintln!("\n--- F2 group create + Welcome ---");
    let f2 = run_f2(args.f2_runs).await?;

    eprintln!("\n--- F4 send/receive RTT + sustained send ---");
    let f4 = run_f4(args.f4_runs, args.sustained).await?;

    eprintln!("\n--- gateway subscribe under concurrency ---");
    let subscribe = run_subscribe(args.sub_runs, args.sub_n).await?;

    eprintln!("\n--- message fetch pagination (page limit {MESSAGES_PAGE_LIMIT}) ---");
    let fetch = if args.skip_fetch {
        eprintln!("  skipped (--skip-fetch)");
        FetchBaseline {
            messages_seeded: 0,
            page_limit: MESSAGES_PAGE_LIMIT,
            first_page_ms: Percentiles::default(),
            first_page_count: 0,
            first_page_has_more: false,
            full_pagination_ms: Percentiles::default(),
            pages_walked: 0,
            runs: 0,
        }
    } else {
        run_fetch(args.fetch_runs, args.fetch_seed).await?
    };

    let report = BaselineReport {
        schema: "citadel-perf-baseline-v1".into(),
        environment,
        f2,
        f4,
        subscribe,
        fetch,
    };

    let json = serde_json::to_string_pretty(&report).context("serialize report")?;
    println!("{json}");

    // Load --diff into memory *before* --write. `just perf-baseline` passes the
    // same path to both flags; writing first would overwrite the prior baseline
    // and make every compare report +0.0% against itself.
    let prior: Option<BaselineReport> = if let Some(path) = &args.diff {
        if path.exists() {
            let text =
                fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
            Some(
                serde_json::from_str(&text)
                    .with_context(|| format!("parse prior baseline {}", path.display()))?,
            )
        } else {
            eprintln!("--diff {}: file missing, skip compare", path.display());
            None
        }
    } else {
        None
    };

    if let Some(path) = &args.write {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(path, &json).with_context(|| format!("write {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    }

    if let Some(prev) = &prior {
        diff_reports(prev, &report);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_empty_is_default_not_nan() {
        let p = percentiles(vec![]);
        assert_eq!(p.n, 0);
        assert_eq!(p.p50_ms, 0.0);
        assert_eq!(p.mean_ms, 0.0);
        assert!(p.min_ms.is_finite());
    }

    #[test]
    fn percentiles_drops_nan_and_negative() {
        let p = percentiles(vec![10.0, f64::NAN, -1.0, 20.0, 30.0]);
        assert_eq!(p.n, 3);
        assert_eq!(p.min_ms, 10.0);
        assert_eq!(p.max_ms, 30.0);
        assert!((p.mean_ms - 20.0).abs() < 1e-9);
    }

    #[test]
    fn percentiles_single_sample() {
        let p = percentiles(vec![42.0]);
        assert_eq!(p.n, 1);
        assert_eq!(p.p50_ms, 42.0);
        assert_eq!(p.p95_ms, 42.0);
        assert_eq!(p.p99_ms, 42.0);
        assert_eq!(p.min_ms, 42.0);
        assert_eq!(p.max_ms, 42.0);
        assert_eq!(p.mean_ms, 42.0);
    }

    #[test]
    fn percentiles_ordered_ten() {
        let samples: Vec<f64> = (1..=10).map(|i| i as f64).collect();
        let p = percentiles(samples);
        assert_eq!(p.n, 10);
        assert_eq!(p.min_ms, 1.0);
        assert_eq!(p.max_ms, 10.0);
        // p50 at index round(0.5 * 9) = 5 → value 6 (1-indexed sample 6)
        assert_eq!(p.p50_ms, 6.0);
    }

    #[test]
    fn page_limit_constant_matches_adr0005() {
        assert_eq!(MESSAGES_PAGE_LIMIT, 500);
    }

    #[test]
    fn baseline_report_json_roundtrip_schema() {
        let report = BaselineReport {
            schema: "citadel-perf-baseline-v1".into(),
            environment: Environment {
                hostname: "test-host".into(),
                os: "windows".into(),
                arch: "x86_64".into(),
                cpu_count: 8,
                rustc: "rustc test".into(),
                git_sha: "deadbeef".into(),
                timestamp_utc: "unix:0".into(),
                stack_note: "unit-test".into(),
            },
            f2: F2Baseline {
                group_create_and_welcome_ms: percentiles(vec![1.0, 2.0, 3.0]),
                initiator_create_submit_ms: percentiles(vec![1.0]),
                per_joiner_welcome_join_ms: percentiles(vec![2.0, 4.0]),
                clients_per_run: 3,
                runs: 1,
            },
            f4: F4Baseline {
                round_trip_ms: percentiles(vec![5.0, 6.0, 7.0]),
                sustained_send_throughput_msg_per_s: 12.5,
                sustained_send_count: 50,
                sustained_send_wall_ms: 4000.0,
                runs: 1,
            },
            subscribe: SubscribeBaseline {
                concurrent_subscribers: 5,
                all_subscribe_ms: percentiles(vec![10.0]),
                fanout_to_last_subscriber_ms: percentiles(vec![11.0]),
                runs: 1,
            },
            fetch: FetchBaseline {
                messages_seeded: 550,
                page_limit: MESSAGES_PAGE_LIMIT,
                first_page_ms: percentiles(vec![100.0]),
                first_page_count: 500,
                first_page_has_more: true,
                full_pagination_ms: percentiles(vec![200.0]),
                pages_walked: 2,
                runs: 1,
            },
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let back: BaselineReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.schema, "citadel-perf-baseline-v1");
        assert_eq!(back.environment.git_sha, "deadbeef");
        assert_eq!(back.fetch.page_limit, 500);
        assert_eq!(back.fetch.first_page_count, 500);
        assert!(back.fetch.first_page_has_more);
        assert!((back.f4.sustained_send_throughput_msg_per_s - 12.5).abs() < 1e-9);
        // Environment is mandatory: a report without it would fail deserialize of this shape.
        assert!(!back.environment.hostname.is_empty());
        assert!(!back.environment.os.is_empty());
    }

    #[test]
    fn fetch_seed_below_page_limit_is_rejected() {
        assert!(validate_fetch_seed(MESSAGES_PAGE_LIMIT - 1).is_err());
        assert!(validate_fetch_seed(0).is_err());
        assert!(validate_fetch_seed(MESSAGES_PAGE_LIMIT).is_ok());
        assert!(validate_fetch_seed(MESSAGES_PAGE_LIMIT + 50).is_ok());
    }

    fn sample_report(f2_p50_ms: f64) -> BaselineReport {
        BaselineReport {
            schema: "citadel-perf-baseline-v1".into(),
            environment: Environment {
                hostname: "test-host".into(),
                os: "windows".into(),
                arch: "x86_64".into(),
                cpu_count: 8,
                rustc: "rustc test".into(),
                git_sha: "deadbeef".into(),
                timestamp_utc: "unix:0".into(),
                stack_note: "unit-test".into(),
            },
            f2: F2Baseline {
                group_create_and_welcome_ms: percentiles(vec![f2_p50_ms]),
                initiator_create_submit_ms: percentiles(vec![1.0]),
                per_joiner_welcome_join_ms: percentiles(vec![2.0]),
                clients_per_run: 3,
                runs: 1,
            },
            f4: F4Baseline {
                round_trip_ms: percentiles(vec![5.0]),
                sustained_send_throughput_msg_per_s: 12.5,
                sustained_send_count: 50,
                sustained_send_wall_ms: 4000.0,
                runs: 1,
            },
            subscribe: SubscribeBaseline {
                concurrent_subscribers: 5,
                all_subscribe_ms: percentiles(vec![10.0]),
                fanout_to_last_subscriber_ms: percentiles(vec![11.0]),
                runs: 1,
            },
            fetch: FetchBaseline {
                messages_seeded: 550,
                page_limit: MESSAGES_PAGE_LIMIT,
                first_page_ms: percentiles(vec![100.0]),
                first_page_count: 500,
                first_page_has_more: true,
                full_pagination_ms: percentiles(vec![200.0]),
                pages_walked: 2,
                runs: 1,
            },
        }
    }

    /// Would have caught write-before-load: if comparison always saw current vs
    /// current (or always zeroed), this fails. Same-path --write/--diff must
    /// load prior first, then write, then compare against the in-memory prior.
    #[test]
    fn compare_reports_nonzero_delta_when_metrics_differ() {
        let prior = sample_report(100.0);
        let current = sample_report(150.0); // +50% on f2 e2e p50
        let deltas = compare_p50_deltas(&prior, &current);
        let f2 = deltas
            .iter()
            .find(|d| d.name == "f2 e2e p50")
            .expect("f2 e2e p50 present");
        assert!(
            f2.pct.abs() > 0.0,
            "differing reports must produce a nonzero delta, got {f2:?}"
        );
        assert!(
            (f2.pct - 50.0).abs() < 1e-9,
            "expected +50%, got {}",
            f2.pct
        );
        assert_eq!(f2.old_ms, 100.0);
        assert_eq!(f2.new_ms, 150.0);

        // Identity compare still yields zeros (the bug mode); ensure that path
        // is distinguishable from a real regression.
        let self_deltas = compare_p50_deltas(&current, &current);
        assert!(
            self_deltas.iter().all(|d| d.pct == 0.0),
            "self-compare must be all +0.0%, got {self_deltas:?}"
        );
    }
}
