/// Test mode — probe a list of DNS resolvers through iodine and rank by RTT.
///
/// For each resolver:
///   1. Spawn iodine with the resolver substituted into iodine_args.
///   2. Wait for the tunnel TUN IP to appear (with connect_timeout_secs).
///   3. Open a TCP connection to server_tun_ip:test_port.
///   4. Send `pings` 8-byte echo messages and measure round-trip time.
///   5. Kill iodine and wait briefly for the TUN to be torn down.
///
/// Results are sorted by average RTT (unreachable resolvers sort last)
/// and written to results.csv in the current directory.
use std::io::Write;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

const CSV_PATH: &str = "results.csv";

use crate::config::TestConfig;
use crate::iodine::IodineProcess;

const RESOLVER_PLACEHOLDER: &str = "RESOLVER";
// Time to wait after killing iodine before starting the next test,
// so the kernel tears down the TUN interface.
const TEARDOWN_PAUSE: Duration = Duration::from_secs(3);

// ── public entry point ────────────────────────────────────────────────────────

pub async fn run(cfg: TestConfig) -> Result<()> {
    if cfg.resolvers.is_empty() {
        anyhow::bail!("resolvers list is empty");
    }
    if !cfg.iodine_args.iter().any(|a| a == RESOLVER_PLACEHOLDER) {
        anyhow::bail!(
            "iodine_args must contain the string \"{RESOLVER_PLACEHOLDER}\" \
             as a placeholder for the resolver IP"
        );
    }

    println!(
        "Testing {} resolver(s) — {} ping(s) each\n",
        cfg.resolvers.len(),
        cfg.pings
    );

    let mut results: Vec<ProbeResult> = Vec::with_capacity(cfg.resolvers.len());

    for (i, resolver) in cfg.resolvers.iter().enumerate() {
        print!("[{}/{}] {resolver} … ", i + 1, cfg.resolvers.len());
        // flush so the user sees the line before we block
        let _ = std::io::Write::flush(&mut std::io::stdout());

        let result = probe(&cfg, resolver).await;

        match result.outcome {
            Outcome::Ok { avg_rtt, .. } => {
                println!("{:.0} ms avg", avg_rtt.as_secs_f64() * 1000.0)
            }
            Outcome::TunnelTimeout => println!("TUNNEL TIMEOUT"),
            Outcome::ConnectFailed(ref e) => println!("CONNECT FAILED ({e})"),
            Outcome::NoPings => println!("NO PINGS RETURNED"),
        }

        results.push(result);
    }

    // Sort: successful probes first by avg RTT, failures last.
    results.sort_by_key(avg_micros);

    print_table(&results);
    write_csv(&results)?;
    Ok(())
}

// ── probe a single resolver ───────────────────────────────────────────────────

struct ProbeResult {
    resolver: String,
    outcome: Outcome,
}

enum Outcome {
    Ok {
        rtts: Vec<Duration>,
        avg_rtt: Duration,
    },
    TunnelTimeout,
    ConnectFailed(String),
    NoPings,
}

async fn probe(cfg: &TestConfig, resolver: &str) -> ProbeResult {
    let args: Vec<String> = cfg
        .iodine_args
        .iter()
        .map(|a| {
            if a == RESOLVER_PLACEHOLDER {
                resolver.to_owned()
            } else {
                a.clone()
            }
        })
        .collect();

    let iodine = match IodineProcess::spawn(&cfg.iodine_bin, &args).await {
        Ok(p) => p,
        Err(e) => {
            return ProbeResult {
                resolver: resolver.to_owned(),
                outcome: Outcome::ConnectFailed(e.to_string()),
            }
        }
    };

    // Wait for tunnel to come up.
    let tunnel_up = time::timeout(
        Duration::from_secs(cfg.connect_timeout_secs),
        IodineProcess::wait_for_ip(&cfg.tun_ip),
    )
    .await;

    if tunnel_up.is_err() || tunnel_up.unwrap().is_err() {
        drop(iodine);
        time::sleep(TEARDOWN_PAUSE).await;
        return ProbeResult {
            resolver: resolver.to_owned(),
            outcome: Outcome::TunnelTimeout,
        };
    }

    // TCP ping.
    let addr = format!("{}:{}", cfg.server_tun_ip, cfg.test_port);
    let connect = time::timeout(
        Duration::from_secs(cfg.ping_timeout_secs),
        TcpStream::connect(&addr),
    )
    .await;

    let stream = match connect {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            drop(iodine);
            time::sleep(TEARDOWN_PAUSE).await;
            return ProbeResult {
                resolver: resolver.to_owned(),
                outcome: Outcome::ConnectFailed(e.to_string()),
            };
        }
        Err(_) => {
            drop(iodine);
            time::sleep(TEARDOWN_PAUSE).await;
            return ProbeResult {
                resolver: resolver.to_owned(),
                outcome: Outcome::ConnectFailed("connect timed out".into()),
            };
        }
    };

    let rtts = tcp_ping(
        stream,
        cfg.pings,
        Duration::from_secs(cfg.ping_timeout_secs),
    )
    .await;

    // Tear down iodine before moving to the next resolver.
    drop(iodine);
    time::sleep(TEARDOWN_PAUSE).await;

    if rtts.is_empty() {
        return ProbeResult {
            resolver: resolver.to_owned(),
            outcome: Outcome::NoPings,
        };
    }

    let avg_rtt = rtts.iter().sum::<Duration>() / rtts.len() as u32;
    ProbeResult {
        resolver: resolver.to_owned(),
        outcome: Outcome::Ok { rtts, avg_rtt },
    }
}

// ── TCP ping ──────────────────────────────────────────────────────────────────

/// Send `count` 8-byte echo messages and collect measured RTTs.
/// Stops early on any error or timeout.
async fn tcp_ping(stream: TcpStream, count: u32, timeout: Duration) -> Vec<Duration> {
    let (mut rx, mut tx) = stream.into_split();
    let mut rtts = Vec::with_capacity(count as usize);
    let mut buf = [0u8; 8];

    for seq in 0..count {
        // Payload: 4-byte seq + 4 zero bytes (server echoes it back verbatim).
        let payload = (seq as u64).to_be_bytes();
        let t0 = Instant::now();

        if tx.write_all(&payload).await.is_err() {
            break;
        }
        match time::timeout(timeout, rx.read_exact(&mut buf)).await {
            Ok(Ok(_)) => rtts.push(t0.elapsed()),
            _ => break,
        }
    }

    rtts
}

// ── output ────────────────────────────────────────────────────────────────────

fn avg_micros(r: &ProbeResult) -> u128 {
    match &r.outcome {
        Outcome::Ok { avg_rtt, .. } => avg_rtt.as_micros(),
        _ => u128::MAX,
    }
}

fn print_table(results: &[ProbeResult]) {
    println!("\n{:-<52}", "");
    println!(
        " {:<5} {:<18} {:>10} {:>10} {:>6}",
        "Rank", "Resolver", "Avg RTT", "Min RTT", "Pkts"
    );
    println!("{:-<52}", "");

    for (rank, r) in results.iter().enumerate() {
        match &r.outcome {
            Outcome::Ok { rtts, avg_rtt } => {
                let min_rtt = rtts.iter().min().copied().unwrap_or_default();
                println!(
                    " {:<5} {:<18} {:>9.0}ms {:>9.0}ms {:>6}",
                    rank + 1,
                    r.resolver,
                    avg_rtt.as_secs_f64() * 1000.0,
                    min_rtt.as_secs_f64() * 1000.0,
                    rtts.len(),
                );
            }
            Outcome::TunnelTimeout => {
                println!(
                    " {:<5} {:<18} {:>10} {:>10} {:>6}",
                    rank + 1,
                    r.resolver,
                    "TIMEOUT",
                    "—",
                    "0"
                );
            }
            Outcome::ConnectFailed(e) => {
                println!(
                    " {:<5} {:<18} {:>10} {:>10} {:>6}",
                    rank + 1,
                    r.resolver,
                    "FAILED",
                    e,
                    "0"
                );
            }
            Outcome::NoPings => {
                println!(
                    " {:<5} {:<18} {:>10} {:>10} {:>6}",
                    rank + 1,
                    r.resolver,
                    "NO REPLY",
                    "—",
                    "0"
                );
            }
        }
    }

    println!("{:-<52}", "");

    // Print best resolver if any succeeded.
    if let Some(best) = results
        .iter()
        .find(|r| matches!(r.outcome, Outcome::Ok { .. }))
    {
        if let Outcome::Ok { avg_rtt, .. } = &best.outcome {
            println!(
                "\nBest resolver: {} ({:.0} ms avg)",
                best.resolver,
                avg_rtt.as_secs_f64() * 1000.0
            );
        }
    }
}

fn write_csv(results: &[ProbeResult]) -> Result<()> {
    let mut f = std::fs::File::create(CSV_PATH)?;
    writeln!(f, "rank,resolver,avg_rtt_ms,min_rtt_ms,pkts,status")?;
    for (rank, r) in results.iter().enumerate() {
        match &r.outcome {
            Outcome::Ok { rtts, avg_rtt } => {
                let min_ms = rtts.iter().min().copied().unwrap_or_default().as_secs_f64() * 1000.0;
                writeln!(
                    f,
                    "{},{},{:.3},{:.3},{},ok",
                    rank + 1,
                    r.resolver,
                    avg_rtt.as_secs_f64() * 1000.0,
                    min_ms,
                    rtts.len(),
                )?;
            }
            Outcome::TunnelTimeout => {
                writeln!(f, "{},{},,,0,tunnel_timeout", rank + 1, r.resolver)?;
            }
            Outcome::ConnectFailed(e) => {
                // Escape any commas in the error string.
                let e_safe = e.replace(',', ";");
                writeln!(
                    f,
                    "{},{},,,0,connect_failed: {e_safe}",
                    rank + 1,
                    r.resolver
                )?;
            }
            Outcome::NoPings => {
                writeln!(f, "{},{},,,0,no_pings", rank + 1, r.resolver)?;
            }
        }
    }
    println!("\nResults saved to {CSV_PATH}");
    Ok(())
}
