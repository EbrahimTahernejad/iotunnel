/// Server mode
///
/// Data flow:
///   client  →[DNS / iodined TUN]→  upstream UDP socket  →  backend
///   backend →  raw spoofed UDP  →  client's real IP:downstream_port
///
/// The client first sends a REGISTER packet through the tunnel to tell us
/// its real IP, downstream port, and which (fake) src IP:port to use.
use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::ServerConfig;
use crate::iodine::IodineProcess;
use crate::raw_send::{RawSendMsg, RawSender};

// ── protocol constants ────────────────────────────────────────────────────────

const TYPE_REGISTER: u8 = 0x01; // 13-byte payload (see below)
const TYPE_DATA: u8 = 0x02; // variable payload

// REGISTER payload layout (12 bytes after the type byte):
//   real_ip       [4]  big-endian
//   downstream_port[2]  big-endian
//   spoof_src_ip   [4]  big-endian
//   spoof_src_port [2]  big-endian

// ── client state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ClientInfo {
    real_ip: Ipv4Addr,
    downstream_port: u16,
    spoof_src_ip: Ipv4Addr,
    spoof_src_port: u16,
}

// ── entry point ───────────────────────────────────────────────────────────────

pub async fn run(cfg: ServerConfig) -> Result<()> {
    // 1. Start iodined and wait for its TUN interface to appear.
    let _iodine = IodineProcess::spawn(&cfg.iodined_bin, &cfg.iodined_args).await?;
    info!("waiting for TUN IP {}…", cfg.tun_ip);
    IodineProcess::wait_for_ip(&cfg.tun_ip).await?;

    // 2. Upstream socket — receives tunnel traffic from client.
    let tunnel_bind = format!("{}:{}", cfg.tun_ip, cfg.tunnel_port);
    let upstream = Arc::new(UdpSocket::bind(&tunnel_bind).await?);
    info!("upstream listening on {tunnel_bind}");

    // 3. Raw sender — sends spoofed UDP downstream to client.
    //    Queue depth of 8 k packets; drops on overflow (prefer loss over latency spike).
    let raw = RawSender::new(8192)?;

    // 4. Backend socket — proxies data to/from the local kcp/tuic server.
    let backend = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    backend.connect(&cfg.backend_addr).await?;
    info!("backend: {}", cfg.backend_addr);

    // 5. Shared client state (last registered client wins).
    let client: Arc<RwLock<Option<ClientInfo>>> = Arc::new(RwLock::new(None));

    // ── Task A: upstream (tunnel) → backend ──────────────────────────────────
    {
        let upstream = upstream.clone();
        let backend = backend.clone();
        let client = client.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let (n, _src) = match upstream.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("upstream recv: {e}");
                        continue;
                    }
                };
                if n == 0 {
                    continue;
                }

                match buf[0] {
                    TYPE_REGISTER if n == 13 => {
                        let ci = parse_register(&buf[1..13]);
                        info!(
                            "client registered: real={}:{} spoof={}:{}",
                            ci.real_ip, ci.downstream_port, ci.spoof_src_ip, ci.spoof_src_port,
                        );
                        *client.write().await = Some(ci);
                    }
                    TYPE_DATA if n > 1 => {
                        if let Err(e) = backend.send(&buf[1..n]).await {
                            warn!("backend send: {e}");
                        }
                    }
                    other => {
                        warn!("unknown packet type 0x{other:02x}, ignoring");
                    }
                }
            }
        });
    }

    // ── Task B: backend → downstream (raw spoofed UDP) ────────────────────────
    {
        let backend = backend.clone();
        let client = client.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let n = match backend.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        warn!("backend recv: {e}");
                        continue;
                    }
                };
                if n == 0 {
                    continue;
                }

                let guard = client.read().await;
                let Some(ci) = guard.as_ref() else { continue };

                raw.send(RawSendMsg {
                    src_ip: ci.spoof_src_ip,
                    src_port: ci.spoof_src_port,
                    dst_ip: ci.real_ip,
                    dst_port: ci.downstream_port,
                    payload: buf[..n].to_vec().into_boxed_slice(),
                });
            }
        });
    }

    // Optional TCP echo listener for latency testing.
    if let Some(port) = cfg.test_port {
        let addr = format!("{}:{}", cfg.tun_ip, port);
        tokio::spawn(async move {
            if let Err(e) = run_test_listener(&addr).await {
                warn!("test listener: {e}");
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}

// ── TCP echo listener for latency testing ────────────────────────────────────

async fn run_test_listener(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("test listener on {addr}");
    loop {
        let (stream, peer) = listener.accept().await?;
        info!("test conn from {peer}");
        tokio::spawn(async move {
            let (mut rx, mut tx) = stream.into_split();
            let mut buf = [0u8; 8];
            while rx.read_exact(&mut buf).await.is_ok() {
                if tx.write_all(&buf).await.is_err() {
                    break;
                }
            }
        });
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn parse_register(b: &[u8]) -> ClientInfo {
    // b is exactly 12 bytes (caller checked n == 13, b = buf[1..13])
    let real_ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    let downstream_port = u16::from_be_bytes([b[4], b[5]]);
    let spoof_src_ip = Ipv4Addr::new(b[6], b[7], b[8], b[9]);
    let spoof_src_port = u16::from_be_bytes([b[10], b[11]]);
    ClientInfo {
        real_ip,
        downstream_port,
        spoof_src_ip,
        spoof_src_port,
    }
}
