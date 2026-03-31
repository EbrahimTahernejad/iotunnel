/// Client mode
///
/// Data flow (upstream):
///   local backend  →  our local socket  →  iodine TUN UDP socket  →[DNS]→  server
///
/// Data flow (downstream):
///   server  →[raw spoofed UDP]→  downstream socket  →  local backend
///
/// Registration:
///   Once iodine is up we send a REGISTER packet through the tunnel so the
///   server learns our real IP, downstream port, and the spoofed src it should use.
///   We also re-register every 30 s in case the server restarted.
///
/// NAT keepalive:
///   We periodically send a dummy UDP from our downstream socket to
///   fake_src_ip:fake_src_port so the NAT keeps the session alive.
///   When the server spoofs packets using that src, the NAT lets them through.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{info, warn};

use crate::config::ClientConfig;
use crate::iodine::IodineProcess;

const TYPE_REGISTER: u8 = 0x01;
const TYPE_DATA: u8     = 0x02;

pub async fn run(cfg: ClientConfig) -> Result<()> {
    // 1. Start iodine and wait for our tunnel IP to appear.
    let _iodine = IodineProcess::spawn(&cfg.iodine_bin, &cfg.iodine_args).await?;
    info!("waiting for TUN IP {}…", cfg.tun_ip);
    IodineProcess::wait_for_ip(&cfg.tun_ip).await?;

    // 2. Upstream socket: bound on our tunnel IP, sends to server's tunnel IP.
    //    Traffic flows through the iodine TUN → encoded as DNS queries → server.
    let upstream = Arc::new(
        UdpSocket::bind(format!("{}:0", cfg.tun_ip))
            .await
            .context("bind upstream socket on tunnel IP")?,
    );
    let server_tunnel: SocketAddr =
        format!("{}:{}", cfg.server_tun_ip, cfg.tunnel_port).parse()?;
    upstream.connect(server_tunnel).await?;
    info!("upstream → {server_tunnel} (via iodine TUN)");

    // 3. Downstream socket: receives spoofed UDP sent by the server.
    //    Also used for NAT keepalive sends to fake_src.
    let downstream = Arc::new(
        UdpSocket::bind(format!("0.0.0.0:{}", cfg.downstream_port))
            .await
            .context("bind downstream socket")?,
    );
    let actual_ds_port = downstream.local_addr()?.port();
    info!("downstream listening on :{actual_ds_port}");

    // 4. Local backend socket: bridges the kcp/tuic client.
    let local = Arc::new(
        UdpSocket::bind(format!("0.0.0.0:{}", cfg.local_port))
            .await
            .context("bind local backend socket")?,
    );
    info!("local backend listening on :{}", cfg.local_port);

    // Parsed config values used across tasks.
    let real_ip: Ipv4Addr       = cfg.real_ip.parse()?;
    let fake_src_ip: Ipv4Addr   = cfg.fake_src_ip.parse()?;
    let fake_src_port           = cfg.fake_src_port;
    let fake_src_addr: SocketAddr =
        format!("{}:{}", cfg.fake_src_ip, cfg.fake_src_port).parse()?;

    // 5. Send initial registration through the tunnel.
    {
        let reg = make_register(real_ip, actual_ds_port, fake_src_ip, fake_src_port);
        for _ in 0..3 {
            let _ = upstream.send(&reg).await;
            time::sleep(Duration::from_millis(100)).await;
        }
        info!(
            "registered: real={}:{} spoof={}:{}",
            real_ip, actual_ds_port, fake_src_ip, fake_src_port,
        );
    }

    // 6. Periodic re-registration (handles server restarts).
    {
        let upstream = upstream.clone();
        tokio::spawn(async move {
            let mut ticker = time::interval(Duration::from_secs(30));
            ticker.tick().await; // skip first tick (already sent above)
            loop {
                ticker.tick().await;
                let reg = make_register(real_ip, actual_ds_port, fake_src_ip, fake_src_port);
                let _ = upstream.send(&reg).await;
            }
        });
    }

    // 7. NAT keepalive — sends from the downstream socket so the NAT maps it.
    {
        let ds = downstream.clone();
        let interval = cfg.nat_keepalive_secs;
        tokio::spawn(async move {
            let mut ticker = time::interval(Duration::from_secs(interval));
            loop {
                ticker.tick().await;
                if let Err(e) = ds.send_to(b"\x00", fake_src_addr).await {
                    warn!("NAT keepalive: {e}");
                }
            }
        });
    }

    // Last seen local peer (the kcp/tuic client's address).
    let local_peer: Arc<RwLock<Option<SocketAddr>>> = Arc::new(RwLock::new(None));

    // ── Task A: local backend → upstream (DNS tunnel) ─────────────────────────
    {
        let upstream   = upstream.clone();
        let local      = local.clone();
        let local_peer = local_peer.clone();

        tokio::spawn(async move {
            // Pre-allocate; reuse each iteration.
            let mut data_buf = vec![0u8; 65_536];
            // Output buffer: 1 type byte + data.
            let mut pkt = vec![0u8; 65_537];
            pkt[0] = TYPE_DATA;

            loop {
                let (n, peer) = match local.recv_from(&mut data_buf).await {
                    Ok(v)  => v,
                    Err(e) => { warn!("local recv: {e}"); continue; }
                };
                if n == 0 { continue; }

                // Track the kcp/tuic client address for downstream delivery.
                {
                    let mut guard = local_peer.write().await;
                    if guard.as_ref() != Some(&peer) {
                        info!("local peer: {peer}");
                        *guard = Some(peer);
                    }
                }

                pkt[1..1 + n].copy_from_slice(&data_buf[..n]);
                if let Err(e) = upstream.send(&pkt[..1 + n]).await {
                    warn!("upstream send: {e}");
                }
            }
        });
    }

    // ── Task B: downstream (spoofed UDP) → local backend ─────────────────────
    {
        let downstream = downstream.clone();
        let local      = local.clone();
        let local_peer = local_peer.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let (n, from) = match downstream.recv_from(&mut buf).await {
                    Ok(v)  => v,
                    Err(e) => { warn!("downstream recv: {e}"); continue; }
                };
                if n == 0 { continue; }

                // Only accept packets spoofed from the expected source.
                if from != fake_src_addr {
                    continue;
                }

                // 1-byte null = NAT keepalive echo; discard.
                if n == 1 && buf[0] == 0x00 { continue; }

                let guard = local_peer.read().await;
                let Some(peer) = *guard else { continue };
                drop(guard);

                if let Err(e) = local.send_to(&buf[..n], peer).await {
                    warn!("local send: {e}");
                }
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build a 13-byte REGISTER packet.
fn make_register(
    real_ip: Ipv4Addr,
    downstream_port: u16,
    spoof_src_ip: Ipv4Addr,
    spoof_src_port: u16,
) -> [u8; 13] {
    let mut buf = [0u8; 13];
    buf[0] = TYPE_REGISTER;
    buf[1..5].copy_from_slice(&real_ip.octets());
    buf[5..7].copy_from_slice(&downstream_port.to_be_bytes());
    buf[7..11].copy_from_slice(&spoof_src_ip.octets());
    buf[11..13].copy_from_slice(&spoof_src_port.to_be_bytes());
    buf
}
