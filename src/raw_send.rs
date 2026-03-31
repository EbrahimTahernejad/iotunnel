/// Spoofed-source raw UDP sender.
///
/// A dedicated OS thread owns the raw socket and drains a sync channel,
/// so the tokio runtime is never blocked and we avoid spawn_blocking overhead
/// per packet.
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc;
use std::thread;

use anyhow::{Context, Result};
use tracing::warn;

static IP_ID: AtomicU16 = AtomicU16::new(1);

pub struct RawSendMsg {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub payload: Box<[u8]>,
}

/// Cheaply cloneable handle — just a channel sender.
#[derive(Clone)]
pub struct RawSender {
    tx: mpsc::SyncSender<RawSendMsg>,
}

impl RawSender {
    /// Spawns the background sender thread. Requires CAP_NET_RAW.
    pub fn new(queue_depth: usize) -> Result<Self> {
        let fd = open_raw_socket().context("open raw socket (need CAP_NET_RAW / root)")?;
        let (tx, rx) = mpsc::sync_channel::<RawSendMsg>(queue_depth);

        thread::Builder::new()
            .name("raw-sender".into())
            .spawn(move || {
                for msg in rx {
                    let ip_id = IP_ID.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = send_spoofed(fd, &msg, ip_id) {
                        warn!("raw sendto: {e}");
                    }
                }
                // rx dropped → thread exits; close fd
                unsafe { libc::close(fd) };
            })
            .context("spawn raw-sender thread")?;

        Ok(Self { tx })
    }

    /// Enqueue a spoofed UDP send. Silently drops if the queue is full
    /// (back-pressure: prefer losing a packet over blocking the runtime).
    #[inline]
    pub fn send(&self, msg: RawSendMsg) {
        let _ = self.tx.try_send(msg);
    }
}

// ── raw socket helpers ────────────────────────────────────────────────────────

fn open_raw_socket() -> Result<libc::c_int> {
    // IPPROTO_RAW implies IP_HDRINCL — we supply the full IP+UDP header.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW,
            libc::IPPROTO_RAW as libc::c_int,
        )
    };
    if fd < 0 {
        anyhow::bail!(
            "socket(AF_INET, SOCK_RAW, IPPROTO_RAW): {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(fd)
}

fn send_spoofed(fd: libc::c_int, msg: &RawSendMsg, ip_id: u16) -> std::io::Result<()> {
    let pkt = build_packet(
        msg.src_ip,
        msg.src_port,
        msg.dst_ip,
        msg.dst_port,
        &msg.payload,
        ip_id,
    );

    // sendto needs the destination even with IP_HDRINCL; kernel uses it for routing.
    let dst = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: msg.dst_port.to_be(),
        sin_addr: libc::in_addr {
            // sockaddr_in.sin_addr.s_addr is in network byte order
            s_addr: u32::from_be_bytes(msg.dst_ip.octets()).to_be(),
        },
        sin_zero: [0u8; 8],
    };

    let rc = unsafe {
        libc::sendto(
            fd,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &dst as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ── packet construction ───────────────────────────────────────────────────────

/// RFC 1071 one's-complement checksum.
fn checksum(data: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in chunks.by_ref() {
        acc += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let Some(&tail) = chunks.remainder().first() {
        acc += (tail as u32) << 8;
    }
    while acc >> 16 != 0 {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

fn build_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
    ip_id: u16,
) -> Vec<u8> {
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    let udp_len = 8u16 + payload.len() as u16;
    let total_len = 20u16 + udp_len;

    // ── UDP checksum (via pseudo-header) ─────────────────────────────────────
    // pseudo: src(4) dst(4) zero(1) proto=17(1) udp_len(2)
    //       + udp_header_with_zero_checksum(8) + payload
    let mut pseudo = Vec::with_capacity(12 + udp_len as usize);
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.push(0);
    pseudo.push(17); // UDP
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    // UDP header (checksum = 0 placeholder)
    pseudo.extend_from_slice(&src_port.to_be_bytes());
    pseudo.extend_from_slice(&dst_port.to_be_bytes());
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    pseudo.extend_from_slice(&[0u8, 0]);
    pseudo.extend_from_slice(payload);

    let mut udp_cksum = checksum(&pseudo);
    if udp_cksum == 0 {
        udp_cksum = 0xFFFF;
    } // 0 means "no checksum" in UDP

    // ── assemble packet ───────────────────────────────────────────────────────
    let mut pkt = vec![0u8; total_len as usize];

    // IPv4 header (20 bytes, no options)
    pkt[0] = 0x45; // version=4, IHL=5
                   // [1] DSCP/ECN = 0
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[4..6].copy_from_slice(&ip_id.to_be_bytes());
    pkt[6] = 0x40; // flags: DF=1
                   // [7] fragment offset = 0
    pkt[8] = 64; // TTL
    pkt[9] = 17; // protocol: UDP
                 // [10..12] IP checksum — computed below
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);

    // Linux fills the IP checksum for us with IPPROTO_RAW, but compute it
    // anyway for compatibility with other kernels.
    let ip_cksum = checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // UDP header (8 bytes)
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    pkt[26..28].copy_from_slice(&udp_cksum.to_be_bytes());

    // payload
    pkt[28..].copy_from_slice(payload);

    pkt
}
