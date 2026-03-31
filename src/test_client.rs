/// Test mode — probe a list of DNS resolvers by replaying the iodine version
/// handshake query directly in Rust, without spawning iodine at all.
///
/// For each resolver × each DNS record type:
///   1. Build the iodine version-check DNS query (type 'v', PROTOCOL_VERSION
///      0x00000502, base32-encoded, sent to port 53 of the resolver).
///   2. Wait for a DNS response and decode it.
///   3. Check for VACK / VNAK / VFUL in the payload.
///
/// Results are sorted by RTT and written to results.csv.
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config::TestConfig;

// iodine protocol version (from iodine/src/version.h)
const PROTOCOL_VERSION: u32 = 0x00000502;

// DNS record types iodine supports for the version query
const QTYPES: &[(&str, u16)] = &[
    ("NULL", 10),
    ("PRIVATE", 65399),
    ("TXT", 16),
    ("SRV", 33),
    ("MX", 15),
    ("CNAME", 5),
    ("A", 1),
];

const DNS_PORT: u16 = 53;
const CSV_PATH: &str = "results.csv";

// base32 alphabet used by iodine (a-z 2-7, lowercase)
const B32_ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

fn b32_enc_5(v: u8) -> u8 {
    B32_ALPHA[(v & 0x1f) as usize]
}

/// Encode `data` as iodine-style base32 with dots every 57 chars,
/// then append ".<topdomain>".
fn build_version_hostname(data: &[u8; 6], topdomain: &str) -> String {
    // base32-encode the 6 bytes → 10 base32 chars (ceiling(6*8/5))
    let mut encoded = [0u8; 10];
    // standard base32, no padding, 6 bytes = 10 chars
    // bits: [0..4][5..9][10..14][15..19][20..24][25..29][30..34][35..39][40..44][45..47+pad]
    let bits: u64 = (data[0] as u64) << 40
        | (data[1] as u64) << 32
        | (data[2] as u64) << 24
        | (data[3] as u64) << 16
        | (data[4] as u64) << 8
        | (data[5] as u64);
    for (i, slot) in encoded.iter_mut().enumerate() {
        let shift = 45 - i * 5;
        *slot = b32_enc_5(((bits >> shift) & 0x1f) as u8);
    }

    // Build the subdomain: 'v' + encoded data, then dotify every 57 chars
    // (iodine calls inline_dotify; for 10 chars we never exceed 57, so no dots needed)
    // Then append the CMC (3-byte anti-cache) and topdomain.
    // iodine appends a random 3-char CMC + dot before topdomain.
    // Use a fixed CMC for probe queries — the server doesn't validate it for 'v'.
    let cmc = "aaa";
    format!(
        "v{}.{}.{}",
        std::str::from_utf8(&encoded).unwrap(),
        cmc,
        topdomain
    )
}

/// Build a DNS query packet for the given hostname and qtype.
fn build_dns_query(hostname: &str, qtype: u16, query_id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(256);

    // Header
    pkt.extend_from_slice(&query_id.to_be_bytes()); // ID
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question: QNAME
    for label in hostname.split('.') {
        if label.is_empty() {
            continue;
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label

    pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN

    pkt
}

/// Extract the answer payload from a DNS response.
/// Returns the raw rdata bytes (NULL/PRIVATE) or decoded name string bytes
/// (CNAME/MX/SRV/TXT/A) as the iodine server sends them.
fn extract_answer(resp: &[u8], qtype: u16) -> Option<Vec<u8>> {
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    if ancount == 0 {
        return None;
    }

    // Skip past the question section
    let mut pos = 12;
    // skip QNAME
    pos = skip_name(resp, pos)?;
    pos += 4; // QTYPE + QCLASS

    if pos >= resp.len() {
        return None;
    }

    // Read first answer
    pos = skip_name(resp, pos)?; // owner name
    if pos + 10 > resp.len() {
        return None;
    }
    let ans_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
    pos += 8; // type(2) + class(2) + ttl(4)
    let rdlen = u16::from_be_bytes([resp[pos], resp[pos + 1]]) as usize;
    pos += 2;

    if pos + rdlen > resp.len() {
        return None;
    }
    let rdata = &resp[pos..pos + rdlen];

    match (qtype, ans_type) {
        // NULL and PRIVATE: raw binary rdata
        (10, _) | (65399, _) => Some(rdata.to_vec()),

        // TXT: first byte is length of the TXT string
        (16, 16) => {
            if rdata.is_empty() {
                return None;
            }
            let txt_len = rdata[0] as usize;
            if 1 + txt_len > rdata.len() {
                return None;
            }
            Some(rdata[1..1 + txt_len].to_vec())
        }

        // CNAME / A query with CNAME answer: decode the CNAME target name
        (5, 5) | (1, 5) => {
            let name = read_name(resp, pos)?;
            Some(name.into_bytes())
        }

        // MX: skip 2-byte preference, then read name
        (15, 15) => {
            if rdlen < 3 {
                return None;
            }
            let name = read_name(resp, pos + 2)?;
            Some(name.into_bytes())
        }

        // SRV: skip 6-byte header (priority/weight/port), then read name
        (33, 33) => {
            if rdlen < 7 {
                return None;
            }
            let name = read_name(resp, pos + 6)?;
            Some(name.into_bytes())
        }

        _ => None,
    }
}

/// Decode the iodine-encoded payload from the answer bytes.
/// iodine prefixes the data with an encoding tag byte (first char of the name).
/// For NULL/PRIVATE the rdata IS the raw payload (no tag byte).
fn decode_iodine_payload(raw: &[u8], qtype: u16) -> Option<Vec<u8>> {
    if raw.is_empty() {
        return None;
    }

    // NULL and PRIVATE carry raw binary directly
    if qtype == 10 || qtype == 65399 {
        return Some(raw.to_vec());
    }

    // For other types, the answer is a hostname whose first char is the
    // encoding tag. We only need to recognise what the server sends back
    // for a version response — iodine servers respond with base32 hostname
    // encoding ('h'/'H' tag) or TXT base32 ('t'/'T') for the version reply.
    // We just need to find VACK/VNAK/VFUL — so try to base32-decode the
    // content after stripping the tag byte and any dots.
    let tag = raw[0].to_ascii_uppercase();
    let rest: Vec<u8> = raw[1..].iter().filter(|&&b| b != b'.').copied().collect();

    match tag {
        b'H' | b'T' => base32_decode_iodine(&rest),
        b'I' | b'S' => base64_decode_simple(&rest),
        b'R' => Some(rest),
        _ => {
            // Unknown tag — attempt base32 anyway, the first 4 bytes are what we need
            base32_decode_iodine(&rest)
        }
    }
}

/// iodine's base32: alphabet a-z2-7 (RFC 4648 but lowercase + no padding).
fn base32_decode_iodine(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8 + 1);
    let mut buf: u64 = 0;
    let mut bits = 0u32;

    for &c in input {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => continue, // skip non-alphabet chars
        };
        buf = (buf << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn base64_decode_simple(input: &[u8]) -> Option<Vec<u8>> {
    // minimal base64 — only used as fallback; we don't need perfect decoding
    // to detect VACK/VNAK/VFUL (which come from NULL/PRIVATE usually)
    let s: Vec<u8> = input
        .iter()
        .filter(|&&b| b != b'\n' && b != b'\r')
        .copied()
        .collect();
    let padded = match s.len() % 4 {
        0 => s,
        2 => {
            let mut v = s;
            v.extend_from_slice(b"==");
            v
        }
        3 => {
            let mut v = s;
            v.push(b'=');
            v
        }
        _ => return None,
    };
    let mut out = Vec::new();
    for chunk in padded.chunks(4) {
        let decode_char = |b: u8| -> Option<u8> {
            match b {
                b'A'..=b'Z' => Some(b - b'A'),
                b'a'..=b'z' => Some(b - b'a' + 26),
                b'0'..=b'9' => Some(b - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                b'=' => Some(0),
                _ => None,
            }
        };
        let a = decode_char(chunk[0])?;
        let b = decode_char(chunk[1])?;
        let c = decode_char(chunk[2])?;
        let d = decode_char(chunk[3])?;
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            out.push((c << 2) | d);
        }
    }
    Some(out)
}

/// Skip a DNS name (label sequence or pointer) at `pos`, return next pos.
fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            // pointer
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

/// Read a DNS name at `pos` as a dotted string, following pointers.
fn read_name(data: &[u8], mut pos: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut safety = 0usize;

    loop {
        if pos >= data.len() || safety > 128 {
            return None;
        }
        safety += 1;
        let len = data[pos];
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= data.len() {
                return None;
            }
            if !jumped {
                jumped = true;
            }
            pos = (((len & 0x3f) as usize) << 8) | data[pos + 1] as usize;
            continue;
        }
        pos += 1;
        if pos + len as usize > data.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&data[pos..pos + len as usize]).to_string());
        pos += len as usize;
    }
    Some(labels.join("."))
}

// ── result types ──────────────────────────────────────────────────────────────

#[derive(Debug)]
enum VersionOutcome {
    Vack,
    Vnak,
    Vfull,
    NoReply,
    DecodeError,
    SendError(String),
}

#[derive(Debug)]
struct ProbeResult {
    resolver: String,
    qtype_name: &'static str,
    outcome: VersionOutcome,
    rtt: Option<Duration>,
}

// ── entry point ───────────────────────────────────────────────────────────────

pub async fn run(cfg: TestConfig) -> Result<()> {
    if cfg.resolvers.is_empty() {
        anyhow::bail!("resolvers list is empty");
    }

    let topdomain = extract_topdomain(&cfg.iodine_args)
        .ok_or_else(|| anyhow::anyhow!("could not find topdomain in iodine_args"))?;

    println!(
        "Probing {} resolver(s) × {} record types against domain {}\n",
        cfg.resolvers.len(),
        QTYPES.len(),
        topdomain,
    );

    let timeout = Duration::from_secs(cfg.ping_timeout_secs);
    let mut results: Vec<ProbeResult> = Vec::new();

    for resolver in &cfg.resolvers {
        for &(qtype_name, qtype) in QTYPES {
            print!("  {resolver:<18} {qtype_name:<8} … ");
            let _ = std::io::stdout().flush();

            let result = probe_version(resolver, &topdomain, qtype, qtype_name, timeout);

            let label = match &result.outcome {
                VersionOutcome::Vack => format!(
                    "VACK  ({:.0} ms)",
                    result.rtt.unwrap_or_default().as_secs_f64() * 1000.0
                ),
                VersionOutcome::Vnak => "VNAK (version mismatch)".into(),
                VersionOutcome::Vfull => "VFULL (server full)".into(),
                VersionOutcome::NoReply => "no reply".into(),
                VersionOutcome::DecodeError => "decode error".into(),
                VersionOutcome::SendError(e) => format!("send error: {e}"),
            };
            println!("{label}");
            results.push(result);
        }
        println!();
    }

    // Sort: VACK first by RTT, everything else after
    results.sort_by_key(|r| match r.outcome {
        VersionOutcome::Vack => r.rtt.map(|d| d.as_micros()).unwrap_or(u128::MAX),
        _ => u128::MAX,
    });

    print_table(&results);
    write_csv(&results)?;
    Ok(())
}

// ── probe a single resolver + qtype ──────────────────────────────────────────

fn probe_version(
    resolver: &str,
    topdomain: &str,
    qtype: u16,
    qtype_name: &'static str,
    timeout: Duration,
) -> ProbeResult {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            return ProbeResult {
                resolver: resolver.to_owned(),
                qtype_name,
                outcome: VersionOutcome::SendError(e.to_string()),
                rtt: None,
            }
        }
    };
    let _ = sock.set_read_timeout(Some(timeout));

    let dst: SocketAddr = format!("{resolver}:{DNS_PORT}")
        .parse()
        .unwrap_or_else(|_| SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), DNS_PORT));

    // Build version payload: 4-byte protocol version + 2-byte rand_seed
    let seed: u16 = rand_u16();
    let mut payload = [0u8; 6];
    payload[0] = (PROTOCOL_VERSION >> 24) as u8;
    payload[1] = (PROTOCOL_VERSION >> 16) as u8;
    payload[2] = (PROTOCOL_VERSION >> 8) as u8;
    payload[3] = PROTOCOL_VERSION as u8;
    payload[4] = (seed >> 8) as u8;
    payload[5] = seed as u8;

    let hostname = build_version_hostname(&payload, topdomain);
    let query_id: u16 = rand_u16();
    let pkt = build_dns_query(&hostname, qtype, query_id);

    let t0 = Instant::now();
    if let Err(e) = sock.send_to(&pkt, dst) {
        return ProbeResult {
            resolver: resolver.to_owned(),
            qtype_name,
            outcome: VersionOutcome::SendError(e.to_string()),
            rtt: None,
        };
    }

    let mut buf = [0u8; 4096];
    let rtt;
    let outcome = loop {
        match sock.recv_from(&mut buf) {
            Err(_) => {
                rtt = None;
                break VersionOutcome::NoReply;
            }
            Ok((n, _from)) => {
                let resp = &buf[..n];
                // Check the query ID matches
                if n < 2 || u16::from_be_bytes([resp[0], resp[1]]) != query_id {
                    continue;
                }
                rtt = Some(t0.elapsed());

                let Some(raw) = extract_answer(resp, qtype) else {
                    break VersionOutcome::DecodeError;
                };
                let Some(decoded) = decode_iodine_payload(&raw, qtype) else {
                    break VersionOutcome::DecodeError;
                };

                if decoded.len() >= 4 {
                    if &decoded[..4] == b"VACK" {
                        break VersionOutcome::Vack;
                    } else if &decoded[..4] == b"VNAK" {
                        break VersionOutcome::Vnak;
                    } else if &decoded[..4] == b"VFUL" {
                        break VersionOutcome::Vfull;
                    }
                }
                break VersionOutcome::DecodeError;
            }
        }
    };

    ProbeResult {
        resolver: resolver.to_owned(),
        qtype_name,
        outcome,
        rtt,
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn rand_u16() -> u16 {
    // simple non-crypto random using system time
    use std::time::{SystemTime, UNIX_EPOCH};
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (ns ^ (ns >> 16)) as u16
}

/// Find the topdomain positional arg in iodine_args.
/// It's the first arg that doesn't start with '-' and isn't a flag value,
/// excluding the nameserver (which comes before it).
/// Strategy: scan for the last non-flag-value bare word.
fn extract_topdomain(args: &[String]) -> Option<String> {
    let mut bare: Vec<&str> = Vec::new();
    let flags_with_value: &[&str] = &[
        "-u", "-t", "-d", "-R", "-m", "-M", "-T", "-O", "-L", "-I", "-P", "-z", "-F",
    ];
    let mut skip_next = false;

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if flags_with_value.iter().any(|&f| arg == f) {
            skip_next = true;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        // Skip the RESOLVER placeholder
        if arg == "RESOLVER" {
            continue;
        }
        bare.push(arg.as_str());
    }

    // bare[0] = nameserver, bare[1] = topdomain (if nameserver present)
    // or bare[0] = topdomain (if nameserver omitted — but we always have one)
    match bare.len() {
        0 => None,
        1 => Some(bare[0].to_owned()),
        _ => Some(bare[bare.len() - 1].to_owned()),
    }
}

// ── output ────────────────────────────────────────────────────────────────────

fn print_table(results: &[ProbeResult]) {
    println!("\n{:-<60}", "");
    println!(
        " {:<18} {:<9} {:>10} Status",
        "Resolver", "Type", "RTT"
    );
    println!("{:-<60}", "");

    for r in results {
        let rtt_s = r
            .rtt
            .map(|d| format!("{:.0}ms", d.as_secs_f64() * 1000.0))
            .unwrap_or_else(|| "—".into());
        let status = match &r.outcome {
            VersionOutcome::Vack => "VACK",
            VersionOutcome::Vnak => "VNAK",
            VersionOutcome::Vfull => "VFULL",
            VersionOutcome::NoReply => "no reply",
            VersionOutcome::DecodeError => "decode error",
            VersionOutcome::SendError(_) => "send error",
        };
        println!(
            " {:<18} {:<9} {:>10}  {}",
            r.resolver, r.qtype_name, rtt_s, status,
        );
    }
    println!("{:-<60}", "");

    if let Some(best) = results
        .iter()
        .find(|r| matches!(r.outcome, VersionOutcome::Vack))
    {
        println!(
            "\nBest: {} via {} ({:.0} ms)",
            best.resolver,
            best.qtype_name,
            best.rtt.unwrap_or_default().as_secs_f64() * 1000.0,
        );
    }
}

fn write_csv(results: &[ProbeResult]) -> Result<()> {
    let mut f = std::fs::File::create(CSV_PATH)?;
    writeln!(f, "resolver,qtype,rtt_ms,status")?;
    for r in results {
        let rtt_ms = r
            .rtt
            .map(|d| format!("{:.3}", d.as_secs_f64() * 1000.0))
            .unwrap_or_default();
        let status = match &r.outcome {
            VersionOutcome::Vack => "vack".into(),
            VersionOutcome::Vnak => "vnak".into(),
            VersionOutcome::Vfull => "vfull".into(),
            VersionOutcome::NoReply => "no_reply".into(),
            VersionOutcome::DecodeError => "decode_error".into(),
            VersionOutcome::SendError(e) => format!("send_error: {}", e.replace(',', ";")),
        };
        writeln!(f, "{},{},{},{}", r.resolver, r.qtype_name, rtt_ms, status)?;
    }
    println!("\nResults saved to {CSV_PATH}");
    Ok(())
}
