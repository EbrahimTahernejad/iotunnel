# iotunnel

An asymmetric UDP tunnel designed for restricted networks where outbound DNS
queries are allowed but direct UDP is blocked or monitored.

- **Upstream (client → server):** carried inside DNS queries via
  [iodine](https://github.com/yarrick/iodine).
- **Downstream (server → client):** raw UDP with a spoofed source IP/port,
  delivered directly to the client's real address.

The combined channel is exposed as a plain UDP socket on both ends so any
UDP-based backend — [KCP](https://github.com/skywind3000/kcp),
[TUIC](https://github.com/EAimTY/tuic), WireGuard, etc. — can sit on top
without modification.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CLIENT MACHINE                        SERVER MACHINE                       │
│                                                                             │
│  kcp/tuic client                       kcp/tuic server                     │
│       │  UDP                                  ▲  UDP                        │
│       ▼                                       │                             │
│  iotunnel (client)                      iotunnel (server)                   │
│       │  upstream: UDP over iodine TUN        │                             │
│       │──────[DNS queries]────────────────────▶ iodined (port 53)           │
│       │                      iodine TUN ──────▶ 10.0.0.1                   │
│       │                                       │                             │
│       │  downstream: raw UDP, spoofed src     │                             │
│       ◀──────[UDP dst=real_ip:ds_port]────────│  SOCK_RAW + IP_HDRINCL     │
│  0.0.0.0:downstream_port                      │  src = fake_src_ip:port     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Why asymmetric?

DNS tunnels (iodine included) encode data in query subdomains and return it in
DNS responses. Queries are cheap and fast to emit; responses are size-limited
and slower. By using DNS only for upstream and direct UDP for downstream, we
get:

- **Higher downstream throughput** — no DNS response size limits.
- **Lower downstream latency** — no round-trip through a DNS resolver.
- **Firewall bypass** — the spoofed source makes the downstream packet look
  like a reply from a trusted host (e.g. `8.8.8.8:443`), which most stateful
  firewalls and NATs already have a session for thanks to the keepalive.

---

## Requirements

| Side   | Requirement |
|--------|-------------|
| Server | Root / `CAP_NET_RAW` (raw socket), port 53 UDP reachable for iodined |
| Client | Outbound DNS (UDP 53) allowed; no special privileges needed |
| Both   | iodine and iodined binaries (built from the submodule) |

---

## Building

### 1. Clone (with submodule)

```bash
git clone --recurse-submodules https://github.com/your-org/iotunnel.git
cd iotunnel
```

### 2. Build iodine

```bash
# Linux
sudo apt-get install build-essential zlib1g-dev
make -C iodine

# The binaries land at iodine/iodine and iodine/iodined
```

### 3. Build iotunnel

```bash
cargo build --release
# binary: target/release/iotunnel
```

### Pre-built releases

Compiled archives for `linux/amd64` and `linux/arm64` are attached to every
[GitHub Release](../../releases). Each archive contains `iotunnel`, `iodine`,
`iodined`, and `config.example.toml`.

---

## DNS setup

iodine requires a subdomain delegated to your server. Add two records to your
zone (replace `t1` and `t1ns` with names of your choice):

```
t1    IN NS   t1ns.example.com.
t1ns  IN A    <SERVER_PUBLIC_IP>
```

After propagation, any DNS query for `*.t1.example.com` is forwarded to your
server's port 53 where iodined answers it.

---

## Configuration

Copy `config.example.toml` and edit it. The `mode` field selects which side
to run.

### Server (`mode = "server"`)

```toml
mode = "server"

[server]
iodined_bin  = "./iodine/iodined"
iodined_args = ["-f", "-c", "-P", "mysecretpassword", "10.0.0.1", "t1.example.com"]

# Must match the tunnel IP given to iodined above
tun_ip      = "10.0.0.1"

# Internal UDP port for the iotunnel framing protocol over the iodine TUN.
# Does not need to be open on the firewall — traffic flows inside the tunnel.
tunnel_port = 5300

# Where to forward upstream data (your kcp/tuic/WireGuard server)
backend_addr = "127.0.0.1:443"
```

| Field | Description |
|-------|-------------|
| `iodined_bin` | Path to the `iodined` binary |
| `iodined_args` | Passed verbatim; `-f` (foreground) is required |
| `tun_ip` | Server-side tunnel IP — must match iodined's first positional arg |
| `tunnel_port` | UDP port used inside the tunnel for our protocol |
| `backend_addr` | Backend UDP endpoint to proxy data to/from |

### Client (`mode = "client"`)

```toml
mode = "client"

[client]
iodine_bin  = "./iodine/iodine"
iodine_args = ["-f", "-r", "8.8.8.8", "t1.example.com", "-P", "mysecretpassword"]

tun_ip        = "10.0.0.2"   # assigned by iodined (default: first client = .2)
server_tun_ip = "10.0.0.1"
tunnel_port   = 5300          # must match server

# Our real public IP — server sends raw UDP packets here
real_ip = "198.51.100.42"

# Port to receive downstream spoofed UDP on. 0 = OS-assigned.
downstream_port = 0

# The server spoofs downstream packets as if they come from this IP:port.
# Must be reachable by UDP from the client so the NAT session is established.
fake_src_ip   = "8.8.8.8"
fake_src_port = 443

# Local port the kcp/tuic client connects to
local_port = 10443

# Keepalive interval (seconds) to hold the NAT entry open
nat_keepalive_secs = 5
```

| Field | Description |
|-------|-------------|
| `iodine_args` | `-f` required; `-r` sets the DNS resolver (skip system resolver) |
| `tun_ip` | Our tunnel IP — iodined assigns these sequentially starting at `.2` |
| `real_ip` | Our public IP; the server raw-sends downstream UDP here |
| `downstream_port` | Receive port for downstream; `0` lets the OS pick one |
| `fake_src_ip/port` | Server spoofs this as the source of every downstream packet |
| `local_port` | The kcp/tuic client should connect to `127.0.0.1:<local_port>` |
| `nat_keepalive_secs` | How often to ping `fake_src_ip:fake_src_port` to keep NAT alive |

#### Choosing `fake_src_ip` and `fake_src_port`

The spoofed source must pass your ISP/NAT:

1. **NAT traversal:** Send a UDP packet from `downstream_port` to
   `fake_src_ip:fake_src_port` — this opens a NAT entry. iotunnel does this
   automatically via the keepalive.
2. **Firewall bypass:** Choose an IP:port that your firewall is unlikely to
   block. `8.8.8.8:443` (Google DNS over non-standard port) or the IP of any
   server you legitimately talk to are common choices.
3. The real host at `fake_src_ip:fake_src_port` may send back junk UDP; the
   client silently discards anything that is just a 1-byte null (keepalive
   echo) and passes everything else to the backend (which will reject it as
   invalid protocol data).

---

## Running

### Server

```bash
# Run as root (or grant CAP_NET_RAW first)
sudo ./target/release/iotunnel server.toml
```

Grant the capability to avoid running the whole process as root:

```bash
sudo setcap cap_net_raw+ep ./target/release/iotunnel
./target/release/iotunnel server.toml
```

### Client

```bash
./target/release/iotunnel client.toml
```

The client does not need elevated privileges.

### Logging

Set `RUST_LOG` to control verbosity:

```bash
RUST_LOG=debug ./target/release/iotunnel config.toml
```

---

## Protocol reference

All communication between iotunnel instances happens over UDP datagrams on
`tunnel_port`, routed transparently through the iodine DNS tunnel. The
protocol is minimal:

| Byte 0 | Total size | Meaning |
|--------|-----------|---------|
| `0x01` | 13 bytes  | **REGISTER** — client announces its downstream address |
| `0x02` | 1 + N     | **DATA** — payload bytes (N ≤ 65 535) |

**REGISTER payload** (bytes 1–12):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────────────────────────────────────────────────────────┤
│                        real_ip  (4 bytes)                         │
├───────────────────────┬───────────────────────────────────────────┤
│   downstream_port (2) │            spoof_src_ip (4 bytes)         │
├───────────────────────┴─────────────────┬─────────────────────────┤
│          spoof_src_ip (cont.)           │   spoof_src_port (2)    │
└─────────────────────────────────────────┴─────────────────────────┘
```

All multi-byte fields are big-endian. The client re-sends REGISTER every
30 seconds so the server recovers automatically after a restart.

**Downstream framing:**
Downstream packets are raw UDP (no type byte). The server constructs a full
IPv4 + UDP packet with `src = spoof_src_ip:spoof_src_port` using a
`SOCK_RAW / IPPROTO_RAW` socket and sends it directly to
`real_ip:downstream_port`.

---

## Caveats

- **Single client per server instance.** The server tracks one registered
  client (last REGISTER wins). Multi-client support would require per-client
  backend sockets keyed by tunnel source address.
- **iodine route injection.** By default iodine may add a default route
  through the tunnel, redirecting all traffic. Use `-r` in `iodine_args` to
  skip this, then add only the specific routes you need.
- **MTU.** iodine's effective MTU is ~200 bytes in the worst case (depends on
  domain length and DNS relay). If your backend protocol is sensitive to MTU,
  set its MTU accordingly to avoid iodine-level fragmentation.
- **iodine version pinning.** iodine's wire protocol is not stable across
  versions. Server and client must run the same build; the submodule pins the
  version.

---

## CI / CD

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| [`ci.yml`](.github/workflows/ci.yml) | Every push / PR | `fmt`, `clippy`, debug + release build, iodine compilation |
| [`release.yml`](.github/workflows/release.yml) | `v*` tag push | Cross-compiles for `amd64` + `arm64`, creates a GitHub Release with archives |

---

## License

MIT
