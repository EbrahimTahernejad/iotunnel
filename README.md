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
| Test   | Outbound DNS (UDP 53) allowed; no special privileges needed |
| Both   | iodine and iodined binaries (built from the submodule) |

---

## Building

### 1. Clone (with submodule)

```bash
git clone --recurse-submodules https://github.com/EbrahimTahernejad/iotunnel.git
cd iotunnel
```

### 2. Build iodine

```bash
sudo apt-get install build-essential zlib1g-dev
make -C iodine
# binaries: iodine/bin/iodine  iodine/bin/iodined
```

### 3. Build iotunnel

```bash
cargo build --release
# binary: target/release/iotunnel
```

### Pre-built releases

Compiled archives for `linux/x86_64` are attached to every
[GitHub Release](../../releases). Each archive contains `iotunnel`, `iodine`,
`iodined`, `config.server.example.toml`, `config.client.example.toml`, and
`config.test.example.toml`.

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

Three example configs are provided — copy the relevant one and edit it.
The `mode` field selects which role to run.

### Server (`mode = "server"`)

```toml
mode = "server"

[server]
iodined_bin  = "./iodined"
# -f  foreground (required)   -c  disable source-IP check (needed behind NAT)
iodined_args = ["-f", "-c", "-P", "mysecretpassword", "10.0.0.1", "t1.example.com"]

tun_ip       = "10.0.0.1"   # must match iodined's first positional arg
tunnel_port  = 5300          # internal framing port (no firewall hole needed)
backend_addr = "127.0.0.1:443"

# Optional: TCP echo port for test-mode latency probing
test_port = 5301
```

| Field | Description |
|-------|-------------|
| `iodined_bin` | Path to the `iodined` binary |
| `iodined_args` | Passed verbatim; `-f` is required |
| `tun_ip` | Server-side tunnel IP — must match iodined's first positional arg |
| `tunnel_port` | UDP port used inside the tunnel for the framing protocol |
| `backend_addr` | Backend UDP endpoint to proxy data to/from |
| `test_port` | *(optional)* TCP echo port for latency testing; omit to disable |

### Client (`mode = "client"`)

```toml
mode = "client"

[client]
iodine_bin  = "./iodine"
# -f = foreground (required)
# -r = skip raw UDP mode (forces traffic through the DNS relay)
# "8.8.8.8" = nameserver positional arg (omit to use /etc/resolv.conf)
# "t1.example.com" = topdomain positional arg
iodine_args = ["-f", "-r", "8.8.8.8", "t1.example.com", "-P", "mysecretpassword"]

tun_ip        = "10.0.0.2"
server_tun_ip = "10.0.0.1"
tunnel_port   = 5300

real_ip         = "198.51.100.42"
downstream_port = 0       # 0 = OS-assigned; reported to server via REGISTER
fake_src_ip     = "8.8.8.8"
fake_src_port   = 443
local_port      = 10443
nat_keepalive_secs = 5
```

| Field | Description |
|-------|-------------|
| `iodine_args` | `-f` required; `-r` skips raw UDP mode (recommended); nameserver is the optional first positional arg before the domain |
| `tun_ip` | Our tunnel IP — iodined assigns sequentially starting at `.2` |
| `real_ip` | Our public IP; the server raw-sends downstream UDP here |
| `downstream_port` | Receive port for downstream; `0` lets the OS pick one |
| `fake_src_ip/port` | Server spoofs this as the source of every downstream packet |
| `local_port` | The kcp/tuic client connects to `127.0.0.1:<local_port>` |
| `nat_keepalive_secs` | How often to ping `fake_src_ip:fake_src_port` to keep NAT alive |

#### Choosing `fake_src_ip` and `fake_src_port`

1. **NAT traversal:** iotunnel automatically sends a keepalive from
   `downstream_port` to `fake_src_ip:fake_src_port`, opening the NAT entry
   that lets the server's spoofed replies through.
2. **Firewall bypass:** choose an IP:port your firewall won't block.
   `8.8.8.8:443` or the address of any server you already talk to are
   common choices.
3. Junk replies from the real host at `fake_src_ip:fake_src_port` are
   silently discarded by the client.

### Test (`mode = "test"`)

Test mode probes a list of DNS resolvers, measures TCP round-trip time through
the iodine tunnel to the server's `test_port`, and prints a ranked summary.
Results are also saved to `results.csv`.

```toml
mode = "test"

[test]
iodine_bin  = "./iodine"
# -f = foreground (required)
# -r = skip raw UDP mode (forces traffic through the DNS relay)
# "RESOLVER" is the nameserver positional arg — substituted with each
#   resolver IP at test time. Must appear in the args exactly as "RESOLVER".
iodine_args = ["-f", "-r", "RESOLVER", "t1.example.com", "-P", "mysecretpassword"]

tun_ip        = "10.0.0.2"
server_tun_ip = "10.0.0.1"
test_port     = 5301        # must match server's test_port

pings                = 5    # ping round-trips per resolver
connect_timeout_secs = 30   # seconds to wait for iodine tunnel to come up
ping_timeout_secs    = 10   # seconds to wait for a single ping reply

resolvers = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
]
```

| Field | Description |
|-------|-------------|
| `iodine_args` | Must contain `"RESOLVER"` as a placeholder |
| `test_port` | Must match `test_port` in the server config |
| `pings` | Number of echo round-trips per resolver |
| `connect_timeout_secs` | Max seconds to wait for the iodine tunnel to appear |
| `ping_timeout_secs` | Max seconds to wait for one ping reply |
| `resolvers` | List of DNS resolver IPs to test |

#### Output

Console table printed after all resolvers are tested:

```
----------------------------------------------------
 Rank  Resolver           Avg RTT    Min RTT   Pkts
----------------------------------------------------
 1     1.1.1.1             42ms       38ms         5
 2     8.8.8.8             61ms       55ms         5
 3     9.9.9.9           TIMEOUT        —           0
----------------------------------------------------

Best resolver: 1.1.1.1 (42 ms avg)

Results saved to results.csv
```

`results.csv` columns: `rank`, `resolver`, `avg_rtt_ms`, `min_rtt_ms`,
`pkts`, `status`. Status is one of `ok`, `tunnel_timeout`, `connect_failed`,
or `no_pings`.

---

## Running

### Server

```bash
# Root required for CAP_NET_RAW (raw socket)
sudo ./iotunnel config.server.example.toml
```

To avoid running the whole process as root:

```bash
sudo setcap cap_net_raw+ep ./iotunnel
./iotunnel config.server.example.toml
```

### Client

```bash
./iotunnel config.client.example.toml
```

### Test

```bash
./iotunnel config.test.example.toml
```

Resolvers are probed sequentially. Each run spawns iodine, waits for the
tunnel, pings, then tears iodine down before the next resolver. Expect each
probe to take `connect_timeout_secs` in the worst case.

### Logging

```bash
RUST_LOG=debug ./iotunnel config.server.example.toml
```

---

## Protocol reference

All tunnelled communication uses UDP datagrams on `tunnel_port`, routed
transparently through iodine. The framing is minimal:

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
30 seconds so the iotunnel server process recovers its state after a restart.
Note: if iodined itself restarts the iodine client connection will also drop
and need to reconnect; iotunnel does not manage that reconnection.

**Downstream:** raw IPv4 + UDP packet built with `SOCK_RAW / IPPROTO_RAW`,
`src = spoof_src_ip:spoof_src_port`, sent directly to `real_ip:downstream_port`.

**Test echo:** 8-byte messages sent over TCP to `server_tun_ip:test_port`.
The server echoes each message back verbatim; the client measures the
round-trip time.

---

## Caveats

- **Single client per server instance.** The server tracks one registered
  client (last REGISTER wins). Multi-client support would require per-client
  backend sockets keyed by tunnel source address.
- **iodine route injection.** By default iodine may add a default route
  through the tunnel. Use `-r` in `iodine_args` to skip this, then add only
  the routes you need manually.
- **MTU.** iodine's effective MTU is ~200 bytes in the worst case (depends on
  domain length and DNS relay). Configure your backend protocol's MTU
  accordingly to avoid fragmentation inside the tunnel.
- **iodine version pinning.** iodine's wire protocol is not stable across
  versions. Server and client must run the same build; the submodule pins the
  exact version.
- **Test mode is sequential.** Resolvers are probed one at a time. Parallel
  probing is not supported because iodine creates a TUN interface with a fixed
  name/IP, preventing concurrent instances.

---

## CI / CD

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| [`ci.yml`](.github/workflows/ci.yml) | Every push / PR | `fmt`, `clippy`, debug + release build, iodine compilation check |
| [`release.yml`](.github/workflows/release.yml) | `v*` tag push | Builds for `linux/x86_64`, creates a GitHub Release with the archive |

---

## License

MIT
