use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub mode: String, // "server", "client", or "test"
    pub server: Option<ServerConfig>,
    pub client: Option<ClientConfig>,
    pub test: Option<TestConfig>,
}

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    /// Path to iodined binary (compile from ./iodine first)
    pub iodined_bin: String,
    /// Args passed verbatim to iodined, e.g.:
    ///   ["-f", "-c", "-P", "secret", "10.0.0.1", "t1.example.com"]
    pub iodined_args: Vec<String>,
    /// The tunnel IP iodined is given as its own address (first arg to iodined)
    pub tun_ip: String,
    /// UDP port we bind on the tunnel interface to receive upstream traffic
    pub tunnel_port: u16,
    /// Backend to forward upstream data to and relay replies from
    /// e.g. "127.0.0.1:443" for a local kcp/tuic server
    pub backend_addr: String,
    /// If set, a TCP echo listener is started on this port (on tun_ip) for
    /// latency testing. Used by test-mode clients.
    pub test_port: Option<u16>,
}

#[derive(Deserialize, Clone)]
pub struct ClientConfig {
    /// Path to iodine client binary
    pub iodine_bin: String,
    /// Args passed verbatim to iodine, e.g.:
    ///   ["-f", "-r", "8.8.8.8", "t1.example.com", "-P", "secret"]
    pub iodine_args: Vec<String>,
    /// The tunnel IP assigned to us (typically 10.0.0.2 with default iodined config)
    pub tun_ip: String,
    /// Server's tunnel IP (typically 10.0.0.1)
    pub server_tun_ip: String,
    /// Must match server's tunnel_port
    pub tunnel_port: u16,
    /// Port we bind for receiving downstream spoofed UDP. 0 = OS-assigned.
    pub downstream_port: u16,
    /// Our real public IP — server sends raw UDP here
    pub real_ip: String,
    /// IP the server should spoof as the source of downstream packets.
    /// Must be a real internet host so NAT keeps the session alive.
    pub fake_src_ip: String,
    /// Port the server spoofs as source (pick something the NAT won't block)
    pub fake_src_port: u16,
    /// Local UDP port the kcp/tuic client connects to us on
    pub local_port: u16,
    /// How often (seconds) to send a keepalive to fake_src to hold the NAT entry
    pub nat_keepalive_secs: u64,
}

#[derive(Deserialize, Clone)]
pub struct TestConfig {
    pub iodine_args: Vec<String>,
    pub ping_timeout_secs: u64,
    /// Path to a text file with one DNS resolver IP per line
    pub resolvers_file: String,
    /// Number of concurrent probe workers (default: 8)
    pub workers: Option<usize>,
}
