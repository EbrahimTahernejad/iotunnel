mod client;
mod config;
mod iodine;
mod raw_send;
mod server;

use anyhow::{Context, Result};
use tracing::error;

#[tokio::main]
async fn main() -> Result<()> {
    // RUST_LOG=info (or debug/trace) controls verbosity.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("iotunnel=info".parse().unwrap()),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_owned());

    let raw =
        std::fs::read_to_string(&config_path).with_context(|| format!("read {config_path}"))?;
    let cfg: config::Config =
        toml::from_str(&raw).with_context(|| format!("parse {config_path}"))?;

    let result = match cfg.mode.as_str() {
        "server" => {
            let scfg = cfg
                .server
                .context("mode=server but [server] section missing")?;
            server::run(scfg).await
        }
        "client" => {
            let ccfg = cfg
                .client
                .context("mode=client but [client] section missing")?;
            client::run(ccfg).await
        }
        m => anyhow::bail!("unknown mode {m:?} — must be \"server\" or \"client\""),
    };

    if let Err(e) = result {
        error!("{e:#}");
        std::process::exit(1);
    }
    Ok(())
}
