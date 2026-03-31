use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;
use tokio::time::sleep;
use tracing::info;

/// Owns a running iodine/iodined child process.
/// The child is killed (SIGKILL) when this struct is dropped.
pub struct IodineProcess {
    _child: tokio::process::Child,
}

impl IodineProcess {
    pub async fn spawn(bin: &str, args: &[String]) -> Result<Self> {
        let child = Command::new(bin)
            .args(args)
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to spawn {bin}"))?;
        info!("spawned {} {:?}", bin, args);
        Ok(Self { _child: child })
    }

    /// Poll `ip addr show` until `ip` appears (iodine sets it up asynchronously).
    pub async fn wait_for_ip(ip: &str) -> Result<()> {
        for secs in 1..=90 {
            sleep(Duration::from_secs(1)).await;
            let out = Command::new("ip")
                .args(["addr", "show"])
                .output()
                .await
                .context("ip addr show")?;
            if String::from_utf8_lossy(&out.stdout).contains(ip) {
                info!("TUN IP {ip} ready after {secs}s");
                return Ok(());
            }
        }
        anyhow::bail!("TUN IP {ip} did not appear within 90 seconds")
    }
}
