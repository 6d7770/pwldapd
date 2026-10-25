//! `pwldapd`: a read-only LDAP server backed by the local POSIX user and
//! group database. Bind requests are authenticated via PAM. All other write
//! operations are rejected. See the man page (`man pwldapd`) for full details.

mod ber;
mod config;
mod handler;
mod ldap;
mod passwd;
mod pam_auth;
mod server;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(version, about = "LDAP daemon backed by local POSIX accounts")]
struct Args {
    /// Path to TOML configuration file.
    #[arg(short = 'c', long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let file_config = config::load_config(
        args.config.as_deref(),
        std::path::Path::new(config::DEFAULT_CONFIG_PATH),
    )?;

    tracing_subscriber::fmt()
        .with_env_filter(config::log_filter(file_config.as_ref()))
        .init();

    let cfg = config::merge_config(file_config, config::derive_base_dn)?;

    let fmt_ranges = |ranges: &[std::ops::RangeInclusive<u32>]| -> String {
        if ranges.is_empty() {
            "all".to_string()
        } else {
            ranges.iter()
                .map(|r| format!("{}-{}", r.start(), r.end()))
                .collect::<Vec<_>>()
                .join(",")
        }
    };
    info!(
        "base_dn={} uid_ranges={} gid_ranges={} max_connections={} idle_timeout={}",
        cfg.base_dn,
        fmt_ranges(&cfg.uid_ranges),
        fmt_ranges(&cfg.gid_ranges),
        cfg.max_connections,
        cfg.idle_timeout
            .map(|d| format!("{}s", d.as_secs()))
            .unwrap_or_else(|| "none".into()),
    );

    pam_auth::check_pam_service();

    server::run(cfg).await
}
