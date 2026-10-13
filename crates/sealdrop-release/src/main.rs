use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use sealdrop_release::app::{build, AppState};
use sealdrop_release::clock::SystemClock;
use sealdrop_release::db::Db;
use sealdrop_release::fsutil;

#[derive(Parser)]
#[command(
    name = "sealdrop-release",
    version,
    about = "Key-release service for sealdrop timed release"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the service signing key (service.key / service.pub in --dir)
    Keygen {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// Replace existing service.key / service.pub (senders must re-pin the new service key)
        #[arg(long)]
        force: bool,
    },
    /// Create a deposit token for a sender; prints it once
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Run the HTTP service (terminate TLS in front of it)
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        #[arg(long, default_value = "releases.db")]
        db: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// Burst size of the per-address rate limiter (keyed on the TCP peer address, or on
        /// the client address from X-Forwarded-For with --trust-proxy)
        #[arg(long, default_value_t = 60)]
        rate_capacity: u32,
        /// Behind a reverse proxy: rate-limit on the first X-Forwarded-For address. Only set
        /// this when the proxy (e.g. Caddy) sets that header itself; otherwise every client
        /// shares the proxy's bucket
        #[arg(long)]
        trust_proxy: bool,
        /// Requests per second the rate limiter refills per address
        #[arg(long, default_value_t = sealdrop_release::app::DEFAULT_REFILL_PER_SEC, value_parser = parse_refill)]
        rate_refill_per_sec: f64,
        /// Days to keep release records (and never-unlocked deposits) before purging
        #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(i64).range(1..=3650))]
        retention_days: i64,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    New {
        name: String,
        #[arg(long, default_value = "releases.db")]
        db: String,
    },
}

fn parse_refill(s: &str) -> Result<f64, String> {
    let v: f64 = s.parse().map_err(|_| format!("`{s}` is not a number"))?;
    if v.is_finite() && v > 0.0 && v <= 1_000_000.0 {
        Ok(v)
    } else {
        Err("must be greater than 0 and at most 1000000".into())
    }
}

/// Writes the signing key pair owner-only, refusing to overwrite unless `force`.
fn write_keys(dir: &std::path::Path, force: bool) -> anyhow::Result<minisign::PublicKey> {
    let key_path = dir.join("service.key");
    let pub_path = dir.join("service.pub");
    if !force {
        for p in [&key_path, &pub_path] {
            if p.exists() {
                anyhow::bail!("{} already exists; pass --force to replace it", p.display());
            }
        }
    }
    let kp = minisign::KeyPair::generate_unencrypted_keypair()?;
    let key_text = kp.sk.to_box(Some("sealdrop-release"))?.into_string();
    let pub_text = kp.pk.to_box()?.into_string();
    let open = |p: &std::path::Path| {
        if force {
            fsutil::create_or_replace_private(p)
        } else {
            fsutil::create_new_private(p)
        }
    };
    open(&key_path)?.write_all(key_text.as_bytes())?;
    open(&pub_path)?.write_all(pub_text.as_bytes())?;
    Ok(kp.pk)
}

fn load_signer(dir: &std::path::Path) -> anyhow::Result<minisign::KeyPair> {
    let sk =
        minisign::SecretKeyBox::from_string(&std::fs::read_to_string(dir.join("service.key"))?)?
            .into_unencrypted_secret_key()?;
    let pk =
        minisign::PublicKeyBox::from_string(&std::fs::read_to_string(dir.join("service.pub"))?)?
            .into_public_key()?;
    Ok(minisign::KeyPair { pk, sk })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Keygen { dir, force } => {
            let pk = write_keys(&dir, force)?;
            println!("service key: {}", pk.to_base64());
        }
        Cmd::Token {
            cmd: TokenCmd::New { name, db },
        } => {
            let db = Db::open(&db)?;
            println!("{}", db.create_token(&name)?);
            eprintln!("store this token securely; it is shown once");
        }
        Cmd::Serve {
            listen,
            db,
            dir,
            rate_capacity,
            rate_refill_per_sec,
            retention_days,
            trust_proxy,
        } => {
            let db = Db::open(&db)?;
            let state = AppState::with_rate(
                db,
                Arc::new(SystemClock),
                load_signer(&dir)?,
                rate_capacity,
                rate_refill_per_sec,
            )
            .trusting_proxy(trust_proxy);
            let sweeper = state.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    tick.tick().await;
                    match sweeper
                        .db
                        .sweep_expired_unix(sweeper.clock.now_unix(), retention_days)
                    {
                        Ok(0) => {}
                        Ok(n) => tracing::info!(deleted_keys = n, "sweep"),
                        Err(e) => tracing::warn!(error = %e, "sweep failed"),
                    }
                }
            });
            let app = build(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            tracing::info!(%listen, "sealdrop-release listening");
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}
