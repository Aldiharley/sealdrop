use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use sealdrop_release::app::{build, AppState};
use sealdrop_release::clock::SystemClock;
use sealdrop_release::db::Db;

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
        #[arg(long, default_value_t = 60)]
        rate_capacity: u32,
        #[arg(long, default_value_t = 90)]
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
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match Cli::parse().cmd {
        Cmd::Keygen { dir } => {
            let kp = minisign::KeyPair::generate_unencrypted_keypair()?;
            std::fs::write(
                dir.join("service.key"),
                kp.sk.to_box(Some("sealdrop-release"))?.into_string(),
            )?;
            std::fs::write(dir.join("service.pub"), kp.pk.to_box()?.into_string())?;
            println!("service key: {}", kp.pk.to_base64());
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
            retention_days,
        } => {
            let db = Db::open(&db)?;
            let state = AppState::new(db, Arc::new(SystemClock), load_signer(&dir)?, rate_capacity);
            let sweeper = state.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    tick.tick().await;
                    if let Ok(n) = sweeper
                        .db
                        .sweep_expired_unix(sweeper.clock.now_unix(), retention_days)
                    {
                        if n > 0 {
                            tracing::info!(deleted_keys = n, "sweep");
                        }
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
