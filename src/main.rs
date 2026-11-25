use ai_governance_gateway::audit::AuditLog;
use ai_governance_gateway::engine::{Direction, Guard};
use ai_governance_gateway::policy::Policy;
use ai_governance_gateway::{eval, server};
use anyhow::Context;
use clap::{Parser, Subcommand};
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(version, about = "Policy-enforcing gateway for enterprise LLM traffic")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the OpenAI-compatible proxy.
    Serve {
        #[arg(long, env = "GATEWAY_LISTEN", default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        #[arg(
            long,
            env = "GATEWAY_UPSTREAM",
            default_value = "https://api.openai.com"
        )]
        upstream: String,
        #[arg(long, env = "GATEWAY_POLICY")]
        policy: Option<PathBuf>,
        #[arg(long, env = "GATEWAY_AUDIT_LOG")]
        audit_log: Option<PathBuf>,
        #[arg(long, env = "GATEWAY_UPSTREAM_TIMEOUT_SECS", default_value_t = 120)]
        upstream_timeout_secs: u64,
    },
    /// Inspect a file (or stdin) and print the decision as JSON.
    Scan {
        file: Option<PathBuf>,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Measure detection accuracy on labeled datasets.
    Eval {
        #[arg(default_value = "datasets")]
        dir: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Exit non-zero if any headline F1 score falls below this value.
        #[arg(long, default_value_t = 0.99)]
        min_f1: f64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Serve {
            listen,
            upstream,
            policy,
            audit_log,
            upstream_timeout_secs,
        } => {
            let state = Arc::new(server::AppState {
                guard: Guard::new(Policy::load(policy.as_deref())?),
                client: reqwest::Client::builder()
                    .timeout(Duration::from_secs(upstream_timeout_secs))
                    .build()?,
                upstream,
                audit: audit_log
                    .map(|p| AuditLog::open(&p).with_context(|| format!("opening {}", p.display())))
                    .transpose()?,
            });
            let listener = tokio::net::TcpListener::bind(listen).await?;
            tracing::info!(%listen, upstream = %state.upstream, "gateway listening");
            axum::serve(listener, server::router(state))
                .with_graceful_shutdown(async {
                    tokio::signal::ctrl_c().await.ok();
                })
                .await?;
        }
        Cmd::Scan { file, policy } => {
            let mut text = String::new();
            match file {
                Some(p) => text = std::fs::read_to_string(p)?,
                None => {
                    std::io::stdin().read_to_string(&mut text)?;
                }
            }
            let guard = Guard::new(Policy::load(policy.as_deref())?);
            let inspection = guard.inspect(&text, Direction::Request);
            println!("{}", serde_json::to_string_pretty(&inspection)?);
        }
        Cmd::Eval {
            dir,
            policy,
            min_f1,
        } => {
            let policy = Policy::load(policy.as_deref())?;
            let report = eval::run(&dir, policy.injection_threshold)?;
            println!("{report}");
            let worst = report.pii.f1().min(report.injection.f1());
            anyhow::ensure!(
                worst >= min_f1,
                "F1 {worst:.4} is below the required {min_f1}"
            );
        }
    }
    Ok(())
}
