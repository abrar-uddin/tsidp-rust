use tracing_subscriber::EnvFilter;

use tsidp::config::{Config, LogFormat};
use tsidp::server::{AppState, run};

#[tokio::main]
async fn main() {
    let cfg = Config::from_args();
    if cfg.check_ready {
        std::process::exit(check_ready(&cfg.admin_listen).await);
    }
    init_logging(&cfg);

    tracing::info!(version = tsidp::version(), "starting tsidp");
    for w in &cfg.startup_warnings {
        tracing::warn!("{w}");
    }
    let state = match AppState::build(cfg).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            std::process::exit(1);
        }
    };
    if let Some(i) = state.issuer() {
        tracing::info!(issuer = %i.url, "issuer set from --issuer-url");
    }
    tracing::info!(
        identity = %state.resolver.describe(),
        state = %state.store.describe(),
        sts = state.cfg.enable_sts,
        funnel = state.cfg.funnel,
        jwt_access_tokens = state.cfg.jwt_access_tokens,
        "configuration"
    );
    if let Err(e) = run(state).await {
        tracing::error!(error = %e, "server failed");
        std::process::exit(1);
    }
}

/// Minimal HTTP GET of /readyz for use as a container health check.
async fn check_ready(admin_listen: &str) -> i32 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = admin_listen
        .replace("0.0.0.0", "127.0.0.1")
        .replace("[::]", "[::1]");
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(&addr).await?;
        s.write_all(b"GET /readyz HTTP/1.0\r\nHost: localhost\r\n\r\n")
            .await?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await?;
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).to_string())
    };
    match tokio::time::timeout(std::time::Duration::from_secs(5), fut).await {
        Ok(Ok(resp)) if resp.starts_with("HTTP/1.") && resp.get(9..12) == Some("200") => {
            println!("ready");
            0
        }
        Ok(Ok(resp)) => {
            eprintln!("not ready: {}", resp.lines().next().unwrap_or(""));
            1
        }
        Ok(Err(e)) => {
            eprintln!("not ready: {e}");
            1
        }
        Err(_) => {
            eprintln!("not ready: timeout");
            1
        }
    }
}

fn init_logging(cfg: &Config) {
    let filter = EnvFilter::try_new(&cfg.log_level)
        .or_else(|_| EnvFilter::try_new(format!("tsidp={},warn", cfg.log_level)))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    match cfg.log_format {
        LogFormat::Json => builder.json().flatten_event(true).init(),
        LogFormat::Text => builder.init(),
    }
}
