//! HTTP server with route group assembly and graceful shutdown.
//!
//! Assembles routes from plugins into three groups (Bare, Public, Protected)
//! with different middleware stacks, then serves via axum with graceful
//! shutdown on SIGTERM/Ctrl+C.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::BoxError;
use crate::plugin::{GasketApp, Plugin};

/// Start the HTTP server with the given app.
/// Blocks until shutdown signal is received.
///
/// # Errors
/// Returns an error if the configured `host` cannot be parsed as an IP, the
/// listener cannot bind to `host:port`, the local address cannot be queried,
/// any plugin's `ready` hook fails, the underlying `axum::serve` returns an
/// error, or any plugin's `shutdown` hook propagates an error.
pub async fn run(app: Arc<GasketApp>) -> Result<(), BoxError> {
    let addr = SocketAddr::new(app.config.server.host.parse()?, app.config.server.port);

    let router = app.build_router();

    tracing::info!(%addr, name = %app.config.name, env = %app.config.env, "Starting server");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;

    app.ready(local_addr).await?;

    // TLS serve path (feature `tls`): when `ServerConfig.tls` is set, terminate
    // TLS with rustls via axum-server instead of plaintext axum::serve. Both
    // paths use `into_make_service_with_connect_info::<SocketAddr>()` so the
    // client `SocketAddr` connect-info (relied on e.g. by proxy-aware rate
    // limiting) is preserved, and both shut down gracefully on SIGTERM/Ctrl+C.
    #[cfg(feature = "tls")]
    if let Some(tls) = app.config.server.tls.clone() {
        tracing::info!(%local_addr, "Server listening (TLS)");
        serve_tls(listener, router, tls, shutdown_signal()).await?;
        app.shutdown().await;
        tracing::info!("Server shutdown complete");
        return Ok(());
    }

    tracing::info!(%local_addr, "Server listening");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    app.shutdown().await;
    tracing::info!("Server shutdown complete");

    Ok(())
}

/// Grace period for in-flight requests to finish when shutting down the TLS
/// server before connections are force-closed.
#[cfg(feature = "tls")]
const TLS_GRACEFUL_SHUTDOWN_SECS: u64 = 10;

/// Serve `router` over TLS (rustls) on the already-bound `listener`, preserving
/// `SocketAddr` connect-info and bridging the unified [`shutdown_signal`] into
/// axum-server's graceful-shutdown handle.
#[cfg(feature = "tls")]
async fn serve_tls(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    tls: crate::config::TlsConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), BoxError> {
    use axum_server::Handle;
    use axum_server::tls_rustls::RustlsConfig;

    let rustls_config = RustlsConfig::from_pem(tls.cert_pem, tls.key_pem).await?;
    // Reuse the listener already bound above (so `local_addr` / `ready` saw the
    // real port) by handing axum-server its std equivalent.
    let std_listener = listener.into_std()?;

    // Bridge the caller's shutdown future into axum-server's graceful-shutdown
    // handle. Taking the future as a parameter (rather than calling
    // `shutdown_signal()` here) keeps this fn drivable from tests.
    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(
            TLS_GRACEFUL_SHUTDOWN_SECS,
        )));
    });

    axum_server::from_tcp_rustls(std_listener, rustls_config)
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "Ctrl+C handler failed; falling back to SIGTERM-only shutdown");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "SIGTERM handler failed; falling back to Ctrl+C-only shutdown");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}

/// Lifecycle plugin for the HTTP server.
/// Ordering: `last` — runs after all other plugins have prepared.
#[derive(Debug, Default)]
pub struct ServerPlugin;

impl Plugin for ServerPlugin {
    fn name(&self) -> &'static str {
        "gasket:server"
    }

    fn ordering(&self) -> crate::plugin::PluginOrdering {
        crate::plugin::PluginOrdering::new().last()
    }
}

impl ServerPlugin {
    /// Start the HTTP server with the given application.
    /// Takes an `Arc<GasketApp>` for consistency with `server::run`.
    ///
    /// # Errors
    /// Propagates any error from the underlying [`run`] function.
    pub async fn run(app: Arc<GasketApp>) -> Result<(), BoxError> {
        run(app).await
    }
}

#[cfg(all(test, feature = "tls"))]
mod tls_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use axum::Router;
    use axum::extract::ConnectInfo;
    use axum::routing::get;
    use std::time::Duration;
    use tokio::sync::oneshot;

    /// Echoes the client's connect-info socket address back — proves the
    /// `SocketAddr` connect-info survives the TLS serve path.
    async fn whoami(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
        addr.to_string()
    }

    #[tokio::test]
    async fn serve_tls_handshakes_and_preserves_connect_info() {
        // rustls needs a process-default crypto provider installed by the app.
        // Idempotent across tests sharing the process — an Err just means another
        // test already installed it.
        if rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .is_err()
        {
            tracing::debug!("rustls crypto provider already installed");
        }

        // Self-signed cert covering localhost + 127.0.0.1.
        let issued = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .expect("generate self-signed cert");
        let cert_pem = issued.cert.pem().into_bytes();
        let key_pem = issued.key_pair.serialize_pem().into_bytes();
        let tls = crate::config::TlsConfig::from_pem(cert_pem.clone(), key_pem);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let router = Router::new().route("/whoami", get(whoami));

        let (tx, rx) = oneshot::channel::<()>();
        let server = tokio::spawn(serve_tls(listener, router, tls, async move {
            let _ = rx.await;
        }));

        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&cert_pem).unwrap())
            .build()
            .unwrap();
        let url = format!("https://localhost:{port}/whoami");

        // Retry until the server is accepting (bounded so a real failure fails).
        let mut body = None;
        for _ in 0..40 {
            if let Ok(resp) = client.get(&url).send().await {
                assert_eq!(resp.status(), reqwest::StatusCode::OK);
                body = Some(resp.text().await.unwrap());
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let body = body.expect("server never answered over TLS");
        // Connect-info preserved end-to-end over TLS.
        assert!(
            body.starts_with("127.0.0.1:"),
            "expected client socket addr, got {body:?}"
        );

        // Graceful shutdown returns from serve_tls.
        let _ = tx.send(());
        let joined = tokio::time::timeout(Duration::from_secs(5), server).await;
        assert!(joined.is_ok(), "TLS server did not shut down gracefully");
    }
}
