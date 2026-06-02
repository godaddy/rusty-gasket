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
