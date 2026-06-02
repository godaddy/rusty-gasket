//! Test utilities for Rusty Gasket applications.
//!
//! Provides [`TestApp`] for building a test harness around your axum router
//! without starting a real HTTP server, [`TestResponse`] for ergonomic
//! response assertions, and [`MockAuthBackend`] for testing authenticated
//! endpoints without real JWT/OIDC infrastructure.
//!
//! # Example
//!
//! ```ignore
//! use rusty_gasket::testing::{TestApp, MockAuthBackend};
//!
//! let app = TestApp::builder()
//!     .mock_auth("test-user")
//!     .router(my_router)
//!     .build();
//!
//! let resp = app.get("/healthcheck").await;
//! assert_eq!(resp.status(), 200);
//! assert_eq!(resp.json::<serde_json::Value>()["status"], "ok");
//! ```

mod mock_auth;
mod test_app;
mod test_response;

pub use mock_auth::MockAuthBackend;
pub use rusty_gasket::BoxError;
pub use test_app::TestApp;
pub use test_response::TestResponse;

/// Re-exports of the most commonly used testing types.
///
/// `use rusty_gasket::testing::prelude::*` to set up an in-process
/// HTTP test in one import.
pub mod prelude {
    pub use rusty_gasket::testing::{BoxError, MockAuthBackend, TestApp, TestResponse};
}
