# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-06-05

### Fixed
- **`OpenApiPlugin` no longer panics at startup.** `OpenApiPlugin::routes()`
  registered `GET /openapi.json` twice — once as an explicit spec route and
  once via the Swagger-UI `.url("/openapi.json", spec)` builder (which itself
  routes the spec) — so `build_router` panicked with "Overlapping method route.
  Handler for `GET /openapi.json` already exists", crashing every service that
  registered the plugin. The spec is now registered exactly once via the
  Swagger-UI builder; `GET /openapi.json` and `/swagger-ui` behave as before.

## [0.1.3] - 2026-06-03

### Added
- **`BasicAuthBackend`** (`auth` feature) — an `AuthBackend` for the HTTP Basic
  scheme that constant-time-compares both the username and password from
  `Authorization: Basic <base64(user:pass)>` against one configured credential
  (held in `secrecy::SecretString`, redacted from `Debug`). For human-facing
  internal pages (admin/diagnostics views, staging gates) guarded by a single
  shared password. Pairs with `RouteGroup::ProtectedWith` like
  `StaticBearerBackend`. Follows the chain contract: defers (`Ok(None)`) when no
  Basic credential is present, definitive failure when one is present but wrong.

## [0.1.2] - 2026-06-02

### Added
- **Named protected auth chains** — `RouteGroup::ProtectedWith("name")` lets
  different endpoints authenticate with different chains in one service
  (e.g. a static-token push endpoint alongside JWT-protected and public
  routes). Register a named chain with `GasketAppBuilder::auth_chain(name,
  state)`; named-protected routes get the full protected middleware stack with
  the named chain substituted for the default authentication layer.
- **`StaticBearerBackend`** (`auth` feature) — an `AuthBackend` that
  constant-time-compares the `Authorization: Bearer` token against one
  configured secret. Backed by `subtle` for the comparison.

## [0.1.1] - 2026-06-02

### Added
- **`s3` feature** — `S3ObjectStore`: get/put/head/list-by-prefix, a presigned
  GET URL, and a streaming `download_response()` helper that serves an object
  as an HTTP response without buffering the whole body in memory.
- **`templates` feature** — minijinja-backed HTML templating. `Templates`
  renders named templates (compiled in-memory via the builder, or loaded from a
  directory) to a `String` or an autoescaped axum HTML response.

## [0.1.0] - 2026-06-02

### Breaking changes
- Builder setters renamed from `with_*` to bare names across the
  workspace: `AppConfigDefinition::{with_server, with_env}` →
  `{server, env}`; `HealthPlugin::with_app_info` → `app_info`;
  `TestAppBuilder::{with_mock_auth, with_mock_auth_identity,
  with_anonymous_auth, with_auth_state, with_logging}` → bare names.
  `TestAppBuilder::logging(bool)` now takes a bool argument.
  Alternative constructors (`with_identity`, `with_details`,
  `with_client`, etc.) keep the `with_*` prefix.
- `AuthMiddlewareState::audit_logger` setter renamed to
  `with_audit_logger` for consistency with the audit-event builders
  (`AuthAuditEvent::with_auth_method`, `with_subject`). The previous
  `audit_logger` method remains as a `#[deprecated]` shim.
- `GasketApp::shutdown` returns `()` instead of
  `Result<(), BoxError>` — per-plugin failures are logged, never
  propagated.
- `rusty-gasket-db` no longer builds with `--no-default-features`;
  the SQLx `Any` pool needs at least one backend feature. Pick
  `postgres` or `mysql` (or both).
- `RateLimitSubject`'s inner field is now private. Construct with
  `RateLimitSubject::new(subject)` and read via `as_str()`.
- `RouteGroup` is now `#[non_exhaustive]`; downstream `match`
  statements need a wildcard arm.
- Many config and event types gained `#[non_exhaustive]`
  (`AppConfigDefinition`, `ServerConfig`, `DatabaseConfig`,
  `DynamoConfig`, `AuthMiddlewareState`, `TransactionMiddlewareState`,
  plus lifecycle context structs). Construct with `::new()` or
  `Default::default()` + field assignment.
- `AuthSummary`, `AuthAuditEvent`, and `AuthMiddlewareState` no
  longer expose their fields publicly. Construct via the builder
  (`AuthSummary::builder()`) or `::new()` + `with_*` setters; read
  via the new accessor methods (`client_id()`, `user_id()`,
  `auth_method()`, etc.). Closes a write-after-construction hole on
  `#[non_exhaustive]` types where an `&mut` reference could rewrite
  values an audit logger was about to record.
- `AuthResult::Failed` now carries a `FailedReason` newtype rather
  than a `String`. The `Display` impl emits only the bounded
  category label (`"failed"`); the raw reason is reachable via
  `AuthResult::failure_reason()` for callers that explicitly need
  it. `FailedReason::new` strips ASCII control bytes and truncates
  to 512 bytes — defeats log-injection and audit-log amplification.
- `RateLimitSubject::new(subject)` now truncates to 256 bytes at a
  UTF-8 boundary. Attacker-controlled JWT `sub` claims can no
  longer grow the rate-limit `DashMap` unbounded.
- `AwsSecretsProvider` four ad-hoc constructors (`from_env`,
  `with_client`, `with_client_and_ttl`, `with_cache_ttl`) collapsed
  into one builder: `AwsSecretsProvider::builder().cache_ttl(...).build(client)`
  or `.build_from_env().await`. The `from_env()` convenience
  constructor is kept.
- `JwksError` (previously `pub(super)`) is now `pub` and
  `#[non_exhaustive]`. Observability code can downcast
  `AuthError::BackendError`'s inner `Box<dyn Error>` to match on
  `HttpStatus { status }`, `BodyTooLarge { max_bytes }`, or
  `FetchTask(JoinError)` instead of grepping message strings.

### Added
- `AppConfigDefinition::from_file_optional` returns `Ok(None)` on a
  missing file so callers no longer have to string-match errors.
- `GasketAppBuilder::request_body_limit(usize)` lets operators
  override the 8 MiB default body size cap.
- `JwtBackendBuilder::leeway_secs` and `validate_nbf` knobs;
  defaults tightened (leeway 0, validate_nbf true).
- JWKS URL parsing now goes through `url::Url` and rejects
  malformed/whitespace/non-http(s) URLs at build time.
- `AuthError::category` and `AuthResult::category` return
  bounded-cardinality `&'static str` labels suitable for metrics
  fields, replacing unbounded `to_string()`.
- `OtelGuard::shutdown(self).await` runs the blocking SDK shutdown
  on `spawn_blocking` so it does not deadlock the runtime.
- `HEALTH_CHECK_TIMEOUT` (5s) is now `pub`; `HealthContributor`
  doc spells out the timeout, concurrency, and cancellation contract.
- Re-exports of `BoxError` plus a `prelude` module on every
  framework crate so consumers can avoid pulling `rusty-gasket`
  for the error type alone.
- `cargo-deny` (`deny.toml`), MSRV CI job, `cargo-semver-checks`
  CI job, community files (`SECURITY.md`, `MIGRATION.md`,
  `CODE_OF_CONDUCT.md`, issue/PR templates).
- `trybuild` compile-fail suite pinning `#[derive(ApiError)]`
  diagnostics for wrong literal kinds, unknown keys, status range,
  missing required attrs, and non-enum input.
- `AuthSummary::builder()` returns an `AuthSummaryBuilder` with
  `client_id` / `client_ip` / `user_id` / `auth_method` /
  `auth_result` / `privileged` setters and matching read-side
  accessors on `AuthSummary` itself.
- `AwsSecretsProvider::builder()` returns an
  `AwsSecretsProviderBuilder` (`cache_ttl` setter, `build(client)` /
  `build_from_env().await` terminals). Inflight single-flight map
  now keys `Weak<Semaphore>` so attacker-influenced keys cannot
  grow the map without bound — entries self-evict after the fetch.
- `#[api_error(skip_into_response)]` opt-out attribute lets callers
  with a hand-rolled `IntoResponse` impl avoid the duplicate-impl
  conflict from the derive.
- `cargo xtask` is now wired via `.cargo/config.toml`; the
  `xtask` crate is reachable by its conventional alias.
- Re-exports added so downstream code can name framework types in
  signatures: `rusty_gasket_auth::{FailedReason, IdentityBuilder,
  AuthRequired}`, `rusty_gasket::observability::AuthSummaryBuilder`,
  `rusty_gasket_gd::auth::GdAuthConfigError`.
- CI gains a `-p rusty-gasket --no-default-features` matrix entry
  plus a dedicated negative job that asserts
  `rusty-gasket-db --no-default-features` triggers the
  `compile_error!` and that the message mentions "feature".
- Tests: `OtelGuard` async-shutdown smoke + drop-only-no-panic; JWKS
  alg-confusion (`token_alg_must_match_jwk_alg`); JWKS no-stampede
  under leader cancellation
  (`leader_cancellation_does_not_starve_followers`);
  `from_file_optional` missing/present/invalid; `AuthSummary`
  builder field round-trip; chain `error_short_circuits_remaining_backends`
  now uses an `AtomicUsize` counter spy to prove the trailing
  backend is not invoked.

### Changed
- JWKS hot path is wait-free via `ArcSwap` with prebuilt
  `DecodingKey`s cached per `kid` — no per-request lock or
  re-parse. Single-flight refresh detached via `tokio::spawn` so
  caller cancellation no longer abandons the in-flight fetch.
- `AwsSecretsProvider` now actually single-flights cache misses
  via a per-key `Mutex` map.
- `AuthSummary` fields are `Cow<'static, str>` so the placeholder
  literals (`"unknown"`, `"anonymous"`, `"none"`) no longer allocate
  per protected request.
- `tower-http::limit::RequestBodyLimitLayer` (8 MiB default) is
  applied to all Public and Protected routes.
- `DatabaseConfig::acquire_timeout_secs` (default 5s) bounds pool
  acquisition so exhaustion surfaces as a 503 instead of blocking.
- Default `DatabaseConfig::max_connections` raised from 10 to 32.
- DB transaction middleware and auth middleware no longer carry a
  redundant `#[tracing::instrument]` span — the root `http_request`
  span already covers them.
- Cookie token source rejects duplicate cookie names rather than
  picking the first match (defends against cookie shadowing).
- `prepare_jwks` warn-logs each broken kid at most once per process
  so a JWKS publishing a single bad key stops re-warning every cache
  refresh.
- JWKS `reqwest::Client` pinned to `redirect::Policy::none()` so a
  DNS-poison or CDN-controlled redirect cannot serve attacker JWKS
  JSON (and cannot downgrade `https` to `http` past the
  `jwks_allow_http(false)` check).
- `JwtBackendBuilder::jwks_url` doc rewritten to honestly describe
  the spawn-detach single-flight contract: concurrent callers
  coalesce, but a cancelled leader can leave a small race window
  where one follower fires a redundant fetch. The total upstream
  count is bounded by a small constant, not by `N` — pinned by the
  `leader_cancellation_does_not_starve_followers` test.
- `OtelGuard::shutdown(self).await` is now bounded by an internal
  5 s deadline so a hung collector cannot park process shutdown on
  SIGTERM.
- `OtelGuard` rewritten on `Option<T>::take()` instead of
  `ManuallyDrop` + `std::mem::replace`. No manual `mem::forget`,
  no swap-in-and-leak of empty SDK providers, and `Drop` becomes a
  true no-op after the async `shutdown()` runs.
- `BUILT_TIME_UTC` reported by `/healthcheck` honors the
  `SOURCE_DATE_EPOCH` build-time env var when set (the de-facto
  reproducible-build convention used by Debian, Nix, Bazel, and
  GitHub Actions release tooling).
- Rate-limit cleanup task wraps each `retain_recent` pass in
  `catch_unwind` so a downcast/allocator panic can't silently kill
  the task and leak the limiter `DashMap`.
- `AwsSecretsProvider` single-flight switched from per-key
  `Mutex<()>` to `Semaphore::new(1)` to express the "one fetcher
  at a time" intent more clearly; same with the JWKS fetch lock.
- Wildcard `_` match arms removed from in-crate `#[non_exhaustive]`
  enums (`HealthStatus`, `AuthError`'s client-error arm) so adding
  a variant in-crate forces a deliberate decision instead of
  sliding into a catch-all that `non_exhaustive` only catches
  cross-crate.

### Fixed
- README quick-start example no longer string-matches error messages
  for the "missing config file" path.
- JWKS bogus-`kid` DoS amplifier — repeated requests with random
  `kid` values used to force one upstream fetch per token; now they
  see `FreshButMissing` until the cache TTL.
- `#[derive(ApiError)]` propagates attribute parse errors (wrong
  literal kind, unknown key) instead of silently swallowing them.
- The generated `StatusCode::from_u16(N).expect(...)` in
  `#[derive(ApiError)]` is now an inline `const { ... }` block
  evaluated at compile time — no runtime expect site in user code.
- Health contributors that hang now degrade to `HealthStatus::Error`
  after 5s instead of stalling the liveness probe.
- `auth_middleware` auto-populates `RateLimitSubject` from the
  authenticated identity; `ClientIdKey` rate limiting no longer
  silently no-ops in production.
- `AppConfig` and `AppConfigDefinition` `Debug` no longer print
  section values; secret URLs in `[database]` etc. no longer leak
  via `dbg!(&config)`.
- Stale docs (DatabaseConfig `Display` claim, RouteGroup pre-body-
  limit list, AuthResult `non_exhaustive` comment, Plugin lifecycle
  list missing `layers`/`routes`).
- `templates/{oss,godaddy}/src/routes.rs` constructed
  `TaggedRoute { group, router }` via struct-literal syntax — a
  guaranteed compile break for every scaffolded project, since
  `TaggedRoute` is `#[non_exhaustive]`. Now uses
  `TaggedRoute::new(...)`. Template `Plugin::name` return type
  also fixed from `&str` to `&'static str` to match the trait.
- Stale `pub(crate)` qualifier on `built_info` (no-op inside a
  private module at the crate root) and a docstring claiming
  `pub(crate)` for a function that's actually `pub`.


## [0.1.0] - 2026-05-28

### Added

#### Core Framework (`rusty-gasket`)
- Plugin-based architecture with ordered lifecycle (init, configure, prepare, ready, shutdown)
- Topologically sorted plugin execution with `before`/`after`/`first`/`last` constraints
- Route groups (Bare, Public, Protected) with distinct middleware stacks
- Ordered middleware pipeline: transport security, logging, authentication, rate limiting, transaction, custom
- TOML/YAML configuration with environment-specific overrides and env var resolution
- Structured error handling with `#[derive(ApiError)]` proc macro and correlation IDs
- Health check framework with contributor aggregation and `/healthcheck` endpoint
- Per-client rate limiting with DashMap eviction and Governor token buckets
- UUID v7 request ID generation and propagation
- Structured JSON logging with tracing-subscriber
- OpenTelemetry OTLP export support
- OpenAPI/Swagger UI integration via utoipa
- TLS support via axum-server + rustls
- Preset system (`presets::api()`) for common plugin bundles

#### Authentication (`rusty-gasket-auth`)
- Pluggable `AuthBackend` trait for custom auth implementations
- Built-in JWT backend with HMAC and RSA support
- API key authentication backend with custom validator trait
- `AuthChain` composing multiple backends (first match wins)
- `Authenticated` and `OptionalIdentity` axum extractors
- Scope-based authorization policies
- Typed identity attributes for backend-specific claims
- Audit logging for authentication events

#### Database (`rusty-gasket-db`)
- PostgreSQL and MySQL support via SQLx `Any` driver
- `DatabasePlugin` with connection pool lifecycle
- `DbTx` extractor for per-request transactions with auto-rollback
- Request ID correlation in database session variables

#### DynamoDB (`rusty-gasket-dynamodb`)
- `DynamoPlugin` with shared `DynamoClient` extension and lifecycle wiring
- `DynamoClient` extractor for handler-side access
- Configuration via `AppConfig` section, env vars, or LocalStack-friendly endpoint override

#### Testing (`rusty-gasket-testing`)
- `TestApp` builder for in-process HTTP testing without a running server
- `TestResponse` with status, JSON deserialization, and header inspection
- `MockAuthBackend` for testing authenticated endpoints

#### Proc Macros (`rusty-gasket-macros`)
- `#[derive(ApiError)]` for generating `IntoResponse` with structured JSON error bodies
- `#[api_error(code, status, expose)]` attribute for per-variant configuration

[Unreleased]: https://github.com/godaddy/rusty-gasket/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/godaddy/rusty-gasket/releases/tag/v0.1.0
