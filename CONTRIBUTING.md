# Contributing to Rusty Gasket

## Prerequisites

- **Rust 1.88+** (install via [rustup](https://rustup.rs/))
- **Docker** (for database integration tests)
- **just** (task runner): `brew install just`

## Building

```bash
cargo build --workspace
```

## Testing

```bash
# Run all tests
cargo test --workspace --all-targets

# Run tests for a specific crate
cargo test -p rusty-gasket
cargo test -p rusty-gasket-auth

# Run with output
cargo test --workspace --all-targets -- --nocapture
```

Database integration tests require Docker:

```bash
just up          # start PostgreSQL via docker-compose
cargo test -p rusty-gasket-db --all-targets
```

## Linting

All three commands must pass before submitting a PR:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Or use the just target:

```bash
just check       # runs fmt + clippy + test + doc + machete
```

## Code Style

- Follow the existing codebase conventions
- All public items must have doc comments
- `unsafe` code is forbidden at the workspace level
- Use `thiserror` for error types, not manual `impl Display`
- Prefer `tracing` over `println!`/`eprintln!`

## Workspace Lint Policy

The workspace enforces strict lints. Notable ones:

- `unsafe_code = "forbid"` -- no unsafe anywhere
- `clippy::unwrap_used = "deny"` -- use `expect()` with context or propagate errors
- `clippy::print_stdout = "warn"` -- use `tracing` for output
- `clippy::wildcard_dependencies = "deny"` -- pin dependency versions

## PR Process

1. Create a feature branch from `main`
2. Make your changes with tests
3. Run `just check` (or the three lint commands above)
4. Open a PR with a clear description of what and why
5. All CI checks must pass before merge

## Architecture

The project is organized as a Cargo workspace:

```
rusty-gasket/         # The framework (core + optional batteries behind features)
rusty-gasket-macros/  # #[derive(ApiError)] proc macro
examples/
  sample-api/         # runnable example
  recipe-api/         # example using the auth + testing features
  bench-api/          # criterion benchmark target
templates/
  oss/                # cargo-generate template for new projects
```

See the [docs/](docs/) guides for design and usage details.

## Adding a New Plugin

1. Implement the `Plugin` trait in a new module
2. Define lifecycle ordering with `PluginOrdering`
3. Register routes via `routes()` using `TaggedRoute` and `RouteGroup`
4. Add tests using `rusty-gasket-testing::TestApp`

## Adding a New Auth Backend

1. Implement `AuthBackend` in `rusty-gasket-auth` (or your overlay crate)
2. Wire it into `AuthChain` in the application's `main.rs`
3. Test with `MockAuthBackend` or integration tests

## Adding a Workspace Dependency

Shared dependencies go in `[workspace.dependencies]` in the root `Cargo.toml`.
Crates reference them with `{ workspace = true }`.
