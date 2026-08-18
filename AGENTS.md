# Agent Guide for rust_http_proxy

This guide helps Codex/agents contribute safely and consistently to this repository. It is written for fast onboarding and predictable changes.

## Project Snapshot
- Language: Rust
- Workspace root: `/Users/bytedance/rust_http_proxy`
- Primary crate: `rust_http_proxy` (see `Cargo.toml`)
- Build system: Cargo
- Packaging: Dockerfiles and RPM assets are in the repo

## Repository Map
- `rust_http_proxy/`: primary crate source
- `deploy/`: deployment assets
- `rpm/`: RPM packaging assets
- `Dockerfile*`: container build variants
- `README.md`: user-facing usage and config

## Quick Start
1. Build
- `cargo build`
2. Run (example)
- `cargo run --package rust_http_proxy -- --help`
3. Tests
- `cargo test`

## Standard Workflows
1. Make a small, focused change
- Update only the files needed to deliver the requested behavior
2. Run checks (when relevant)
- `cargo fmt`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
3. Update docs if you add flags, env vars, or behavior
- `README.md`

## Coding Conventions
- Follow `rustfmt` defaults (see `rustfmt.toml`).
- Prefer explicit error handling with clear context.
- Keep functions small and focused; avoid deep nesting.
- Avoid cleverness when clarity is possible.
- Add comments only for non-obvious logic.

## Error Handling
- Prefer returning `Result<T, E>` and propagate errors with context.
- When adding new errors, keep messages actionable and user-facing.
- Avoid panics except for unreachable or invariant-checked paths.

## Logging & Metrics
- Check for existing logging conventions before adding new logs.
- Prefer structured logging (fields) if supported.
- Avoid logging sensitive data, secrets, or full request payloads.

## Configuration & Secrets
- Do not commit secrets or private keys.
- Prefer existing config files or environment variables.
- Document new configuration in `README.md`.

## Tests
- Favor small, deterministic tests.
- If you add a new feature, add or update tests when practical.
- When tests are not added, explain why in your response.

## Performance & Safety
- Avoid unnecessary allocations in hot paths.
- Prefer borrowing over cloning when it improves performance and clarity.
- Keep concurrency safe and explicit; document assumptions.

## Docs & User-Facing Changes
- Update `README.md` when adding flags, environment variables, or major behavior changes.
- Keep examples current with any CLI changes.

## Release / Packaging Notes
- If changes affect packaging, update related scripts or docs in:
- `Dockerfile*`
- `rpm/`
- `deploy/`

## Troubleshooting
- If a command fails, capture the exact error and mention it in your response.
- If behavior is unclear, request clarification before making broad changes.

## Safe Defaults for Agents
- Avoid destructive commands (`git reset --hard`, `rm -rf`) unless explicitly asked.
- Never delete or rewrite user changes you did not make.
- Ask for confirmation before behavior-changing refactors.

## Cursor Cloud specific instructions
These notes cover non-obvious caveats for this repo in the Cloud Agent VM. Standard build/lint/test/run commands live in the `Quick Start` / `Standard Workflows` sections above; use those.

### Toolchain
- The crate is `edition = "2024"` (MSRV `1.85.0`), so it needs Rust >= 1.85. The base image ships an older system `rustc` (1.83), so the environment sets rustup's `stable` toolchain as the default (`rustup default stable`). Just use `cargo` normally; do not fall back to the 1.83 toolchain.
- Default features are `aws_lc_rs` + `mimalloc`; `aws_lc_rs` needs `cmake` + a C toolchain (already present). No OpenSSL is used.

### Lint caveats
- Plain `cargo clippy -- -D warnings` (lib + bins) is clean.
- `cargo clippy --all-targets --all-features` pulls in the optional `bpf*` features, which build `libbpf` from source and need extra system packages (`autoconf autopoint flex bison gawk clang pkg-config make libelf-dev zlib1g-dev`, installed in this environment). Without them it fails with `autoreconf is required to compile libbpf-sys`.
- `cargo clippy --all-targets ...` (i.e. including the test target) currently fails because `#![deny(clippy::unwrap_used)]` flags an existing `.unwrap()` in a `#[cfg(test)]` test in `rust_http_proxy/src/config.rs`. This is pre-existing (CI does not run clippy) — not an environment problem.

### Test caveats
- `cargo test` runs fully self-contained e2e tests (proxy + upstreams are spawned in-process; no external services needed).
- Known pre-existing failures: 6 HTTP/2-upstream e2e tests fail with `hyper::Error(Io, BrokenPipe)` (`reverse_proxy_e2e_tests` H2 cases, `forward_bypass_e2e_tests` mitm-h2 cases, `mitm_stub_e2e_tests` h2 cases). Trace logs show the proxy actually returns `200 OK`; the error is a race in HTTP/2 connection teardown. CI (`.github/workflows/combined_build.yml`) never runs `cargo test`, so this is ungated. The other 100 tests pass. Tests do not initialize the proxy logger — to debug, temporarily call `log_x::init_log("/tmp", "debug.log", "trace")` inside a test.

### Running the app
- Single self-contained binary; default port `3128` (README examples use `7788`). The MITM React console (`/mitm`) is pre-built and embedded via `rust-embed` from `mitm-ui/dist/` (committed), so no Node build is needed to run the proxy — Node is only needed to rebuild `mitm-ui`.
- Quick smoke test: `./target/debug/rust_http_proxy -p 7788 --web-content-path <dir> --users user:pass`, then static serving is `curl http://127.0.0.1:7788/`, forward proxy is `curl -x http://user:pass@127.0.0.1:7788 http://<origin>`, and metrics are `curl -u user:pass http://127.0.0.1:7788/metrics`. Without `--users`, the proxy/metrics/mitm endpoints are unauthenticated.
