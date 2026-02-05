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
