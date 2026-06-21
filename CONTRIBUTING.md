# Contributing to EVMGuard

## Development requirements

- Stable Rust toolchain.
- `cargo fmt`, `cargo clippy`, and `cargo test` must pass before a pull request is opened.

## Contribution process

1. Open an issue before starting a substantial change.
2. Keep pull requests focused on one behavior or rule.
3. Include tests for every new or modified rule.
4. Preserve stable rule identifiers once released.
5. Update documentation when public behavior changes.

## Rule contributions

New rules must define a stable identifier, a severity, expected evidence, test fixtures, and documentation in `docs/rules.md`.

## Commit messages

Use concise imperative commit messages, such as `Add ERC-20 approval inspection`.
