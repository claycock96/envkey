# Contributing

Thanks for contributing to envkey.

## Prerequisites

- Rust stable (see `rust-toolchain.toml`)
- `cargo`, `clippy`, and `rustfmt`

## Local workflow

```bash
make check
```

This runs:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --locked`

## Pull request expectations

- Keep changes focused and small.
- Add or update tests for behavioral changes.
- Keep CLI output stable unless intentionally changed.
- Update docs when public behavior changes.
- Add a changelog entry for user-visible changes.

Use the pull request template checklist before requesting review.

## Versioning and releases

- We aim to follow Semantic Versioning.
- Pre-1.0 releases may still include breaking changes.
- Tags are of the form `vX.Y.Z` or `vX.Y.Z-beta.N`.
- Release notes are generated from merged pull requests and changelog context.

## Reporting issues

- Bugs/features: GitHub Issues using templates
- Security: follow [SECURITY.md](SECURITY.md)

## Code of Conduct

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
