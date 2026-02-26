# envkey

[![CI](https://github.com/claycock96/envkey/actions/workflows/ci.yml/badge.svg)](https://github.com/claycock96/envkey/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/claycock96/envkey?display_name=tag)](https://github.com/claycock96/envkey/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-brightgreen)](https://www.rust-lang.org/)

**Secrets without servers.**

`envkey` is a single Rust binary for encrypting project secrets with [age](https://github.com/FiloSottile/age), storing them in a git-friendly `.envkey` file, and keeping plaintext out of your repo.

No Vault cluster. No SaaS dependency. No secret sprawl in `.env` files.

## Why envkey

Teams usually choose between two bad defaults:

- Insecure workflows (`.env` in repos, secrets in chat, ad hoc docs)
- Heavy platforms (Vault/KMS/SaaS) with higher setup and operating cost

`envkey` targets the middle:

- Local age identities
- Encrypted values in version control
- Minimal setup and fast local workflow

### Quick comparison

| Approach | Infrastructure | Team sharing | Git-native history | Setup friction |
| --- | --- | --- | --- | --- |
| `.env` files | None | Manual and risky | Poor | Low |
| SOPS | None/optional cloud | Manual key management | Good | Medium |
| Vault | Server required | Strong | Separate system | High |
| `envkey` | None | Designed into workflow (M2+) | Good | Low |

## 60-second demo (current M1)

```bash
# from this repo
cargo install --path .

# initialize local identity and project .envkey
envkey init

# optionally select identity file for this invocation
envkey --identity ~/.envkey/alice.age init

# set and retrieve a secret
envkey set DATABASE_URL "postgres://user:pass@localhost:5432/app"
envkey get DATABASE_URL

# list keys/metadata (values remain encrypted)
envkey ls

# current M1 guardrail
envkey get -e production DATABASE_URL
# => M1 supports only default environment
```

## Install and run

### Option 1: install with Cargo

```bash
cargo install --path .
envkey --help
```

### Option 2: build and run directly

```bash
cargo build --release
./target/release/envkey --help
```

## Identity file location

- Default identity file: `~/.envkey/identity.age`
- Global CLI override: `envkey --identity /path/to/identity.age ...`
- Environment override (still supported): `ENVKEY_IDENTITY=/path/to/identity.age`
- Compatibility fallback: if default is missing, envkey checks legacy config
  location (`$XDG_CONFIG_HOME/envkey/identity.age` or platform equivalent).

### Multi-identity local testing

```bash
envkey --identity ~/.envkey/alice.age init
envkey --identity ~/.envkey/alice.age get DATABASE_URL

envkey --identity ~/.envkey/bob.age init
envkey --identity ~/.envkey/bob.age get DATABASE_URL
```

## Current status

Maturity: **M1 implemented; M2+ planned**.

Implemented now:

- `envkey init`
- `envkey set <KEY> <VALUE>`
- `envkey get <KEY>`
- `envkey ls`
- `.envkey` YAML schema with age-encrypted values

Planned next:

- Team member management (`member add/rm/ls`)
- Multi-environment access control
- Secret injection (`run`, `export`)
- Rotation and audit workflows

## Security model (what this protects)

`envkey` helps protect against:

- plaintext secrets committed to git
- casual repo inspection exposing secret values
- accidental distribution of plaintext config files

`envkey` does not protect against:

- compromised developer machines
- malicious admins
- plaintext exposure inside running process memory

See [SECURITY.md](./SECURITY.md) for reporting and disclosure policy.

## Development

```bash
make check
```

Includes:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --locked`

## Release automation

Releases are managed by [Release Please](https://github.com/googleapis/release-please).

- On pushes to `main`, Release Please opens/updates a release PR.
- Merging that release PR creates a `v*` tag and GitHub release.
- The existing `.github/workflows/release.yml` then builds and uploads artifacts for Linux/macOS/Windows.

Repository setup requirement:

- Add a `RELEASE_PLEASE_TOKEN` repository secret (GitHub PAT with repo write permissions).
  This allows the tag created by Release Please to trigger downstream tag workflows.

## Get involved

If you want to help shape v1.0, high-impact areas are:

1. Team workflow design and implementation (M2)
2. Environment-level access model
3. Injection/export UX for CI and containers
4. Docs and integration examples

Start with:

- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [SUPPORT.md](./SUPPORT.md)
- Open issues labeled `enhancement` or `good first issue`

## License

MIT ([LICENSE](./LICENSE))
