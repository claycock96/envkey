# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and the project aims to follow
Semantic Versioning.

## [0.4.0-beta.1](https://github.com/claycock96/envkey/compare/v0.3.0-beta.1...v0.4.0-beta.1) (2026-02-26)


### Features

* add team member commands with admin auth and re-encryption ([#9](https://github.com/claycock96/envkey/issues/9)) ([28890a7](https://github.com/claycock96/envkey/commit/28890a70a381c155d383a667d7b56d43a2cb1b96))

## [0.3.0-beta.1](https://github.com/claycock96/envkey/compare/v0.2.0-beta.1...v0.3.0-beta.1) (2026-02-26)


### Features

* add global --identity flag and tilde-safe init paths ([#4](https://github.com/claycock96/envkey/issues/4)) ([52ac048](https://github.com/claycock96/envkey/commit/52ac048aa6a3af1685621d90563e146f4f4c124e))


### Bug Fixes

* configure release-please to emit plain v* tags ([#7](https://github.com/claycock96/envkey/issues/7)) ([a037db5](https://github.com/claycock96/envkey/commit/a037db5f9771c6664ee5ee58f03bfdc699cce0e1))

## [0.2.0-beta.1](https://github.com/claycock96/envkey/compare/envkey-v0.1.0-beta.1...envkey-v0.2.0-beta.1) (2026-02-26)


### Features

* add global --identity flag and tilde-safe init paths ([#4](https://github.com/claycock96/envkey/issues/4)) ([52ac048](https://github.com/claycock96/envkey/commit/52ac048aa6a3af1685621d90563e146f4f4c124e))

## [Unreleased]

### Added

- Global identity override flag: `envkey --identity <FILE> <command>`.
- New default identity path: `~/.envkey/identity.age`.
- Interactive `init` prompt support for custom identity location.
- Tilde expansion for identity path input (for example `~/.envkey2/identity.age`).
- Backward-compatible identity lookup fallback to legacy config-dir location.
- Team member management commands:
  - `envkey member add <NAME> <PUBKEY> [--role <admin|member|ci|readonly>]`
  - `envkey member update <NAME> <PUBKEY>`
  - `envkey member role set <NAME> <ROLE>`
  - `envkey member rm <NAME> [--yes]`
  - `envkey member ls`
- CI key generation shortcut via `envkey member add --role ci <NAME>`.
- Self-demotion guard for admins in role changes.
- Role changes re-encrypt stored secrets (same mutation model as add/rm/update).
- Identity-based admin authorization for member add/remove.
- Membership change re-encryption of stored secrets with atomic persistence.
- README role definitions and current M2 role-scope notes.
- Release Please automation configuration:
  - `.github/workflows/release-please.yml`
  - `release-please-config.json`
  - `.release-please-manifest.json`
- Release Please now uses plain `v*` tags (no package/component prefix).

### Planned

- Planned M2+ work: multi-environment access controls,
  injection workflows (`run`/`export`), and rotation commands.
- Environment-specific `member grant/revoke` remains deferred to M3.

## [0.1.0-beta.1] - 2026-02-26

### Added

- Initial public beta release with M1 command set:
  - `envkey init`
  - `envkey set <KEY> <VALUE>`
  - `envkey get <KEY>`
  - `envkey ls`
- `.envkey` YAML format with age-encrypted secret values.
- Identity key handling with `$ENVKEY_IDENTITY` override and XDG default path.
- CI checks for format, lint, and tests on Linux/macOS.
- Integration and unit test coverage for M1 behavior and failure modes.
