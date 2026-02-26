# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and the project aims to follow
Semantic Versioning.

## [Unreleased]

### Added

- Global identity override flag: `envkey --identity <FILE> <command>`.
- New default identity path: `~/.envkey/identity.age`.
- Interactive `init` prompt support for custom identity location.
- Tilde expansion for identity path input (for example `~/.envkey2/identity.age`).
- Backward-compatible identity lookup fallback to legacy config-dir location.
- Release Please automation configuration:
  - `.github/workflows/release-please.yml`
  - `release-please-config.json`
  - `.release-please-manifest.json`

### Planned

- Planned M2+ work: team management, multi-environment access controls,
  injection workflows (`run`/`export`), and rotation commands.

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
