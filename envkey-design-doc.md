# envkey — Secrets Without Servers

## Design Document v1.0

**One-liner:** Share, rotate, and inject secrets using age encryption and a file — no Vault, no SaaS, no server.

**Mission:** Fill the gap between "paste secrets in Slack" and "deploy HashiCorp Vault" with a zero-infrastructure, git-friendly, team-capable secret management tool that anyone can set up in under 60 seconds.

---

## 1. Problem Statement

### 1.1 The Secret Management Spectrum

Every software team faces the same problem: how do we share secrets (API keys, database passwords, signing certificates, tokens) between team members and environments? The current landscape offers only two extremes with nothing in between:

**The Insecure End:** `.env` files committed to repos (accidentally or deliberately), secrets pasted in Slack/Discord, shared Google Docs with passwords, plain-text config files on servers, sticky notes, 1Password shared vaults used as a poor-man's secret manager. A 2024 Akeyless survey found 96% of organizations report "secrets sprawl" — secrets scattered across multiple locations with no audit trail.

**The Overengineered End:** HashiCorp Vault (requires a dedicated server, operator knowledge, unsealing ceremonies, Raft consensus), AWS Secrets Manager ($0.40/secret/month plus API charges), Doppler/Infisical/1Password Secrets Automation (SaaS dependency, vendor lock-in, paid tiers for team features). These solutions are excellent for large organizations, but they require infrastructure that most teams under 50 people will never set up. The activation energy is too high.

### 1.2 The Closest Existing Solution: SOPS

Mozilla SOPS (now a CNCF project) comes closest to solving this problem. SOPS encrypts values in structured files (YAML, JSON, ENV, INI) while leaving keys visible, enabling git diffs. It supports age, PGP, AWS KMS, GCP KMS, and Azure Key Vault as encryption backends.

But SOPS has critical gaps:

1. **No team key management.** SOPS encrypts to specific age/PGP keys, but there's no built-in concept of "team members." Adding a new developer means manually re-encrypting every secrets file with the new key added. Removing a developer requires the same. There is no `sops add-member` command.

2. **No secret injection.** SOPS decrypts files, but doesn't inject secrets into processes. Developers must write `sops exec-env secrets.yaml -- ./myapp` or pipe through `sops -d` and source manually. There's no native `envkey run ./myapp` that just works.

3. **No rotation workflow.** SOPS has no concept of secret rotation. There's no `sops rotate` that generates a new database password, updates the encrypted file, and commits the change.

4. **Configuration overhead.** SOPS requires a `.sops.yaml` configuration file with creation rules. The documentation for setting up age with SOPS spans multiple pages. First-time setup takes 15-30 minutes.

### 1.3 The Insight

age proved that encryption can be as simple as GPG was supposed to be — small keys, no configuration, no key servers. What's missing is the workflow layer on top: team membership, secret injection, rotation, and a git-native storage model that makes secrets a first-class part of the codebase without the secrets themselves ever being visible.

envkey is the workflow tool that age needs, just as git is the workflow tool that SHA-1 hashing needed.

---

## 2. Design Principles

1. **Zero infrastructure.** No servers, no SaaS accounts, no cloud services. The secrets file lives in your git repo. The encryption keys live on team members' machines. That's it.

2. **Git-native.** The encrypted secrets file is designed to be committed to version control. It diffs meaningfully (keys visible, values encrypted). It merges cleanly (each key-value pair is an independent encrypted unit). It has full history via `git log`.

3. **Team-first.** Adding and removing team members is a first-class operation, not an afterthought. `envkey member add alice@company.com` is all it takes. Key distribution is handled automatically.

4. **age under the hood.** All cryptography uses the age v1 specification — audited, reviewed, implemented in Go (filippo.io/age) and Rust (str4d/rage). No custom cryptography. No algorithm choices.

5. **Injection-native.** `envkey run -- ./myapp` decrypts secrets and injects them as environment variables. This is the primary interface for consuming secrets.

6. **Single binary.** One binary, all platforms. No Python, no Node, no runtime dependencies.

---

## 3. Data Model

### 3.1 The Secrets File: `.envkey`

The central artifact is a single file called `.envkey` (or `.envkey.yaml`) that lives in the root of a project repository. It contains:

```yaml
# .envkey - committed to git
version: 1
team:
  alice:
    pubkey: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
    role: admin
    added: 2026-01-15
  bob:
    pubkey: age1yr5s663dts2yk0p0r65s0gf06yp2kkfhvny3qanmm05uqm6uz5esj0pxhz
    role: member
    added: 2026-01-20
  ci-prod:
    pubkey: age1tg5rmxlyjcetlv3d32ul4my9k5y4lt60zzml00ewjgcxzz247w4q0n5yup
    role: ci
    added: 2026-02-01

environments:
  default:
    DATABASE_URL: <age-encrypted blob>
    API_KEY: <age-encrypted blob>
    STRIPE_SECRET: <age-encrypted blob>
  production:
    DATABASE_URL: <age-encrypted blob>
    API_KEY: <age-encrypted blob>
    STRIPE_SECRET: <age-encrypted blob>
    SENTRY_DSN: <age-encrypted blob>
  staging:
    DATABASE_URL: <age-encrypted blob>
    API_KEY: <age-encrypted blob>
```

### 3.2 Encryption Model

Each secret value is independently encrypted using age, with multiple recipients (all current team members with access to that environment):

```
For each secret value:
  1. Generate a random 128-bit data key
  2. Encrypt the data key to each team member's age public key
  3. Encrypt the secret value with the data key (AES-256-GCM)
  4. Store as base64-encoded age ciphertext
```

This means:
- **Any single team member can decrypt** — they only need their own private key
- **Adding a member** requires re-encrypting only the data keys (not re-encrypting the actual secrets)
- **Removing a member** requires re-encrypting all secrets (because the removed member might have decrypted and cached them — the re-encryption generates new data keys)
- **Each value is independently encrypted** — git diffs show which keys changed, even though values are opaque

### 3.3 Key Storage

Team members' private keys are stored at `~/.config/envkey/identity.age` (or `$ENVKEY_IDENTITY`). This file is created once during `envkey init` or `envkey join` and never needs to be shared.

The CI/CD key pair is generated during `envkey member add --role ci ci-prod` and the private key is stored as a CI secret (e.g., GitHub Actions secret, GitLab CI variable).

### 3.4 Role-Based Access

| Role | Decrypt default | Decrypt env-specific | Add members | Remove members | Rotate |
|------|----------------|---------------------|-------------|----------------|--------|
| admin | Yes | All | Yes | Yes | Yes |
| member | Yes | Assigned only | No | No | No |
| ci | No | Assigned only | No | No | No |
| readonly | Yes | Assigned only | No | No | No |

Roles are enforced by encryption: a CI key is only listed as a recipient for its specific environment's secrets. It literally cannot decrypt other environments because it doesn't have the data key.

---

## 4. CLI Interface

### 4.1 Initialization

```bash
# First-time setup in a project
$ envkey init
✓ Generated identity key at ~/.config/envkey/identity.age
✓ Created .envkey with you as admin
✓ Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

Add your first secret:
  envkey set DATABASE_URL "postgres://..."

# Join an existing project (someone shares your pubkey output from init)
$ envkey init
✓ Generated identity key at ~/.config/envkey/identity.age
Your public key: age1yr5s663dts2yk0p0r65s0gf06yp2kkfhvny3qanmm05uqm6uz5esj0pxhz

Share this key with a project admin to be added.
```

### 4.2 Secret Management

```bash
# Set a secret (default environment)
$ envkey set DATABASE_URL "postgres://user:pass@host:5432/db"
✓ Encrypted DATABASE_URL for 3 recipients (default)

# Set for specific environment
$ envkey set -e production DATABASE_URL "postgres://prod:secret@prod-host:5432/db"
✓ Encrypted DATABASE_URL for 2 recipients (production)

# Get a single secret
$ envkey get DATABASE_URL
postgres://user:pass@host:5432/db

# List all keys (values hidden)
$ envkey ls
ENVIRONMENT  KEY              SET BY   LAST MODIFIED
default      DATABASE_URL     alice    2026-01-15
default      API_KEY          alice    2026-01-15
default      STRIPE_SECRET    bob      2026-01-20
production   DATABASE_URL     alice    2026-02-01
production   SENTRY_DSN       alice    2026-02-01

# Remove a secret
$ envkey rm API_KEY
✓ Removed API_KEY from default

# Show a secret's value
$ envkey get DATABASE_URL -e production
postgres://prod:secret@prod-host:5432/db
```

### 4.3 Team Management

```bash
# Add a team member
$ envkey member add bob age1yr5s663...
✓ Added bob (member) — re-encrypted 3 secrets in default

# Add CI identity  
$ envkey member add --role ci ci-prod
✓ Generated CI key pair
✓ Private key (add this to your CI secrets as ENVKEY_IDENTITY):
  AGE-SECRET-KEY-1QFWJT8DK5AJ3WEQK23SGTA6RMMFGWLZ5SQRNYXR3GXQPE0ME2EQHS5AE2

# Assign environment access
$ envkey member grant ci-prod -e production
✓ ci-prod can now decrypt production secrets

# Remove a team member
$ envkey member rm bob
⚠ Removing bob requires re-encrypting all accessible secrets.
  This generates new encryption keys that bob cannot decrypt.
  Continue? [y/N] y
✓ Removed bob — re-encrypted 3 secrets in default

# List team
$ envkey member ls
NAME      ROLE    ENVIRONMENTS        ADDED
alice     admin   all                 2026-01-15
bob       member  default             2026-01-20
ci-prod   ci      production          2026-02-01
```

### 4.4 Secret Injection (The Core Workflow)

```bash
# Run a command with secrets injected as environment variables
$ envkey run -- ./start-server.sh
# equivalent to: DATABASE_URL=... API_KEY=... ./start-server.sh

# Run with specific environment
$ envkey run -e production -- docker compose up

# Export as .env file (for tools that need it)
$ envkey export > .env
# or for specific environment
$ envkey export -e staging > .env.staging

# Export as JSON
$ envkey export --format json

# Pipe a single secret
$ envkey get SIGNING_KEY | base64 -d > signing.key

# Use in Dockerfile or CI
$ envkey run -e production -- npm run deploy
```

### 4.5 Secret Rotation

```bash
# Rotate a specific secret (prompts for new value)
$ envkey rotate DATABASE_URL
New value for DATABASE_URL: [hidden input]
✓ Rotated DATABASE_URL across all environments

# Rotate with generated value
$ envkey rotate API_KEY --generate 32
✓ Generated new 32-character random API_KEY
✓ Rotated in default, production

# Rotate all secrets (re-encrypt with new data keys)
$ envkey rotate --all
✓ Rotated encryption keys for all 5 secrets across 3 environments

# Rotate after member removal (recommended)
$ envkey member rm bob && envkey rotate --all
```

### 4.6 Git Integration

```bash
# Diff encrypted changes (shows which keys changed, not values)
$ envkey diff
~ default/DATABASE_URL  (modified by alice, 2 hours ago)
+ default/NEW_KEY       (added by alice, 2 hours ago)
- staging/OLD_KEY       (removed by bob, 1 day ago)

# Audit log (from git history)
$ envkey log
2026-02-15 alice  set     default/DATABASE_URL
2026-02-14 alice  add     production/SENTRY_DSN
2026-02-10 alice  member  added bob
2026-02-01 alice  init    created .envkey
```

---

## 5. Architecture

### 5.1 System Components

```
┌─────────────────────────────────────────────────────────┐
│                    envkey CLI                            │
│                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │
│  │ Crypto   │ │ Team     │ │ Inject   │ │ Storage   │  │
│  │ Engine   │ │ Manager  │ │ Engine   │ │ Layer     │  │
│  │          │ │          │ │          │ │           │  │
│  │ age lib  │ │ RBAC     │ │ exec()   │ │ .envkey   │  │
│  │ keygen   │ │ grant/   │ │ env vars │ │ file fmt  │  │
│  │ encrypt  │ │ revoke   │ │ export   │ │ YAML ser  │  │
│  │ decrypt  │ │ rotate   │ │ .env fmt │ │ git ops   │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Identity Manager                     │   │
│  │  ~/.config/envkey/identity.age                    │   │
│  │  $ENVKEY_IDENTITY env var                         │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘

┌──────────────┐         ┌──────────────┐
│   .envkey    │ ◀──── git ────▶ │   Remote     │
│   (repo)     │         │   (GitHub,   │
│              │         │    GitLab)   │
└──────────────┘         └──────────────┘
```

### 5.2 Cryptographic Design

**Key Hierarchy:**

```
Team Member's age Identity (long-lived, per-person)
  └─▶ Data Key (per-secret, random 128-bit)
       └─▶ Secret Value (AES-256-GCM encrypted)
```

**Encryption of a single secret value:**

```
1. plaintext = "postgres://user:pass@host/db"
2. data_key = random_bytes(16)  // 128-bit
3. recipients = [alice.pubkey, bob.pubkey, ci-prod.pubkey]
4. encrypted = age.Encrypt(plaintext, recipients)
   // age internally:
   //   - encrypts data_key to each recipient's X25519 pubkey
   //   - encrypts plaintext with ChaCha20-Poly1305 using data_key
5. store as base64(encrypted) in .envkey YAML
```

**Decryption:**

```
1. Read base64 blob from .envkey
2. Load identity from ~/.config/envkey/identity.age
3. plaintext = age.Decrypt(blob, identity)
   // age internally:
   //   - finds the recipient stanza matching this identity
   //   - decrypts data_key using identity's X25519 private key
   //   - decrypts plaintext with ChaCha20-Poly1305 using data_key
4. Return plaintext
```

**Member addition (re-keying):**

```
When adding new member C to a secret encrypted for [A, B]:
1. Decrypt secret using current admin's identity → plaintext
2. Re-encrypt plaintext with recipients = [A, B, C]
3. Store new ciphertext (replaces old)
// Note: this is a full re-encryption because age doesn't support 
// adding recipients to existing ciphertext
```

**Member removal (re-keying):**

```
When removing member B from secrets encrypted for [A, B, C]:
1. Decrypt all secrets B could access using admin's identity
2. Re-encrypt each with recipients = [A, C]  (B excluded)
3. Store new ciphertexts
// Critical: must re-encrypt ALL secrets B had access to,
// because B may have cached plaintext values
```

### 5.3 File Format Specification

The `.envkey` file is YAML with a specific schema:

```yaml
version: 1

# Team members and their public keys
team:
  <name>:
    pubkey: <age public key (bech32)>
    role: admin | member | ci | readonly
    added: <ISO 8601 date>
    environments: [list]  # optional, defaults to ["default"]

# Encrypted secrets organized by environment  
environments:
  <env-name>:
    <KEY>:
      value: <base64-encoded age ciphertext>
      set_by: <team member name>
      modified: <ISO 8601 datetime>

# Optional metadata
metadata:
  created: <ISO 8601 datetime>
  project: <project name>
```

**Why YAML?** Keys are visible in plaintext, which enables git diffs. YAML is more human-readable than JSON for this use case. The file is machine-written (by envkey) and human-readable (for git review). YAML comments survive round-tripping, allowing manual annotations.

**Merge conflict strategy:** Since each secret is an independent key-value pair, git merges work naturally. The only merge conflicts occur when two people modify the same secret simultaneously, which is the correct behavior (force human resolution). envkey includes a `envkey merge-driver` command that can be registered as a git merge driver for smarter conflict resolution.

---

## 6. Implementation Plan

### 6.1 Language Choice: Rust

Rationale:
- Single static binary with no dependencies
- The `rage` crate (Rust age implementation) is production-quality, maintained by str4d (one of age's designers)
- Memory safety critical for cryptographic code
- Cross-compilation to all major platforms
- Fast startup time (important for `envkey run` which is in the critical path of every `docker compose up`)

### 6.2 Key Dependencies

| Crate | Purpose | Maturity |
|-------|---------|----------|
| `age` (rage) | age encryption/decryption | Production (str4d) |
| `serde` + `serde_yaml` | YAML serialization | Production |
| `clap` | CLI parsing | Production |
| `base64` | Encoding | Production |
| `secrecy` | Zeroize secrets from memory | Production |
| `dialoguer` | Interactive prompts | Stable |
| `dirs` | XDG directory paths | Stable |
| `rand` | Cryptographic RNG | Production |

### 6.3 Milestone Plan

**M1 — Core Crypto (Weeks 1-2)**
- `envkey init` — generate age identity, create `.envkey` file
- `envkey set KEY VALUE` — encrypt with age, store in YAML
- `envkey get KEY` — decrypt with age identity
- `envkey ls` — list keys (no decryption needed)
- Single user, single environment ("default")
- Goal: working encrypted secret storage for one person

**M2 — Team Management (Weeks 3-4)**
- `envkey member add NAME PUBKEY` — add team member, re-encrypt secrets
- `envkey member rm NAME` — remove member, re-encrypt secrets
- `envkey member ls` — list team members
- Role-based encryption (only encrypt to authorized members)
- Goal: two people can share secrets via git

**M3 — Environments (Weeks 5-6)**
- Multiple environments (default, production, staging, etc.)
- `-e ENV` flag on all commands
- Environment-specific team access (`envkey member grant NAME -e ENV`)
- CI role (access to specific environments only)
- Goal: production secrets separated from development secrets

**M4 — Injection Engine (Weeks 7-8)**
- `envkey run -- COMMAND` — decrypt + exec with env vars
- `envkey export` — emit as `.env` file or JSON
- `envkey export --format docker` — emit as Docker env format
- `envkey export --format k8s-secret` — emit as Kubernetes Secret YAML
- Secure memory handling (zeroize plaintext after exec)
- Goal: `envkey run -- npm start` is the primary developer workflow

**M5 — Rotation and Audit (Weeks 9-10)**
- `envkey rotate KEY` — rotate individual secret
- `envkey rotate --all` — rotate all encryption keys
- `envkey rotate --generate N` — auto-generate random secret
- `envkey diff` — show what changed (from git)
- `envkey log` — audit trail from git history
- Git merge driver for `.envkey` files
- Goal: complete secret lifecycle management

**M6 — Polish and Ship (Weeks 11-12)**
- Shell completions (bash, zsh, fish)
- `envkey verify` — validate `.envkey` file integrity (can all listed members decrypt?)
- `envkey doctor` — check setup (identity exists, .envkey valid, git configured)
- Man page and documentation
- Cross-platform CI builds
- Homebrew formula, cargo install, GitHub Releases
- Goal: v0.1.0 public release

---

## 7. Security Model

### 7.1 Threat Model

**What envkey protects against:**
- Secrets in plaintext in git repos
- Unauthorized access by non-team-members
- Secrets visible in CI logs (injected as env vars, not printed)
- Casual snooping (someone reading `.envkey` sees only encrypted blobs)
- Cloud provider access to secrets (everything encrypted at rest with keys only on developer machines)

**What envkey does NOT protect against:**
- A compromised developer machine (if your laptop is owned, your secrets are exposed)
- A malicious team admin (admins can decrypt everything by design)
- Memory forensics on running processes (secrets are in process memory during execution)
- Revoked members who already extracted secrets (re-encryption prevents future access, not retroactive access)
- Side-channel attacks on age encryption (age itself addresses this)

### 7.2 Security Properties

**Forward secrecy on member removal:** When a member is removed, all secrets they could access are re-encrypted with new data keys. Even if the removed member retained the `.envkey` file, they cannot decrypt the new ciphertexts.

**Minimum privilege:** CI keys are only added as recipients for their specific environments. A production CI key literally cannot decrypt staging secrets — the ciphertext doesn't contain a recipient stanza for that key.

**No secret in transit:** Secrets never leave the developer's machine in plaintext. The encrypted `.envkey` file travels through git. Decryption happens locally.

**Key material handling:**
- Private keys are stored with 0600 permissions
- Plaintext secrets are zeroized from memory after use (`secrecy` crate)
- `envkey run` uses `exec()` to replace the envkey process with the target command, so envkey itself exits and its memory is reclaimed

### 7.3 Comparison with Alternatives

| Property | envkey | SOPS | Vault | 1Password |
|----------|--------|------|-------|-----------|
| Zero infrastructure | Yes | Yes | No (server) | No (SaaS) |
| Team management | Built-in | Manual | Built-in | Built-in |
| Secret injection | `envkey run` | `sops exec-env` | `vault exec` | `op run` |
| Git-native | Yes | Yes | No | No |
| Rotation workflow | Built-in | Manual | Built-in | Manual |
| Offline capable | Yes | Partial* | No | No |
| Cost | Free | Free | Free/Paid | Paid |
| Audit trail | Git history | Git history | Built-in | Built-in |
| Setup time | 30 seconds | 15 minutes | Hours | Minutes |

*SOPS with age is offline-capable; SOPS with KMS requires cloud access.

---

## 8. Edge Cases and Design Decisions

### 8.1 What happens when two admins set the same secret simultaneously?

Git merge conflict on the `.envkey` file. Both changes appear in the YAML. The developer resolving the conflict chooses which value to keep, then runs `envkey set` to re-encrypt the winning value. The custom merge driver can detect this and prompt interactively.

### 8.2 What if a team member loses their private key?

They generate a new identity (`envkey init --force`), share the new public key with an admin, and the admin runs `envkey member update NAME NEW_PUBKEY`. All secrets are re-encrypted with the new key.

### 8.3 Can envkey work without git?

Yes. The `.envkey` file is just a file. Git provides audit trail and distribution, but envkey works with any file synchronization method (Dropbox, rsync, USB stick). Without git, you lose `envkey diff` and `envkey log`.

### 8.4 How large can the `.envkey` file get?

Each encrypted secret value is approximately `(plaintext_length + 200) * 1.37` bytes (age overhead + base64 encoding). A project with 50 secrets averaging 64 bytes each, encrypted for 10 team members, produces a `.envkey` file of approximately 100KB. This scales comfortably to hundreds of secrets.

### 8.5 Why not use SOPS format for compatibility?

SOPS format encrypts values in-place within existing YAML/JSON files. This is elegant for Kubernetes secrets but problematic for general secret management: (1) it couples secret structure to application config structure, (2) it doesn't support team membership as a first-class concept, (3) it doesn't support environments natively. envkey's custom format is designed for the team-secret-management use case specifically.

### 8.6 What about secret file (not just environment variable) injection?

Some secrets are files (TLS certificates, SSH keys, service account JSON). envkey supports this via:

```bash
# Store a file as a secret
envkey set --file TLS_CERT ./cert.pem

# Extract a file secret
envkey get --file TLS_CERT > cert.pem

# In envkey run, file secrets are written to a tmpfs
envkey run --file-secrets-dir /tmp/secrets -- ./myapp
# TLS_CERT env var = "/tmp/secrets/TLS_CERT"
# The file is cleaned up when myapp exits
```

---

## 9. Distribution and Adoption Strategy

### 9.1 Naming

"envkey" has a potential conflict with EnvKey Inc (envkey.com), a commercial secrets management SaaS. Alternative names to consider:

- **vlt** — short for "vault" but not HashiCorp's
- **sek** — short for "secrets"  
- **lockbox** — evocative, clear purpose
- **keyring** — familiar concept
- **agevault** — combines age + vault, clear lineage
- **enseal** — encrypt + seal

Recommendation: Proceed with `envkey` if the name is available; fall back to `lockbox` or `sek`.

### 9.2 Launch Strategy

1. **Blog post:** "I replaced Vault with a 5MB binary and a YAML file" — contrarian, technically detailed, targets HN/Reddit audience
2. **README-driven development:** The README is the product. It should show the complete workflow in 30 seconds of reading.
3. **Integration guides:** Day-one guides for GitHub Actions, GitLab CI, Docker Compose, Kubernetes, Terraform
4. **Migration tool:** `envkey import --from-env .env` and `envkey import --from-sops secrets.yaml` to lower migration friction

### 9.3 Success Metrics

**v0.1 (3 months):** 1,000 GitHub stars. Used by at least 10 open source projects. Blog post reaches HN front page.

**v0.5 (6 months):** 5,000 stars. GitHub Action published. Integration with at least one popular framework's documentation.

**v1.0 (12 months):** 10,000+ stars. Packaged in Homebrew core. Recognized as the standard "lightweight secrets management" tool for small-to-medium teams.

---

## 10. Open Design Questions

1. **Should envkey support cloud KMS backends (like SOPS does)?** Proposal: No in v1. The entire point is zero infrastructure. Users who need KMS should use SOPS. envkey's competitive advantage is simplicity, and adding KMS support adds configuration complexity.

2. **Should envkey support encrypting individual files (not just key-value pairs)?** Proposal: Yes, via `--file` flag (see 8.6). File secrets are common enough (TLS certs, SSH keys) to warrant first-class support.

3. **Should there be a web UI?** Proposal: No. envkey is a CLI tool. A web UI would require a server, which violates principle #1.

4. **Should envkey support secret templates?** (e.g., `DATABASE_URL = "postgres://${DB_USER}:${DB_PASS}@${DB_HOST}/${DB_NAME}"`) Proposal: Defer to v2. Template support is useful but adds complexity. In v1, store the full connection string as a single secret.

5. **Should envkey integrate with git hooks?** Proposal: Yes — provide a pre-commit hook that prevents committing decrypted secrets (scans for patterns like `AGE-SECRET-KEY-` and common secret formats in tracked files).
