use std::env;
use std::str::FromStr;

use age::x25519;
use chrono::{SecondsFormat, Utc};
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};

use crate::crypto::{decrypt_value, encrypt_value};
use crate::error::{EnvkeyError, Result};
use crate::identity::{
    detect_username, identity_path, load_identity_from, load_or_generate_identity,
};
use crate::model::{EnvkeyFile, SecretEntry, TeamMember};
use crate::storage::{envkey_path, read_envkey, write_envkey_atomic};

#[derive(Debug, Parser)]
#[command(name = "envkey", version, about = "Secrets without servers")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a local age identity and initialize .envkey
    Init {
        /// Force identity regeneration (blocked if .envkey already exists)
        #[arg(long)]
        force: bool,
    },
    /// Encrypt and store a secret key/value pair
    Set {
        #[arg(short = 'e', long = "env", default_value = "default")]
        env: String,
        key: String,
        value: String,
    },
    /// Decrypt and print a secret value
    Get {
        #[arg(short = 'e', long = "env", default_value = "default")]
        env: String,
        key: String,
    },
    /// List secret keys and metadata
    Ls {
        #[arg(short = 'e', long = "env", default_value = "default")]
        env: String,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { force } => cmd_init(force),
        Commands::Set { env, key, value } => cmd_set(&env, &key, value),
        Commands::Get { env, key } => cmd_get(&env, &key),
        Commands::Ls { env } => cmd_ls(&env),
    }
}

fn cmd_init(force: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let envkey_path = envkey_path(&cwd);

    if force && envkey_path.exists() {
        return Err(EnvkeyError::message(
            "--force is blocked when .envkey already exists; remove .envkey first in M1",
        ));
    }

    let identity_path = identity_path()?;
    let (bundle, generated_identity) = load_or_generate_identity(&identity_path, force)?;
    let username = detect_username();

    if generated_identity {
        println!("✓ Generated identity key at {}", bundle.path.display());
    } else {
        println!("✓ Using existing identity key at {}", bundle.path.display());
    }

    if envkey_path.exists() {
        let mut file = read_envkey(&envkey_path)?;
        if !file.team.contains_key(&username) {
            file.team.insert(
                username.clone(),
                TeamMember {
                    pubkey: bundle.recipient.to_string(),
                    role: crate::model::Role::Admin,
                    added: now_date(),
                    environments: None,
                },
            );
            write_envkey_atomic(&envkey_path, &file)?;
            println!("✓ Added {username} as admin in existing .envkey");
        } else {
            println!("✓ .envkey already exists");
        }
    } else {
        let file = EnvkeyFile::new(username.clone(), bundle.recipient.to_string(), now_date());
        write_envkey_atomic(&envkey_path, &file)?;
        println!("✓ Created .envkey with you as admin");
    }

    println!("✓ Public key: {}", bundle.recipient);
    Ok(())
}

fn cmd_set(env_name: &str, key: &str, value: String) -> Result<()> {
    require_m1_env(env_name)?;
    validate_secret_key(key)?;

    let cwd = env::current_dir()?;
    let envkey_path = envkey_path(&cwd);
    if !envkey_path.exists() {
        return Err(EnvkeyError::message(
            "missing .envkey in current directory; run `envkey init` first",
        ));
    }

    let mut file = read_envkey(&envkey_path)?;
    let identity_bundle = load_identity_from(&identity_path()?)?;

    let recipients = parse_recipients_from_team(&file)?;
    if recipients.is_empty() {
        return Err(EnvkeyError::message("no team recipients found in .envkey; cannot encrypt"));
    }

    let secret: SecretString = value.into();
    let encrypted = encrypt_value(secret.expose_secret(), &recipients)?;

    let set_by = detect_username();
    file.default_env_mut().insert(
        key.to_string(),
        SecretEntry { value: encrypted, set_by, modified: now_timestamp() },
    );

    write_envkey_atomic(&envkey_path, &file)?;

    // Fast-fail if the current identity cannot decrypt what we just wrote.
    let written = file
        .default_env()
        .and_then(|env| env.get(key))
        .ok_or_else(|| EnvkeyError::message("internal error: secret missing after write"))?;
    let _ = decrypt_value(&written.value, &identity_bundle.identity)?;

    println!(
        "✓ Encrypted {} for {} recipient{} ({})",
        key,
        recipients.len(),
        if recipients.len() == 1 { "" } else { "s" },
        env_name
    );

    Ok(())
}

fn cmd_get(env_name: &str, key: &str) -> Result<()> {
    require_m1_env(env_name)?;

    let cwd = env::current_dir()?;
    let envkey_path = envkey_path(&cwd);
    if !envkey_path.exists() {
        return Err(EnvkeyError::message(
            "missing .envkey in current directory; run `envkey init` first",
        ));
    }

    let file = read_envkey(&envkey_path)?;
    let identity = load_identity_from(&identity_path()?)?;

    let env = file
        .default_env()
        .ok_or_else(|| EnvkeyError::message("default environment not found in .envkey"))?;
    let entry =
        env.get(key).ok_or_else(|| EnvkeyError::message(format!("secret key not found: {key}")))?;

    let plaintext = decrypt_value(&entry.value, &identity.identity)?;
    println!("{plaintext}");
    Ok(())
}

fn cmd_ls(env_name: &str) -> Result<()> {
    require_m1_env(env_name)?;

    let cwd = env::current_dir()?;
    let envkey_path = envkey_path(&cwd);
    if !envkey_path.exists() {
        return Err(EnvkeyError::message(
            "missing .envkey in current directory; run `envkey init` first",
        ));
    }

    let file = read_envkey(&envkey_path)?;
    let Some(env) = file.default_env() else {
        println!("ENVIRONMENT  KEY  SET_BY  MODIFIED");
        return Ok(());
    };

    let mut rows: Vec<(String, String, String, String)> = env
        .iter()
        .map(|(key, entry)| {
            ("default".to_string(), key.clone(), entry.set_by.clone(), entry.modified.clone())
        })
        .collect();

    rows.sort_by(|a, b| a.1.cmp(&b.1));

    let env_w = rows
        .iter()
        .map(|row| row.0.len())
        .max()
        .unwrap_or("ENVIRONMENT".len())
        .max("ENVIRONMENT".len());
    let key_w = rows.iter().map(|row| row.1.len()).max().unwrap_or("KEY".len()).max("KEY".len());
    let set_by_w =
        rows.iter().map(|row| row.2.len()).max().unwrap_or("SET_BY".len()).max("SET_BY".len());

    println!("{:<env_w$}  {:<key_w$}  {:<set_by_w$}  MODIFIED", "ENVIRONMENT", "KEY", "SET_BY");

    for (env_name, key, set_by, modified) in rows {
        println!("{:<env_w$}  {:<key_w$}  {:<set_by_w$}  {}", env_name, key, set_by, modified);
    }

    Ok(())
}

fn parse_recipients_from_team(file: &EnvkeyFile) -> Result<Vec<x25519::Recipient>> {
    file.team
        .values()
        .map(|member| {
            x25519::Recipient::from_str(&member.pubkey).map_err(|err| {
                EnvkeyError::message(format!("invalid team public key {}: {err}", member.pubkey))
            })
        })
        .collect()
}

fn validate_secret_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(EnvkeyError::message("secret key cannot be empty"));
    }

    let mut chars = key.chars();
    let first = chars.next().ok_or_else(|| EnvkeyError::message("secret key cannot be empty"))?;
    if !(first == '_' || first.is_ascii_uppercase()) {
        return Err(EnvkeyError::message(format!(
            "invalid secret key `{key}`: must start with A-Z or _"
        )));
    }

    if !chars.all(|c| c == '_' || c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return Err(EnvkeyError::message(format!(
            "invalid secret key `{key}`: use only A-Z, 0-9, _"
        )));
    }

    Ok(())
}

fn require_m1_env(env_name: &str) -> Result<()> {
    if env_name != "default" {
        return Err(EnvkeyError::message(format!(
            "M1 supports only default environment; got `{env_name}`"
        )));
    }
    Ok(())
}

fn now_date() -> String {
    Utc::now().date_naive().to_string()
}

fn now_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_secret_key_rules() {
        assert!(validate_secret_key("DATABASE_URL").is_ok());
        assert!(validate_secret_key("_TOKEN_1").is_ok());

        assert!(validate_secret_key("database_url").is_err());
        assert!(validate_secret_key("1DATABASE").is_err());
        assert!(validate_secret_key("API-KEY").is_err());
    }

    #[test]
    fn non_default_env_is_rejected() {
        let err = require_m1_env("production").expect_err("must fail");
        assert!(err.to_string().contains("M1 supports only default environment"));
    }
}
