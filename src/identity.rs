use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use age::x25519;

use crate::error::{EnvkeyError, Result};

#[derive(Clone)]
pub struct IdentityBundle {
    pub identity: x25519::Identity,
    pub recipient: x25519::Recipient,
    pub path: PathBuf,
}

pub fn detect_username() -> String {
    env::var("USER").or_else(|_| env::var("USERNAME")).unwrap_or_else(|_| "admin".to_string())
}

pub fn default_identity_path() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| EnvkeyError::message("could not determine home directory"))?;
    Ok(home.join(".envkey").join("identity.age"))
}

pub fn legacy_identity_path() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .ok_or_else(|| EnvkeyError::message("could not determine config directory"))?;
    Ok(base.join("envkey").join("identity.age"))
}

pub fn resolve_identity_path(cli_override: Option<&Path>) -> Result<PathBuf> {
    let override_path = cli_override
        .map(Path::to_path_buf)
        .or_else(|| env::var("ENVKEY_IDENTITY").ok().map(PathBuf::from));
    resolve_identity_path_with(override_path)
}

pub fn expand_home_prefix(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if path_str == "~" {
        return dirs::home_dir()
            .ok_or_else(|| EnvkeyError::message("could not determine home directory"));
    }
    if let Some(rest) = path_str.strip_prefix("~/").or_else(|| path_str.strip_prefix("~\\")) {
        let home = dirs::home_dir()
            .ok_or_else(|| EnvkeyError::message("could not determine home directory"))?;
        return Ok(home.join(rest));
    }
    Ok(path.to_path_buf())
}

fn resolve_identity_path_with(override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return expand_home_prefix(&path);
    }

    let default = default_identity_path()?;
    if identity_exists(&default) {
        return Ok(default);
    }

    let legacy = legacy_identity_path()?;
    if identity_exists(&legacy) {
        return Ok(legacy);
    }

    Ok(default)
}

pub fn identity_exists(path: &Path) -> bool {
    path.is_file()
}

pub fn generate_identity_at(path: &Path) -> Result<IdentityBundle> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let identity = x25519::Identity::generate();
    let secret = identity.to_string();

    let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
    file.write_all(secret.expose_secret().as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    load_identity_from(path)
}

pub fn load_identity_from(path: &Path) -> Result<IdentityBundle> {
    let raw = fs::read_to_string(path).map_err(|err| {
        EnvkeyError::message(format!("failed to read identity at {}: {err}", path.display()))
    })?;
    let key = raw.trim();
    if key.is_empty() {
        return Err(EnvkeyError::message(format!("identity file {} is empty", path.display())));
    }

    let identity = x25519::Identity::from_str(key).map_err(|err| {
        EnvkeyError::message(format!("invalid identity in {}: {err}", path.display()))
    })?;
    let recipient = identity.to_public();

    Ok(IdentityBundle { identity, recipient, path: path.to_path_buf() })
}

pub fn load_or_generate_identity(path: &Path, force: bool) -> Result<(IdentityBundle, bool)> {
    if force || !identity_exists(path) {
        return Ok((generate_identity_at(path)?, true));
    }

    Ok((load_identity_from(path)?, false))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn generate_and_load_identity() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("identity.age");

        let generated = generate_identity_at(&path).expect("generate");
        assert!(generated.recipient.to_string().starts_with("age1"));

        let loaded = load_identity_from(&path).expect("load");
        assert_eq!(generated.recipient.to_string(), loaded.recipient.to_string());
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_permissions_are_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("identity.age");

        generate_identity_at(&path).expect("generate");

        let metadata = fs::metadata(path).expect("metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn default_and_legacy_paths_match_expected_suffixes() {
        let default = default_identity_path().expect("default path");
        assert!(default.ends_with(PathBuf::from(".envkey").join("identity.age")));

        let legacy = legacy_identity_path().expect("legacy path");
        assert!(legacy.ends_with(PathBuf::from("envkey").join("identity.age")));
    }

    #[test]
    fn resolve_identity_path_prefers_cli_override() {
        let custom = PathBuf::from("/tmp/custom.age");
        let resolved = resolve_identity_path_with(Some(custom.clone())).expect("resolved");
        assert_eq!(resolved, custom);
    }

    #[test]
    fn expands_tilde_paths() {
        let expanded = expand_home_prefix(Path::new("~/identity.age")).expect("expanded");
        let home = dirs::home_dir().expect("home");
        assert_eq!(expanded, home.join("identity.age"));
    }
}
