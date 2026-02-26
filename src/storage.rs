use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use rand::distr::Alphanumeric;
use rand::{Rng, rng};

use crate::error::{EnvkeyError, Result};
use crate::model::EnvkeyFile;

pub const ENVKEY_FILE_NAME: &str = ".envkey";

pub fn envkey_path(cwd: &Path) -> PathBuf {
    cwd.join(ENVKEY_FILE_NAME)
}

pub fn read_envkey(path: &Path) -> Result<EnvkeyFile> {
    let raw = fs::read_to_string(path)
        .map_err(|err| EnvkeyError::message(format!("failed to read {}: {err}", path.display())))?;
    let file: EnvkeyFile = serde_yaml::from_str(&raw).map_err(|err| {
        EnvkeyError::message(format!("invalid .envkey YAML in {}: {err}", path.display()))
    })?;
    file.ensure_supported_version()?;
    Ok(file)
}

pub fn write_envkey_atomic(path: &Path, file: &EnvkeyFile) -> Result<()> {
    let yaml = serde_yaml::to_string(file)
        .map_err(|err| EnvkeyError::message(format!("failed to serialize .envkey: {err}")))?;

    let parent = path
        .parent()
        .ok_or_else(|| EnvkeyError::message(".envkey path has no parent directory"))?;
    fs::create_dir_all(parent)?;

    let suffix: String = rng().sample_iter(Alphanumeric).map(char::from).take(8).collect();
    let tmp = parent.join(format!("{}.tmp.{}", ENVKEY_FILE_NAME, suffix));

    fs::write(&tmp, yaml.as_bytes()).map_err(|err| {
        EnvkeyError::message(format!("failed to write temporary file {}: {err}", tmp.display()))
    })?;

    fs::rename(&tmp, path).map_err(|err| {
        let _ = fs::remove_file(&tmp);
        EnvkeyError::message(format!("failed to replace {} atomically: {err}", path.display()))
    })?;

    Ok(())
}

pub fn with_envkey_lock<T>(path: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    let parent = path
        .parent()
        .ok_or_else(|| EnvkeyError::message(".envkey path has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let lock_path = parent.join(format!("{ENVKEY_FILE_NAME}.lock"));

    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| {
            EnvkeyError::message(format!("failed to open lock file {}: {err}", lock_path.display()))
        })?;
    lock_file.lock_exclusive().map_err(|err| {
        EnvkeyError::message(format!("failed to acquire lock {}: {err}", lock_path.display()))
    })?;

    action()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::tempdir;

    use crate::model::{SecretEntry, TeamMember};

    use super::*;

    #[test]
    fn write_and_read_round_trip() {
        let temp = tempdir().expect("tempdir");
        let path = envkey_path(temp.path());

        let mut file =
            EnvkeyFile { version: 1, team: BTreeMap::new(), environments: BTreeMap::new() };
        file.team.insert(
            "alice".to_string(),
            TeamMember {
                pubkey: "age1example".to_string(),
                role: crate::model::Role::Admin,
                added: "2026-02-26".to_string(),
                environments: None,
            },
        );
        file.default_env_mut().insert(
            "API_KEY".to_string(),
            SecretEntry {
                value: "encrypted".to_string(),
                set_by: "alice".to_string(),
                modified: "2026-02-26T00:00:00Z".to_string(),
            },
        );

        write_envkey_atomic(&path, &file).expect("write");
        let loaded = read_envkey(&path).expect("read");

        assert!(loaded.team.contains_key("alice"));
        assert!(loaded.default_env().expect("default env").contains_key("API_KEY"));
    }

    #[test]
    fn malformed_yaml_returns_actionable_error() {
        let temp = tempdir().expect("tempdir");
        let path = envkey_path(temp.path());
        fs::write(&path, "not: [valid").expect("write");

        let err = read_envkey(&path).expect_err("must fail");
        assert!(err.to_string().contains("invalid .envkey YAML"));
    }
}
