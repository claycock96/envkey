use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{EnvkeyError, Result};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvkeyFile {
    pub version: u32,
    #[serde(default)]
    pub team: BTreeMap<String, TeamMember>,
    #[serde(default)]
    pub environments: BTreeMap<String, BTreeMap<String, SecretEntry>>,
}

impl EnvkeyFile {
    pub fn new(owner_name: String, owner_pubkey: String, now_date: String) -> Self {
        let mut team = BTreeMap::new();
        team.insert(
            owner_name,
            TeamMember {
                pubkey: owner_pubkey,
                role: Role::Admin,
                added: now_date,
                environments: None,
            },
        );

        let mut environments = BTreeMap::new();
        environments.insert("default".to_string(), BTreeMap::new());

        Self { version: FORMAT_VERSION, team, environments }
    }

    pub fn ensure_supported_version(&self) -> Result<()> {
        if self.version != FORMAT_VERSION {
            return Err(EnvkeyError::message(format!(
                "unsupported .envkey version: {} (supported: {})",
                self.version, FORMAT_VERSION
            )));
        }
        Ok(())
    }

    pub fn default_env_mut(&mut self) -> &mut BTreeMap<String, SecretEntry> {
        self.environments.entry("default".to_string()).or_default()
    }

    pub fn default_env(&self) -> Option<&BTreeMap<String, SecretEntry>> {
        self.environments.get("default")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    pub pubkey: String,
    pub role: Role,
    pub added: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environments: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Member,
    Ci,
    Readonly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub value: String,
    pub set_by: String,
    pub modified: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_yaml() {
        let mut file = EnvkeyFile::new(
            "alice".to_string(),
            "age1example".to_string(),
            "2026-02-26".to_string(),
        );
        file.default_env_mut().insert(
            "API_KEY".to_string(),
            SecretEntry {
                value: "encrypted".to_string(),
                set_by: "alice".to_string(),
                modified: "2026-02-26T00:00:00Z".to_string(),
            },
        );

        let yaml = serde_yaml::to_string(&file).expect("serialize");
        let parsed: EnvkeyFile = serde_yaml::from_str(&yaml).expect("deserialize");

        assert_eq!(parsed.version, FORMAT_VERSION);
        assert!(parsed.team.contains_key("alice"));
        assert!(parsed.default_env().expect("default env").contains_key("API_KEY"));
    }

    #[test]
    fn version_guard_rejects_unknown_version() {
        let file = EnvkeyFile { version: 99, team: BTreeMap::new(), environments: BTreeMap::new() };

        let err = file.ensure_supported_version().expect_err("must fail");
        assert!(err.to_string().contains("unsupported .envkey version: 99"));
    }
}
