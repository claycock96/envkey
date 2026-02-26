use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use age::secrecy::ExposeSecret;
use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::TempDir;

use envkey::model::EnvkeyFile;

fn identity_path(temp: &TempDir) -> PathBuf {
    temp.path().join("identity.age")
}

fn cmd_in(temp: &TempDir) -> Command {
    let mut cmd = cargo_bin_cmd!("envkey");
    cmd.current_dir(temp.path()).env("ENVKEY_IDENTITY", identity_path(temp)).env("USER", "alice");
    cmd
}

fn cmd_no_identity(temp: &TempDir, home: &Path, user: &str) -> Command {
    let mut cmd = cargo_bin_cmd!("envkey");
    cmd.current_dir(temp.path()).env_remove("ENVKEY_IDENTITY").env("HOME", home).env("USER", user);
    cmd
}

fn cmd_with_global_identity(temp: &TempDir, identity: &Path, user: &str) -> Command {
    let mut cmd = cargo_bin_cmd!("envkey");
    cmd.current_dir(temp.path()).env("USER", user).arg("--identity").arg(identity);
    cmd
}

fn read_envkey(temp: &TempDir) -> EnvkeyFile {
    let content = fs::read_to_string(temp.path().join(".envkey")).expect("read .envkey");
    serde_yaml::from_str(&content).expect("valid yaml")
}

fn write_envkey(temp: &TempDir, file: &EnvkeyFile) {
    let yaml = serde_yaml::to_string(file).expect("serialize");
    fs::write(temp.path().join(".envkey"), yaml).expect("write .envkey");
}

fn run_init(temp: &TempDir) {
    cmd_in(temp).args(["init"]).assert().success();
}

#[test]
fn init_creates_identity_and_envkey() {
    let temp = tempfile::tempdir().expect("tempdir");

    cmd_in(&temp)
        .args(["init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated identity key"))
        .stdout(predicate::str::contains("Created .envkey with you as admin"))
        .stdout(predicate::str::contains("Public key: age1"));

    assert!(identity_path(&temp).exists());

    let envkey_content = fs::read_to_string(temp.path().join(".envkey")).expect("read .envkey");
    assert!(envkey_content.contains("version: 1"));
    assert!(envkey_content.contains("default"));
}

#[test]
fn init_is_idempotent() {
    let temp = tempfile::tempdir().expect("tempdir");

    run_init(&temp);

    cmd_in(&temp)
        .args(["init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Using existing identity key"))
        .stdout(predicate::str::contains(".envkey already exists"));
}

#[test]
fn init_without_override_uses_home_dot_envkey_identity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    fs::create_dir_all(&home).expect("mkdir home");

    cmd_no_identity(&temp, &home, "alice").args(["init"]).assert().success();

    assert!(home.join(".envkey").join("identity.age").exists());
}

#[test]
fn init_global_identity_flag_creates_identity_at_exact_location() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    fs::create_dir_all(&home).expect("mkdir home");

    let custom = temp.path().join("ids").join("alice.age");
    cmd_no_identity(&temp, &home, "alice")
        .arg("--identity")
        .arg(&custom)
        .arg("init")
        .assert()
        .success();

    assert!(custom.exists());
    assert!(!home.join(".envkey").join("identity.age").exists());
}

#[test]
fn init_global_identity_rejects_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    fs::create_dir_all(&home).expect("mkdir home");
    let identity_dir = temp.path().join("ids");
    fs::create_dir_all(&identity_dir).expect("mkdir ids");

    cmd_no_identity(&temp, &home, "alice")
        .arg("--identity")
        .arg(&identity_dir)
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("identity path must be a file path, got directory"));
}

#[test]
fn init_prompt_expands_tilde_path_input() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    fs::create_dir_all(&home).expect("mkdir home");
    let expected = home.join(".envkey2").join("identity.age");

    cmd_no_identity(&temp, &home, "alice")
        .env("ENVKEY_INIT_PROMPT", "1")
        .args(["init"])
        .write_stdin("~/.envkey2/identity.age\n")
        .assert()
        .success();

    assert!(expected.exists());
}

#[test]
fn non_init_commands_fallback_to_legacy_identity_path() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    fs::create_dir_all(&home).expect("mkdir home");
    let legacy = legacy_identity_path_for_home(&home);
    fs::create_dir_all(legacy.parent().expect("legacy parent")).expect("mkdir legacy parent");

    cmd_no_identity(&temp, &home, "alice")
        .env("ENVKEY_IDENTITY", &legacy)
        .args(["init"])
        .assert()
        .success();
    cmd_no_identity(&temp, &home, "alice")
        .env("ENVKEY_IDENTITY", &legacy)
        .args(["set", "API_KEY", "legacy-secret"])
        .assert()
        .success();

    assert!(!home.join(".envkey").join("identity.age").exists());
    assert!(legacy.exists());

    cmd_no_identity(&temp, &home, "alice")
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("legacy-secret\n");
}

fn legacy_identity_path_for_home(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library").join("Application Support").join("envkey").join("identity.age")
    }

    #[cfg(not(target_os = "macos"))]
    {
        home.join(".config").join("envkey").join("identity.age")
    }
}

#[test]
fn global_identity_flag_overrides_envkey_identity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let good_identity = temp.path().join("good.age");
    let bad_identity = temp.path().join("bad.age");

    let good = age::x25519::Identity::generate().to_string();
    let bad = age::x25519::Identity::generate().to_string();
    fs::write(&good_identity, format!("{}\n", good.expose_secret())).expect("write good key");
    fs::write(&bad_identity, format!("{}\n", bad.expose_secret())).expect("write bad key");

    cmd_with_global_identity(&temp, &good_identity, "alice").args(["init"]).assert().success();
    cmd_with_global_identity(&temp, &good_identity, "alice")
        .args(["set", "API_KEY", "flag-wins"])
        .assert()
        .success();

    let mut cmd = cargo_bin_cmd!("envkey");
    cmd.current_dir(temp.path())
        .env("USER", "alice")
        .env("ENVKEY_IDENTITY", &bad_identity)
        .arg("--identity")
        .arg(&good_identity)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("flag-wins\n");
}

#[test]
fn set_get_round_trip_and_plaintext_not_written() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    let plaintext = "postgres://user:pass@localhost:5432/app";

    cmd_in(&temp).args(["set", "DATABASE_URL", plaintext]).assert().success();

    let envkey_content = fs::read_to_string(temp.path().join(".envkey")).expect("read .envkey");
    assert!(!envkey_content.contains(plaintext));

    cmd_in(&temp).args(["get", "DATABASE_URL"]).assert().success().stdout(format!("{plaintext}\n"));
}

#[test]
fn set_existing_key_updates_ciphertext_and_timestamp() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp).args(["set", "API_KEY", "first-value"]).assert().success();

    let before = read_envkey(&temp);
    let before_entry =
        before.default_env().expect("default env").get("API_KEY").expect("api key").clone();

    thread::sleep(Duration::from_secs(1));

    cmd_in(&temp).args(["set", "API_KEY", "second-value"]).assert().success();

    let after = read_envkey(&temp);
    let after_entry =
        after.default_env().expect("default env").get("API_KEY").expect("api key").clone();

    assert_ne!(before_entry.value, after_entry.value);
    assert_ne!(before_entry.modified, after_entry.modified);
}

#[test]
fn ls_lists_keys_without_values() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp).args(["set", "API_KEY", "super-secret"]).assert().success();

    cmd_in(&temp)
        .args(["ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ENVIRONMENT"))
        .stdout(predicate::str::contains("API_KEY"))
        .stdout(predicate::str::contains("super-secret").not());
}

#[test]
fn get_missing_key_returns_non_zero() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp)
        .args(["get", "MISSING_KEY"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("secret key not found: MISSING_KEY"));
}

#[test]
fn get_with_wrong_identity_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp).args(["set", "API_KEY", "secret"]).assert().success();

    let wrong_identity = temp.path().join("wrong-identity.age");
    let wrong = age::x25519::Identity::generate().to_string();
    fs::write(&wrong_identity, format!("{}\n", wrong.expose_secret())).expect("write wrong key");

    let mut cmd = cargo_bin_cmd!("envkey");
    cmd.current_dir(temp.path())
        .env("ENVKEY_IDENTITY", wrong_identity)
        .env("USER", "alice")
        .args(["get", "API_KEY"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to decrypt value"));
}

#[test]
fn malformed_yaml_returns_actionable_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    fs::write(temp.path().join(".envkey"), "not: [valid").expect("write malformed");

    cmd_in(&temp)
        .args(["ls"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid .envkey YAML"));
}

#[test]
fn unsupported_version_returns_actionable_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    fs::write(temp.path().join(".envkey"), "version: 2\nteam: {}\nenvironments: {}\n")
        .expect("write version 2");

    cmd_in(&temp)
        .args(["ls"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported .envkey version: 2"));
}

#[test]
fn corrupted_ciphertext_returns_actionable_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp).args(["set", "API_KEY", "secret"]).assert().success();

    let mut file = read_envkey(&temp);
    let entry = file.default_env_mut().get_mut("API_KEY").expect("api key exists");
    entry.value = "not-base64***".to_string();
    write_envkey(&temp, &file);

    cmd_in(&temp)
        .args(["get", "API_KEY"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ciphertext is not valid base64"));
}

#[test]
fn non_default_environment_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp)
        .args(["set", "-e", "production", "API_KEY", "secret"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("M1 supports only default environment; got `production`"));
}

#[test]
fn init_force_is_blocked_when_envkey_exists() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp)
        .args(["init", "--force"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force is blocked when .envkey already exists"));
}
