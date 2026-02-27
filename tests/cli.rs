use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use age::secrecy::ExposeSecret;
use age::x25519;
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

fn cmd_in_with_identity(temp: &TempDir, identity: &Path, user: &str) -> Command {
    let mut cmd = cargo_bin_cmd!("envkey");
    cmd.current_dir(temp.path()).env("ENVKEY_IDENTITY", identity).env("USER", user);
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

fn generate_identity_file(path: &Path) -> String {
    let identity = x25519::Identity::generate();
    fs::write(path, format!("{}\n", identity.to_string().expose_secret())).expect("write identity");
    identity.to_public().to_string()
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
fn init_on_existing_envkey_does_not_add_new_admin_by_username() {
    let temp = tempfile::tempdir().expect("tempdir");
    let alice_identity = temp.path().join("alice.age");
    let bob_identity = temp.path().join("bob.age");

    cmd_with_global_identity(&temp, &alice_identity, "alice").args(["init"]).assert().success();
    cmd_with_global_identity(&temp, &bob_identity, "bob")
        .args(["init"])
        .assert()
        .success()
        .stdout(predicate::str::contains(".envkey already exists"));

    let file = read_envkey(&temp);
    assert!(file.team.contains_key("alice"));
    assert!(!file.team.contains_key("bob"));
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
    let legacy = legacy_identity_path_for_test(&home, &temp);
    fs::create_dir_all(legacy.parent().expect("legacy parent")).expect("mkdir legacy parent");

    let mut init_cmd = cmd_no_identity(&temp, &home, "alice");
    #[cfg(not(target_os = "macos"))]
    {
        init_cmd.env("XDG_CONFIG_HOME", temp.path().join("xdg"));
    }
    init_cmd.env("ENVKEY_IDENTITY", &legacy).args(["init"]).assert().success();

    let mut set_cmd = cmd_no_identity(&temp, &home, "alice");
    #[cfg(not(target_os = "macos"))]
    {
        set_cmd.env("XDG_CONFIG_HOME", temp.path().join("xdg"));
    }
    set_cmd
        .env("ENVKEY_IDENTITY", &legacy)
        .args(["set", "API_KEY", "legacy-secret"])
        .assert()
        .success();

    assert!(!home.join(".envkey").join("identity.age").exists());
    assert!(legacy.exists());

    let mut get_cmd = cmd_no_identity(&temp, &home, "alice");
    #[cfg(not(target_os = "macos"))]
    {
        get_cmd.env("XDG_CONFIG_HOME", temp.path().join("xdg"));
    }
    get_cmd.args(["get", "API_KEY"]).assert().success().stdout("legacy-secret\n");
}

fn legacy_identity_path_for_test(_home: &Path, _temp: &TempDir) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        _home.join("Library").join("Application Support").join("envkey").join("identity.age")
    }

    #[cfg(not(target_os = "macos"))]
    {
        _temp.path().join("xdg").join("envkey").join("identity.age")
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

#[test]
fn member_add_success_and_default_role() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    cmd_in(&temp).args(["set", "API_KEY", "secret"]).assert().success();

    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);

    let before = read_envkey(&temp);
    let before_value =
        before.default_env().expect("default env").get("API_KEY").expect("api key").value.clone();

    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();

    let after = read_envkey(&temp);
    let bob = after.team.get("bob").expect("bob exists");
    assert_eq!(bob.role, envkey::model::Role::Member);

    let after_value =
        after.default_env().expect("default env").get("API_KEY").expect("api key").value.clone();
    assert_ne!(before_value, after_value);

    cmd_in(&temp).args(["get", "API_KEY"]).assert().success().stdout("secret\n");
}

#[test]
fn member_add_supports_all_roles() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    let cases = [
        ("admin", "amy", envkey::model::Role::Admin),
        ("ci", "ci-prod", envkey::model::Role::Ci),
        ("readonly", "rob", envkey::model::Role::Readonly),
    ];

    for (role_arg, name, expected_role) in cases {
        let identity = temp.path().join(format!("{name}.age"));
        let pubkey = generate_identity_file(&identity);
        cmd_in(&temp).args(["member", "add", name, &pubkey, "--role", role_arg]).assert().success();

        let file = read_envkey(&temp);
        assert_eq!(file.team.get(name).expect("member exists").role, expected_role);
    }
}

#[test]
fn member_add_duplicate_name_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);

    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();
    cmd_in(&temp)
        .args(["member", "add", "bob", &bob_pubkey])
        .assert()
        .failure()
        .stderr(predicate::str::contains("team member already exists: bob"));
}

#[test]
fn member_add_invalid_pubkey_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp)
        .args(["member", "add", "bob", "not-a-valid-pubkey"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid age public key for bob"));
}

#[test]
fn member_add_requires_admin_identity() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    let non_admin_identity = temp.path().join("non-admin.age");
    let _ = generate_identity_file(&non_admin_identity);

    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);

    cmd_in_with_identity(&temp, &non_admin_identity, "notadmin")
        .args(["member", "add", "bob", &bob_pubkey])
        .assert()
        .failure()
        .stderr(predicate::str::contains("current identity is not an admin in .envkey"));
}

#[test]
fn member_add_ci_without_pubkey_generates_keypair_and_prints_private_key() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    cmd_in(&temp).args(["set", "API_KEY", "secret"]).assert().success();

    cmd_in(&temp)
        .args(["member", "add", "ci-prod", "--role", "ci"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated CI key pair"))
        .stdout(predicate::str::contains("ENVKEY_IDENTITY"))
        .stdout(predicate::str::contains("AGE-SECRET-KEY-"));

    let file = read_envkey(&temp);
    let ci = file.team.get("ci-prod").expect("ci member exists");
    assert_eq!(ci.role, envkey::model::Role::Ci);
    assert!(ci.pubkey.starts_with("age1"));
}

#[test]
fn member_add_non_ci_without_pubkey_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp)
        .args(["member", "add", "alice2", "--role", "member"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("public key is required unless --role ci is used"));
}

#[test]
fn member_add_ci_with_pubkey_still_supported() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    let ci_identity = temp.path().join("ci.age");
    let ci_pubkey = generate_identity_file(&ci_identity);

    cmd_in(&temp)
        .args(["member", "add", "ci-prod", &ci_pubkey, "--role", "ci"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added ci-prod (ci)"))
        .stdout(predicate::str::contains("Generated CI key pair").not());
}

#[test]
fn member_update_success_reencrypts_and_new_key_decrypts() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    cmd_in(&temp).args(["set", "API_KEY", "secret"]).assert().success();

    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);
    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();
    cmd_in_with_identity(&temp, &bob_identity, "bob")
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("secret\n");

    let before = read_envkey(&temp);
    let before_value =
        before.default_env().expect("default env").get("API_KEY").expect("api key").value.clone();

    let bob_new_identity = temp.path().join("bob-new.age");
    let bob_new_pubkey = generate_identity_file(&bob_new_identity);
    cmd_in(&temp).args(["member", "update", "bob", &bob_new_pubkey]).assert().success();

    let after = read_envkey(&temp);
    let after_value =
        after.default_env().expect("default env").get("API_KEY").expect("api key").value.clone();
    assert_ne!(before_value, after_value);

    cmd_in_with_identity(&temp, &bob_identity, "bob")
        .args(["get", "API_KEY"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to decrypt value"));
    cmd_in_with_identity(&temp, &bob_new_identity, "bob")
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("secret\n");
}

#[test]
fn member_update_unknown_member_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    let some_pubkey = generate_identity_file(&temp.path().join("some.age"));

    cmd_in(&temp)
        .args(["member", "update", "missing", &some_pubkey])
        .assert()
        .failure()
        .stderr(predicate::str::contains("team member not found: missing"));
}

#[test]
fn member_update_invalid_pubkey_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp)
        .args(["member", "update", "alice", "not-a-valid-pubkey"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid age public key for alice"));
}

#[test]
fn member_update_non_admin_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);
    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();

    let non_admin_identity = temp.path().join("non-admin.age");
    let _ = generate_identity_file(&non_admin_identity);
    let replacement_pubkey = generate_identity_file(&temp.path().join("replacement.age"));

    cmd_in_with_identity(&temp, &non_admin_identity, "notadmin")
        .args(["member", "update", "bob", &replacement_pubkey])
        .assert()
        .failure()
        .stderr(predicate::str::contains("current identity is not an admin in .envkey"));
}

#[test]
fn member_update_same_pubkey_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);
    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();

    cmd_in(&temp)
        .args(["member", "update", "bob", &bob_pubkey])
        .assert()
        .failure()
        .stderr(predicate::str::contains("new public key matches existing key for bob"));
}

#[test]
fn member_update_self_admin_blocked() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    let replacement_pubkey = generate_identity_file(&temp.path().join("alice-new.age"));

    cmd_in(&temp)
        .args(["member", "update", "alice", &replacement_pubkey])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "cannot update your own admin identity in M2; add a new admin first",
        ));
}

#[test]
fn member_role_set_success_updates_role_and_reencrypts() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    cmd_in(&temp).args(["set", "API_KEY", "secret"]).assert().success();

    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);
    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();

    let before = read_envkey(&temp);
    let before_value =
        before.default_env().expect("default env").get("API_KEY").expect("api key").value.clone();

    cmd_in(&temp).args(["member", "role", "set", "bob", "readonly"]).assert().success();

    let after = read_envkey(&temp);
    assert_eq!(after.team.get("bob").expect("bob exists").role, envkey::model::Role::Readonly);
    let after_value =
        after.default_env().expect("default env").get("API_KEY").expect("api key").value.clone();
    assert_ne!(before_value, after_value);
}

#[test]
fn member_role_set_unknown_member_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp)
        .args(["member", "role", "set", "missing", "readonly"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("team member not found: missing"));
}

#[test]
fn member_role_set_non_admin_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);
    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();

    let non_admin_identity = temp.path().join("non-admin.age");
    let _ = generate_identity_file(&non_admin_identity);

    cmd_in_with_identity(&temp, &non_admin_identity, "notadmin")
        .args(["member", "role", "set", "bob", "readonly"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("current identity is not an admin in .envkey"));
}

#[test]
fn member_role_set_noop_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);
    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();

    cmd_in(&temp)
        .args(["member", "role", "set", "bob", "member"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("member bob already has role member"));
}

#[test]
fn member_role_set_self_demotion_blocked() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp)
        .args(["member", "role", "set", "alice", "member"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot change your own admin role in M2"));
}

#[test]
fn member_role_set_self_admin_to_admin_is_noop_fail() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp)
        .args(["member", "role", "set", "alice", "admin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("member alice already has role admin"));
}

#[test]
fn member_role_set_reflected_in_member_ls() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);
    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();
    cmd_in(&temp).args(["member", "role", "set", "bob", "readonly"]).assert().success();

    cmd_in(&temp)
        .args(["member", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob"))
        .stdout(predicate::str::contains("readonly"));
}

#[test]
fn member_rm_requires_yes_or_interactive_confirmation() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);
    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();

    cmd_in(&temp)
        .args(["member", "rm", "bob"])
        .write_stdin("n\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("aborted"));

    cmd_in(&temp)
        .args(["member", "rm", "bob"])
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("aborted"));

    cmd_in(&temp).args(["member", "rm", "bob"]).write_stdin("y\n").assert().success();
}

#[test]
fn member_rm_unknown_member_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp)
        .args(["member", "rm", "missing", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("team member not found: missing"));
}

#[test]
fn member_rm_self_removal_is_blocked() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    cmd_in(&temp)
        .args(["member", "rm", "alice", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot remove your own admin identity"));
}

#[test]
fn member_rm_requires_admin_identity() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);
    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();

    let non_admin_identity = temp.path().join("non-admin.age");
    let _ = generate_identity_file(&non_admin_identity);

    cmd_in_with_identity(&temp, &non_admin_identity, "notadmin")
        .args(["member", "rm", "bob", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("current identity is not an admin in .envkey"));
}

#[test]
fn member_rm_reencrypts_and_revokes_removed_member() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);
    cmd_in(&temp).args(["set", "API_KEY", "secret"]).assert().success();

    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);
    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey]).assert().success();

    cmd_in_with_identity(&temp, &bob_identity, "bob")
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("secret\n");

    let before = read_envkey(&temp);
    let before_value =
        before.default_env().expect("default env").get("API_KEY").expect("api key").value.clone();

    cmd_in(&temp).args(["member", "rm", "bob", "--yes"]).assert().success();

    let after = read_envkey(&temp);
    let after_value =
        after.default_env().expect("default env").get("API_KEY").expect("api key").value.clone();
    assert_ne!(before_value, after_value);

    cmd_in_with_identity(&temp, &bob_identity, "bob")
        .args(["get", "API_KEY"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to decrypt value"));
}

#[test]
fn member_ls_displays_sorted_rows_with_lowercase_roles() {
    let temp = tempfile::tempdir().expect("tempdir");
    run_init(&temp);

    let zoe_pubkey = generate_identity_file(&temp.path().join("zoe.age"));
    let bob_pubkey = generate_identity_file(&temp.path().join("bob.age"));
    cmd_in(&temp)
        .args(["member", "add", "zoe", &zoe_pubkey, "--role", "readonly"])
        .assert()
        .success();
    cmd_in(&temp).args(["member", "add", "bob", &bob_pubkey, "--role", "ci"]).assert().success();

    let assert = cmd_in(&temp)
        .args(["member", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("NAME"))
        .stdout(predicate::str::contains("ROLE"))
        .stdout(predicate::str::contains("ENVIRONMENTS"))
        .stdout(predicate::str::contains("alice"))
        .stdout(predicate::str::contains("admin"))
        .stdout(predicate::str::contains("bob"))
        .stdout(predicate::str::contains("ci"))
        .stdout(predicate::str::contains("zoe"))
        .stdout(predicate::str::contains("readonly"))
        .stdout(predicate::str::contains("default"));

    let output = String::from_utf8(assert.get_output().stdout.clone()).expect("utf8 stdout");
    let alice_pos = output.find("alice").expect("alice present");
    let bob_pos = output.find("bob").expect("bob present");
    let zoe_pos = output.find("zoe").expect("zoe present");
    assert!(alice_pos < bob_pos && bob_pos < zoe_pos, "member list should be sorted by name");
}

#[test]
fn member_commands_support_global_identity_flag() {
    let temp = tempfile::tempdir().expect("tempdir");
    let admin_identity = temp.path().join("admin.age");
    let admin_pubkey = generate_identity_file(&admin_identity);

    cmd_with_global_identity(&temp, &admin_identity, "alice").args(["init"]).assert().success();

    let alice = read_envkey(&temp).team.get("alice").expect("alice member").pubkey.clone();
    assert_eq!(alice, admin_pubkey);

    let bob_identity = temp.path().join("bob.age");
    let bob_pubkey = generate_identity_file(&bob_identity);
    cmd_with_global_identity(&temp, &admin_identity, "alice")
        .args(["member", "add", "bob", &bob_pubkey])
        .assert()
        .success();

    cmd_with_global_identity(&temp, &admin_identity, "alice")
        .args(["member", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob"));
}

#[test]
fn member_add_allows_second_initialized_identity_to_read_existing_secrets() {
    let temp = tempfile::tempdir().expect("tempdir");
    let identity_dir = temp.path().join("ids");
    fs::create_dir_all(&identity_dir).expect("mkdir ids");
    let a_identity = identity_dir.join("a.age");
    let b_identity = identity_dir.join("b.age");

    cmd_with_global_identity(&temp, &a_identity, "alice").args(["init"]).assert().success();
    cmd_with_global_identity(&temp, &a_identity, "alice")
        .args(["set", "DATABASE_URL", "postgres://alice@localhost/app"])
        .assert()
        .success();

    let before = read_envkey(&temp);
    assert!(before.team.contains_key("alice"));
    assert!(!before.team.contains_key("bob"));
    let before_value = before
        .default_env()
        .expect("default env")
        .get("DATABASE_URL")
        .expect("database_url")
        .value
        .clone();

    cmd_with_global_identity(&temp, &b_identity, "alice").args(["init"]).assert().success();
    let after_b_init = read_envkey(&temp);
    assert!(after_b_init.team.contains_key("alice"));
    assert!(!after_b_init.team.contains_key("bob"));

    let b_secret = fs::read_to_string(&b_identity).expect("read b identity");
    let b_identity_value = b_secret.lines().next().expect("identity line");
    let b_pubkey = x25519::Identity::from_str(b_identity_value)
        .expect("parse b identity")
        .to_public()
        .to_string();

    cmd_with_global_identity(&temp, &a_identity, "alice")
        .args(["member", "add", "bob", &b_pubkey])
        .assert()
        .success();

    let after_add = read_envkey(&temp);
    let after_value = after_add
        .default_env()
        .expect("default env")
        .get("DATABASE_URL")
        .expect("database_url")
        .value
        .clone();
    assert_ne!(before_value, after_value);

    cmd_with_global_identity(&temp, &b_identity, "bob")
        .args(["get", "DATABASE_URL"])
        .assert()
        .success()
        .stdout("postgres://alice@localhost/app\n");
}
