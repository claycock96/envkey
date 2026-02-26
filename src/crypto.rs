use std::io::Write;

use age::{Encryptor, Recipient, decrypt, x25519};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::{EnvkeyError, Result};

pub fn encrypt_value(plaintext: &str, recipients: &[x25519::Recipient]) -> Result<String> {
    if recipients.is_empty() {
        return Err(EnvkeyError::message("cannot encrypt without at least one recipient"));
    }

    let encryptor = Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn Recipient))
        .map_err(|err| EnvkeyError::message(format!("failed to build encryptor: {err}")))?;

    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|err| EnvkeyError::message(format!("failed to wrap encrypt output: {err}")))?;
    writer
        .write_all(plaintext.as_bytes())
        .map_err(|err| EnvkeyError::message(format!("failed to encrypt value: {err}")))?;
    writer
        .finish()
        .map_err(|err| EnvkeyError::message(format!("failed to finalize encryption: {err}")))?;

    Ok(STANDARD.encode(out))
}

pub fn decrypt_value(ciphertext_b64: &str, identity: &x25519::Identity) -> Result<String> {
    let ciphertext = STANDARD
        .decode(ciphertext_b64)
        .map_err(|err| EnvkeyError::message(format!("ciphertext is not valid base64: {err}")))?;

    let decrypted = decrypt(identity, &ciphertext)
        .map_err(|err| EnvkeyError::message(format!("failed to decrypt value: {err}")))?;

    String::from_utf8(decrypted)
        .map_err(|err| EnvkeyError::message(format!("decrypted value is not valid UTF-8: {err}")))
}

#[cfg(test)]
mod tests {
    use age::x25519;

    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public();

        let encrypted = encrypt_value("super-secret", &[recipient]).expect("encrypt");
        let decrypted = decrypt_value(&encrypted, &identity).expect("decrypt");

        assert_eq!(decrypted, "super-secret");
    }

    #[test]
    fn decrypt_with_wrong_identity_fails() {
        let identity_a = x25519::Identity::generate();
        let identity_b = x25519::Identity::generate();
        let recipient = identity_a.to_public();

        let encrypted = encrypt_value("super-secret", &[recipient]).expect("encrypt");
        let err = decrypt_value(&encrypted, &identity_b).expect_err("must fail");

        assert!(err.to_string().contains("failed to decrypt value"));
    }
}
