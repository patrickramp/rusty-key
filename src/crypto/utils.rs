use crate::random::new_secret_string;

use super::*;

use age::secrecy::ExposeSecret;
use std::fs;
use std::path::{Path, PathBuf};

impl CryptoManager {
    /// Initialize secret store with new age keypair
    pub fn init_store(
        &self,
        keys_dir: &Path,
        secrets_dir: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let (public_key_path, private_key_path) = get_key_paths(keys_dir);

        // Check existing keys unless force is enabled
        fs.overwrite_check(&public_key_path, force)?;
        fs.overwrite_check(&private_key_path, force)?;

        // Create secure directories
        fs.create_secure_dir(keys_dir, 0o710)?;
        fs.create_secure_dir(secrets_dir, 0o750)?;

        // Generate and store keypair
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();

        fs.write_atomic(&public_key_path, recipient.as_bytes(), 0o640, 0o710)?;
        fs.write_atomic(
            &private_key_path,
            identity.to_string().expose_secret().as_bytes(),
            0o600,
            0o710,
        )?;

        println!("Public key: {}", public_key_path.display());
        println!("Private key: {}", private_key_path.display());
        println!("Secret store initialized at {}", secrets_dir.display());

        Ok(())
    }

    /// Create new recipient key
    pub fn new_recipient(
        &self,
        key_path: &Path,
        recipient_path: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        fs.overwrite_check(recipient_path, force)?;

        let identity = fs.parse_identity_file(key_path)?;
        let new_recipient = identity.to_public();

        fs.write_atomic(
            recipient_path,
            new_recipient.to_string().as_bytes(),
            0o640,
            0o710,
        )?;

        println!("New public recipient key: {}", recipient_path.display());
        Ok(())
    }

    /// Create new identity
    pub fn new_identity(
        &self,
        key_path: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        fs.overwrite_check(key_path, force)?;

        let identity = age::x25519::Identity::generate();
        fs.write_atomic(
            key_path,
            identity.to_string().expose_secret().as_bytes(),
            0o600,
            0o710,
        )?;
        println!("New private identity: {}", key_path.display());
        Ok(())
    }

    /// Rotate secret contents

    pub fn rotate_secret(
        &self,
        key_path: &Path,
        recipient: &str,
        base: u64,
        secret_path: &Path,
        verify: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let identity = fs.parse_identity_file(key_path)?;
        let recipient = fs.parse_recipient(recipient)?;

        let old_secret = self.decrypt_file(&identity, secret_path)?;
        let content_length = old_secret.expose_secret().len();

        let new_secret = new_secret_string(content_length, base)?;

        self.encrypt_to_file(secret_path, &recipient, &new_secret, true, fs)?;

        if verify {
            match self.verify_secret(&identity, secret_path) {
                Ok(()) => println!("Roundtrip verification successful"),
                Err(e) => eprintln!("Verification failed: {}", e),
            }
        }
        match self.decrypt_file(&identity, secret_path)?.expose_secret() != old_secret.expose_secret() {
            true => {}
            false => {
                return Err(SecretError::Parse(
                    "Secret unchanged. Failed to rotate secret".to_string(),
                ));
            }
        }

        println!(
            "Secret {} rotated ({} characters long)",
            secret_path.display(),
            content_length,
        );

        Ok(())
    }

    /// Rotate all secrets in directory
    pub fn rotate_all_secrets(
        &self,
        key_path: &Path,
        recipient: &str,
        secrets_dir: &Path,
        base: u64,
        verify: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let mut errors = Vec::new();

        for secret in fs.list_age_files(secrets_dir)? {
            match self.rotate_secret(
                key_path,
                recipient,
                base,
                &secret,
                verify,
                fs,
            ) {
                Ok(()) => {}
                Err(e) => errors.push(e),
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(SecretError::Multiple(errors))
        }
    }
    


    /// Rotate age keypair
    pub fn rotate_encryption_keys(
        &self,
        old_key_path: &Path,
        new_keys_dir: &Path,
        secrets_dir: &Path,
        verify: bool,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let (public_key_path, private_key_path) = get_key_paths(new_keys_dir);

        if !force && (public_key_path.exists() || private_key_path.exists()) {
            return Err(SecretError::FileExists(
                "Keys already exist. Use --force to overwrite".to_string(),
            ));
        }

        let new_identity = age::x25519::Identity::generate();
        let new_recipient = new_identity.to_public();

        fs.write_atomic(
            &public_key_path,
            new_recipient.to_string().as_bytes(),
            0o640,
            0o750,
        )?;
        fs.write_atomic(
            &private_key_path,
            new_identity.to_string().expose_secret().as_bytes(),
            0o600,
            0o750,
        )?;

        let old_identity = fs.parse_identity_file(&old_key_path)?;

        println!("New Public key: {}", public_key_path.display());
        println!("New Private key: {}", private_key_path.display());

        self.roate_keys(
            &old_identity,
            &new_recipient,
            &new_identity,
            secrets_dir,
            verify,
            fs,
        )?;

        println!(" at {} successfully rotated", secrets_dir.display());
        Ok(())
    }

    // Utility methods
    fn roate_keys(
        &self,
        old_identity: &age::x25519::Identity,
        new_recipient: &age::x25519::Recipient,
        new_identity: &age::x25519::Identity,
        secrets_dir: &Path,
        verify: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let mut n = 0;
        for file in fs.list_age_files(secrets_dir)? {
            match self.decrypt_file(&old_identity, &file) {
                Ok(secret) => {
                    self.encrypt_to_file(&file, &new_recipient, &secret, true, fs)?;
                    println!("Secret {} successfully rotated", file.display());

                    if verify {
                        match self.verify_secret(&new_identity, &file) {
                            Ok(()) => println!("Roundtrip verification successful"),
                            Err(e) => eprintln!("Verification failed: {}", e),
                        }
                    }
                    n += 1;
                }
                Err(e) => {
                    eprintln!("Failed to rotate secret {}: {}", file.display(), e);
                }
            }
        }

        if n == 0 {
            return Err(SecretError::Parse("No secrets rotated".to_string()));
        } else {
            print!("{} secrets have been rotated...  ", n);
        }

        Ok(())
    }

    /// List secret files with their last modified time
    pub fn list_secrets(&self, directory: &Path, fs: &FileManager) -> Result<(), SecretError> {
        let secret_files = fs.list_age_files(directory)?;

        for secret_file in secret_files {
            let file_metadata = fs::metadata(&secret_file)?;
            let last_modified = file_metadata.modified()?.elapsed().map_err(|e| {
                SecretError::Parse(format!("Failed to retrieve file modified date: {}", e))
            })?;

            if let Some(file_name) = secret_file.with_extension("").file_name() {
                println!(
                    "{} (Last modified {} days ago)",
                    file_name.to_string_lossy(),
                    last_modified.as_secs() / (60 * 60 * 24)
                );
            } else {
                println!("Invalid file name: {}", secret_file.display());
            }
        }

        Ok(())
    }

    fn verify_secret(
        &self,
        identity: &age::x25519::Identity,
        secret: &Path,
    ) -> Result<(), SecretError> {
        match self.decrypt_file(&identity, &secret) {
            Ok(_) => Ok(()),
            Err(e) => Err(SecretError::Parse(format!(
                "Failed to verify secret {}: {}",
                secret.display(),
                e
            ))),
        }
    }
}

/// Ensure path has .age extension
pub fn ensure_age_extension(path: &Path) -> PathBuf {
    if path.extension().and_then(|ext| ext.to_str()) == Some("age") {
        path.to_path_buf()
    } else {
        path.with_extension("age")
    }
}

fn get_key_paths(keys_dir: &Path) -> (PathBuf, PathBuf) {
    let public_key_path = keys_dir.join("recipient.pub");
    let private_key_path = keys_dir.join("identity.key");
    (public_key_path, private_key_path)
}

