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
    ) -> Result<(), SecretError> {
        let (public_key_path, private_key_path) = default_key_paths(keys_dir);

        // Check existing keys unless force is enabled
        FileManager.overwrite_check(&public_key_path, force)?;
        FileManager.overwrite_check(&private_key_path, force)?;

        // Create secure directories
        FileManager.create_secure_dir(keys_dir, 0o710)?;
        FileManager.create_secure_dir(secrets_dir, 0o750)?;

        // Generate and store keypair
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();

        FileManager.write_atomic(
            &public_key_path,
            recipient.to_string().as_bytes(),
            0o640,
            0o710,
        )?;
        FileManager.write_atomic(
            &private_key_path,
            identity.to_string().expose_secret().as_bytes(),
            0o600,
            0o710,
        )?;

        println!("New Identity (Private key): {}", private_key_path.display());
        println!("New Recipient (Public key): {}", public_key_path.display());
        println!("Secret store initialized @: {}", secrets_dir.display());

        Ok(())
    }

    /// Create new recipient key
    pub fn new_recipient(
        &self,
        key_path: &Path,
        recipient_path: &Path,
        force: bool,
    ) -> Result<(), SecretError> {
        // Check existing keys unless force is enabled
        FileManager.overwrite_check(recipient_path, force)?;

        // Generate new recipient from existing identity
        let identity = FileManager.parse_identity_file(key_path)?;
        let new_recipient = identity.to_public();

        // Write new recipient
        FileManager.write_atomic(
            recipient_path,
            new_recipient.to_string().as_bytes(),
            0o640,
            0o710,
        )?;

        println!("New Recipient (Public key): {}", recipient_path.display());
        Ok(())
    }

    /// Create new identity
    pub fn new_identity(&self, key_path: &Path, force: bool) -> Result<(), SecretError> {
        // Check existing keys unless force is enabled
        FileManager.overwrite_check(key_path, force)?;

        // Generate new identity
        let identity = age::x25519::Identity::generate();

        // Write new identity
        FileManager.write_atomic(
            key_path,
            identity.to_string().expose_secret().as_bytes(),
            0o600,
            0o710,
        )?;
        println!("New Identity (Private key): {}", key_path.display());
        Ok(())
    }

    /// Rotate secret contents
    pub fn rotate_secret(
        &self,
        key_path: &Path,
        recipient: &str,
        secret_path: &Path,
        base: u64,
    ) -> Result<(), SecretError> {
        // Decrypt secret and create new secret of same length
        let identity = FileManager.parse_identity_file(key_path)?;
        let old_secret = self.decrypt_file(&identity, secret_path)?;
        let content_length = old_secret.expose_secret().len();
        let new_secret = new_secret_string(content_length, base)?;
        // Encrypt new secret to file
        self.new_secret(&recipient, new_secret.expose_secret(), secret_path, true)?;

        // Verify secret has changed
        match self.decrypt_file(&identity, secret_path)?.expose_secret()
            == old_secret.expose_secret()
        {
            true => {
                return Err(SecretError::Parse(format!(
                    "Failed to rotate secret {}: contents did not change",
                    secret_path.display()
                )));
            }
            false => {
                println!(
                    "Successfully rotated secret {} ({} bytes)",
                    secret_path.display(),
                    content_length
                );
            }
        }

        Ok(())
    }

    /// Rotate all secrets in directory
    pub fn rotate_all_secrets(
        &self,
        key_path: &Path,
        recipient: &str,
        secrets_dir: &Path,
        base: u64,
    ) -> Result<(), SecretError> {
        // Create list of errors
        let mut errors = Vec::new();

        // Rotate all secrets
        for secret in FileManager.list_age_files(secrets_dir)? {
            match self.rotate_secret(key_path, recipient, &secret, base) {
                Ok(()) => {}
                Err(e) => errors.push(e),
            }
        }

        // Return error if any
        if errors.is_empty() {
            println!("Successfully rotated all secrets");
            Ok(())
        } else {
            for error in &errors {
                eprintln!("[Warning!]: {}", error);
            }
            return Err(SecretError::InvalidPath(
                "Failed to rotate secrets".to_string(),
            ));
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
    ) -> Result<(), SecretError> {
        let (public_key_path, private_key_path) = default_key_paths(new_keys_dir);

        // Check existing keys unless force is enabled
        FileManager.overwrite_check(&public_key_path, force)?;
        FileManager.overwrite_check(&private_key_path, force)?;

        // Backup old keys if overwriting
        backup_key(&private_key_path, &old_key_path)?;
        if public_key_path.exists() {
            backup_key(&public_key_path, &public_key_path)?;
        }

        // Parse old key
        let old_identity = FileManager.parse_identity_file(&old_key_path)?;
        
        // Generate new keypair and write
        let new_identity = age::x25519::Identity::generate();
        let new_recipient = new_identity.to_public();

        FileManager.write_atomic(
            &public_key_path,
            new_recipient.to_string().as_bytes(),
            0o640,
            0o750,
        )?;
        FileManager.write_atomic(
            &private_key_path,
            new_identity.to_string().expose_secret().as_bytes(),
            0o600,
            0o750,
        )?;

        println!("New Identity (Private key): {}", private_key_path.display());
        println!("New Recipient (Public key): {}", public_key_path.display());

        let mut n = 0;
        for file in FileManager.list_age_files(secrets_dir)? {
            self.roate_key(&old_identity, &new_recipient, &new_identity, &file, verify)?;
            n += 1;
        }

        if n == 0 {
            return Err(SecretError::Parse("No secrets rotated".to_string()));
        } else {
            println!(
                "{} secrets rotated successfully",n,
            );
        }

        Ok(())
    }

    // Utility methods
    fn roate_key(
        &self,
        old_identity: &age::x25519::Identity,
        new_recipient: &age::x25519::Recipient,
        new_identity: &age::x25519::Identity,
        secret_path: &Path,
        verify: bool,
    ) -> Result<(), SecretError> {
        match self.decrypt_file(&old_identity, &secret_path) {
            Ok(secret) => {
                self.new_secret(
                    &new_recipient.to_string(),
                    secret.expose_secret(),
                    secret_path,
                    true,
                )?;

                if verify {
                    match self.verify_decrypt(&new_identity, secret_path) {
                        Ok(()) => {println!("[OK] Decryption verified");}
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to rotate secret {}: {}", secret_path.display(), e);
            }
        }
        Ok(())
    }

    /// List secret files with their last modified time
    pub fn list_secrets(&self, directory: &Path) -> Result<(), SecretError> {
        let secret_files = FileManager.list_age_files(directory)?;

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

    fn verify_decrypt(
        &self,
        identity: &age::x25519::Identity,
        secret: &Path,
    ) -> Result<(), SecretError> {
        match self.decrypt_file(&identity, &secret) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
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

fn default_key_paths(keys_dir: &Path) -> (PathBuf, PathBuf) {
    let public_key_path = keys_dir.join("recipient.pub");
    let private_key_path = keys_dir.join("identity.key");
    (public_key_path, private_key_path)
}

fn backup_key(new: &Path, old: &Path) -> Result<(), SecretError> {
    if new == old {
        let old_bak = old.with_extension("bak");
        match fs::copy(old, &old_bak) {
            Ok(_) => {
                println!(
                    "New and old keys have the same path. Old key backed up to {}",
                    old_bak.display()
                );
            }
            Err(e) => {
                return Err(SecretError::InvalidPath(format!(
                    "Failed to backup old key: {}",
                    e
                )));
            }
        }
    }
    Ok(())
}
