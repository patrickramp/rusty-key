// // src/crypto/decryption.rs
use super::*;

use age::Decryptor;
use age::secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

impl CryptoManager {
    /// Decrypt to .env file
    pub fn decrypt_to_env(
        &self,
        key_path: &Path,
        source_dir: &Path,
        env_output: &Path,
        force: bool,
    ) -> Result<(), SecretError> {
        // Verify output file doesn't exist
        FileManager.overwrite_check(env_output, force)?;

        // Ensure the parent directory exists and is secure
        FileManager.create_secure_dir(
            env_output.parent().ok_or_else(|| {
                SecretError::InvalidPath(format!(
                    "Invalid output directory: {}",
                    env_output.display()
                ))
            })?,
            0o710,
        )?;

        let identity = FileManager.parse_identity_file(key_path)?;

        // Decrypt all secrets to string
        let mut env_contents = String::new();
        let secure_contents = {
            for secret in FileManager.list_age_files(source_dir)? {
                let secret_name = secret
                    .file_stem()
                    .expect("Invalid filename")
                    .to_str()
                    .unwrap();
                let secret_content = self.decrypt_file(&identity, &secret)?;
                env_contents.push_str(&format!(
                    "{}={}\n",
                    secret_name.to_uppercase(),
                    secret_content.expose_secret()
                ));
            }
            SecretString::from(env_contents)
        };

        // Write all entries to the output file
        FileManager.write_atomic(
            env_output,
            secure_contents.expose_secret().as_bytes(),
            0o640,
            0o710,
        )?;

        Ok(())
    }

    /// Decrypt secret to specific file
    pub fn decrypt_to_path(
        &self,
        identity: &age::x25519::Identity,
        source: &Path,
        output: &Path,
        force: bool,
    ) -> Result<(), SecretError> {
        // Verify output file doesn't exist
        FileManager.overwrite_check(output, force)?;

        let content = self.decrypt_file(&identity, source)?;

        FileManager.write_atomic(output, content.expose_secret().as_bytes(), 0o640, 0o750)?;
        Ok(())
    }

    pub fn decrypt_file(
        &self,
        identity: &age::x25519::Identity,
        source: &Path,
    ) -> Result<SecretString, SecretError> {
        let input = source.to_str().ok_or_else(|| {
            SecretError::InvalidPath(format!("Invalid filename: {}", source.display()))
        })?;
        let content = fs::read(input).map_err(|e| {
            SecretError::InvalidPath(format!("Failed to read {}: {}", input, e))
        })?;
        self.decrypt_secret(&identity, &content)
    }

    pub fn decrypt_secret(
        &self,
        identity: &age::x25519::Identity,
        secret_bytes: &[u8],
    ) -> Result<SecretString, SecretError> {
        // Create decryptor
        let decryptor = Decryptor::new(secret_bytes)?;

        // Decrypt content to string
        let mut decrypted = Vec::new();
        let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
        reader.read_to_end(&mut decrypted)?;
        let content = String::from_utf8(decrypted).map_err(|e| {
            SecretError::Parse(format!("Unable to parse secret content (Invalid UTF-8): {}", e))
        })?;

        Ok(SecretString::from(content))
    }

    /// Decrypt secret to stdout
    pub fn show_secret(&self, key_path: &Path, source: &Path) -> Result<(), SecretError> {
        let identity = FileManager.parse_identity_file(key_path)?;
        let content = self.decrypt_file(&identity, source)?;

        io::stdout().write_all(content.expose_secret().as_bytes())?;
        io::stdout().flush()?;
        Ok(())
    }

    /// Decrypt all secrets in directory
    pub fn decrypt_all_secrets(
        &self,
        key_path: &Path,
        source_dir: &Path,
        output_dir: &Path,
        force: bool,
    ) -> Result<(), SecretError> {
        // Verify output directory exists and is secure
        FileManager.create_secure_dir(output_dir, 0o710)?;

        // List encrypted files
        let encrypted_files = FileManager.list_age_files(source_dir)?;

        // Load identity
        let identity = FileManager.parse_identity_file(key_path)?;

        // Batch decrypt
        let (success_count, errors) =
            self.batch_decrypt(&encrypted_files, output_dir, &identity, force)?;
        self.report_batch_results(success_count, errors, output_dir)
    }

    fn batch_decrypt(
        &self,
        files: &[PathBuf],
        output_dir: &Path,
        identity: &age::x25519::Identity,
        force: bool,
    ) -> Result<(u16, Vec<String>), SecretError> {
        let mut success_count: u16 = 0;
        let mut errors = Vec::new();

        for file in files {
            match self.decrypt_to_path(identity, &file, &output_dir, force) {
                Ok(()) => success_count += 1,
                Err(e) => errors.push(format!("Failed to decrypt {}: {}", file.display(), e)),
            }
        }

        Ok((success_count, errors))
    }

    fn report_batch_results(
        &self,
        success_count: u16,
        errors: Vec<String>,
        output: &Path,
    ) -> Result<(), SecretError> {
        for error in &errors {
            eprintln!("Warning: {}", error);
        }

        match success_count {
            0 if !errors.is_empty() => Err(SecretError::InvalidPath(
                "No files could be decrypted".to_string(),
            )),
            0 => Ok(()), // No files found case already handled
            count => {
                eprintln!("Decrypted {} secrets to {}", count, output.display());
                Ok(())
            }
        }
    }

    pub fn decrypt_path_to_path(
        &self,
        identity: &Path,
        source: &Path,
        output: &Path,
        force: bool,
    ) -> Result<(), SecretError> {
        let identity = FileManager.parse_identity_file(identity)?;
        self.decrypt_to_path(&identity, source, output, force)
    }

    pub fn decrypt_path_to_dir(
        &self,
        identity: &Path,
        source: &Path,
        output_dir: &Path,
        force: bool,
    ) -> Result<(), SecretError> {
        let output_name = source
            .file_stem() // get filename without extension
            .and_then(|s| s.to_str()) // convert to &str
            .ok_or_else(|| {
                SecretError::InvalidPath(format!("Invalid filename: {}", source.display()))
            })?;

        let output_path = output_dir.join(output_name);
        let identity = FileManager.parse_identity_file(identity)?;


        self.decrypt_to_path(&identity, source, &output_path, force)?;

        Ok(())
    }
}
