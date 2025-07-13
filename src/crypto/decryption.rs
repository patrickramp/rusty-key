// // src/crypto/decryption.rs
use super::*;

use age::Decryptor;
use age::secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

impl CryptoManager {
    /// Decrypt secret to specific file
    pub fn open_secret_to_file (
        &self,
        key_path: &Path,
        secret: &Path,
        output: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        // Verify output file doesn't exist
        fs.overwrite_check(output, force)?;

        let identity = fs.parse_identity_file(key_path)?;
        let content = self.decrypt_file(&identity, secret)?;

        fs.write_atomic(output, content.expose_secret().as_bytes(), 0o640, 0o750)?;
        Ok(())
    }

    /// Decrypt all secrets in directory
    pub fn open_all_secrets(
        &self,
        key_path: &Path,
        source: &Path,
        output: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        // List encrypted files
        let encrypted_files = fs.list_age_files(source)?;

        // Verify output directory exists and is secure
        fs.create_secure_dir(output, 0o710)?;

        // Load identity
        let identity = fs.parse_identity_file(key_path)?;

        // Batch decrypt
        let (success_count, errors) =
            self.process_batch_decrypt(&encrypted_files, output, &identity, force, fs)?;
        self.report_batch_results(success_count, errors, output)
    }

    /// Decrypt to .env file
    pub fn decrypt_to_env(
        &self,
        key_path: &Path,
        secret_dir: &Path,
        output: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        // Verify output file doesn't exist
        fs.overwrite_check(output, force)?;

        // Ensure the parent directory exists and is secure
        fs.create_secure_dir(
            output.parent().ok_or_else(|| {
                SecretError::InvalidPath(format!("Invalid output directory: {}", output.display()))
            })?,
            0o710,
        )?;

        
        let identity = fs.parse_identity_file(key_path)?;
        
        let mut env_contents = String::new();

        let secure_contents = {
            for secret in fs.list_age_files(secret_dir)? {
                let secret_name = secret.file_stem().expect("Invalid filename").to_str().unwrap();
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
        fs.write_atomic(
            output,
            secure_contents.expose_secret().as_bytes(),
            0o640,
            0o710,
        )?;

        Ok(())
    }

    fn process_batch_decrypt(
        &self,
        files: &[PathBuf],
        output_dir: &Path,
        identity: &age::x25519::Identity,
        force: bool,
        fs: &FileManager,
    ) -> Result<(u16, Vec<String>), SecretError> {
        let mut success_count: u16 = 0;
        let mut errors = Vec::new();

        for file in files {
            match self.decrypt_single_file(file, output_dir, identity, force, fs) {
                Ok(()) => success_count += 1,
                Err(e) => errors.push(format!("Failed to decrypt {}: {}", file.display(), e)),
            }
        }

        Ok((success_count, errors))
    }

    fn decrypt_single_file(
        &self,
        source: &Path,
        output_dir: &Path,
        identity: &age::x25519::Identity,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let stem = source.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
            SecretError::InvalidPath(format!("Invalid filename: {}", source.display()))
        })?;

        let output_path = output_dir.join(stem);

        if !force && output_path.exists() {
            return Err(SecretError::FileExists(format!(
                "File {} already exists (use --force to overwrite)",
                output_path.display()
            )));
        }

        let content = self.decrypt_file(identity, source)?;
        fs.write_atomic(
            &output_path,
            content.expose_secret().as_bytes(),
            0o640,
            0o750,
        )?;
        Ok(())
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

    pub fn decrypt_file(
        &self,
        identity: &age::x25519::Identity,
        source: &Path,
    ) -> Result<SecretString, SecretError> {
        let encrypted = fs::read(source)?;
        let decryptor = Decryptor::new(&encrypted[..])?;

        let mut decrypted = Vec::new();
        let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
        reader.read_to_end(&mut decrypted)?;

        let content = String::from_utf8(decrypted).map_err(|e| {
            SecretError::Parse(format!("Invalid UTF-8 in decrypted content: {}", e))
        })?;

        Ok(SecretString::from(content))
    }

    /// Decrypt secret to stdout
    pub fn show_secret(
        &self,
        key_path: &Path,
        source: &Path,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let identity = fs.parse_identity_file(key_path)?;
        let content = self.decrypt_file(&identity, source)?;

        io::stdout().write_all(content.expose_secret().as_bytes())?;
        io::stdout().flush()?;
        Ok(())
    }
}
