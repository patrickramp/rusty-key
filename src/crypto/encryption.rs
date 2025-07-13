// src/crypto/encryption.rs
use super::*;

use age::Encryptor;
use age::secrecy::{ExposeSecret, SecretString};
use std::io::Write;
use std::path::Path;

impl CryptoManager {
    /// Encrypt content to file
    pub fn new_secret(
        &self,
        recipient: &str,
        input: &str,
        output: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let output = ensure_age_extension(output);
        let recipient = fs.parse_recipient(recipient)?;
        let content = SecretString::from(fs.parse_content(input)?);

        self.encrypt_to_file(&output, &recipient, &content, force, fs)?;

        println!(
            "Encrypted {} bytes to {}",
            content.expose_secret().len(),
            output.display()
        );
        Ok(())
    }

    /// Create secret with optional auto-decrypt
    pub fn quick_secret(
        &self,
        recipient: &str,
        key_path: &Path,
        name: &str,
        length: usize,
        base: u64,
        output_dir: &Path,
        cache_dir: &Path,
        auto_decrypt: bool,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let output_file = ensure_age_extension(&output_dir.join(name));
        let input = new_secret_string(length, base)?; 

        self.new_secret(recipient, input.expose_secret(), &output_file, force, fs)?;

        if auto_decrypt {
            let cache_file = cache_dir
                .join(output_file.file_name().unwrap())
                .with_extension("");
            self.open_secret_to_file(key_path, &output_file, &cache_file, true, fs)?;
            println!("Auto-decrypted to {}", cache_file.display());
        }

        Ok(())
    }


    // Private implementation methods
    pub fn encrypt_to_file(
        &self,
        output: &Path,
        recipient: &age::x25519::Recipient,
        content: &SecretString,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        fs.overwrite_check(output, force)?;

        let encryptor =
            Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
                .map_err(|e| SecretError::Parse(format!("Failed to create encryptor: {}", e)))?;

        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(content.expose_secret().as_bytes())?;
        writer.finish()?;

        fs.write_atomic(output, &encrypted, 0o640, 0o750)?;
        Ok(())
    }
}

// Sanitize filename
pub fn sanitize_filename(filename: &str) -> String {
    const MAX_LEN: usize = 255;
    const RESERVED_NAMES: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    let mut result = String::with_capacity(filename.len());

    // Truncate filename if over MAX_LEN
    if result.len() > MAX_LEN {
        result.truncate(MAX_LEN);
    }

    for ch in filename.chars() {
        match ch {
            '\x00'..='\x1F' | '<' | '>' | ':' | '"' | '|' | '?' | '*' | '/' | '\\' => {
                result.push('_')
            }
            _ => result.push(ch),
        }
    }

    // Trim whitespace and trailing dots
    result = result.trim_matches(char::is_whitespace).to_string();
    result = result.trim_end_matches('.').to_string();

    // Check reserved name
    let name_part = result.split('.').next().unwrap_or("");
    if RESERVED_NAMES
        .iter()
        .any(|&r| r.eq_ignore_ascii_case(name_part))
    {
        result.push('_');
    }

    if result.is_empty() {
        result = "UNNAMED".to_string();
    }

    result
}
