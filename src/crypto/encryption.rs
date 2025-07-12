use super::*;

impl CryptoManager {
    /// Encrypt content to file
    pub fn encrypt_secret(
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
        input: &str,
        name: &str,
        output_dir: &Path,
        cache_dir: &Path,
        auto_decrypt: bool,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let output_file = if name == "random_id" {
            generate_unique_filename(output_dir)?
        } else {
            ensure_age_extension(&output_dir.join(name))
        };

        self.encrypt_secret(recipient, input, &output_file, force, fs)?;

        if auto_decrypt {
            let cache_file = cache_dir
                .join(output_file.file_name().unwrap())
                .with_extension("");
            self.decrypt_to_file(key_path, &output_file, &cache_file, true, fs)?;
            println!("Auto-decrypted to {}", cache_file.display());
        }

        Ok(())
    }
    
    /// Decrypt secret to stdout
    pub fn show_secret(&self, key_path: &Path, source: &Path) -> Result<(), SecretError> {
        let identity = load_identity(key_path)?;
        let content = self.decrypt_file(&identity, source)?;

        io::stdout().write_all(content.expose_secret().as_bytes())?;
        io::stdout().flush()?;
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
        if !force && output.exists() {
            return Err(SecretError::FileExists(format!(
                "Output file {} already exists. Use --force to overwrite",
                output.display()
            )));
        }

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


