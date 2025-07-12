use super::*;

impl CryptoManager {
    /// Decrypt secret to specific file
    pub fn decrypt_to_file(
        &self,
        key_path: &Path,
        secret: &Path,
        output: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        if !force && output.exists() {
            return Err(SecretError::FileExists(format!(
                "Output file {} already exists. Use --force to overwrite",
                output.display()
            )));
        }

        let identity = load_identity(key_path)?;
        let content = self.decrypt_file(&identity, secret)?;

        fs.write_atomic(output, content.expose_secret().as_bytes(), 0o640, 0o750)?;
        Ok(())
    }


    /// Decrypt all secrets in directory
    pub fn decrypt_all_secrets(
        &self,
        key_path: &Path,
        source: &Path,
        output: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let identity = load_identity(key_path)?;
        fs.create_secure_dir(output, 0o710)?;

        let encrypted_files = fs.list_encrypted_files(source)?;
        if encrypted_files.is_empty() {
            eprintln!("Warning: No .age files found in {}", source.display());
            return Ok(());
        }

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
        if !force && output.exists() {
            return Err(SecretError::FileExists(format!(
                "Output file {} already exists. Use --force to overwrite",
                output.display()
            )));
        }

        fs.create_secure_dir(output.parent().ok_or_else(|| {
            SecretError::InvalidPath(format!("Invalid output directory: {}", output.display()))
        })?, 0o710)?;

        fs.write_atomic(path::Path::new(output), "".as_bytes(), 0o640, 0o710)?; 

        let identity = load_identity(key_path)?;
        for secret in fs.list_encrypted_files(secret_dir)? {
            let var: &str = self.decrypt_file(identity, &secret_dir)?.expose_secret();
            // Write to output file
            fs::append_file(output, format!("{}={}\n", secret.file_stem().unwrap().to_str().unwrap(), var).as_bytes())?;
        }
        Ok(())
    }


    fn process_batch_decrypt(
        &self,
        files: &[PathBuf],
        output_dir: &Path,
        identity: &age::x25519::Identity,
        force: bool,
        fs: &FileManager,
    ) -> Result<(usize, Vec<String>), SecretError> {
        let mut success_count = 0;
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
        success_count: usize,
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

        Ok(SecretString::from(
            String::from_utf8_lossy(&decrypted).to_string(),
        ))
    }









}

