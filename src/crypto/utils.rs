use super::*;

impl CryptoManager {
    pub fn new() -> Self {
        Self
    }

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
        if !force && (private_key_path.exists() || public_key_path.exists()) {
            return Err(SecretError::FileExists(
                "Keys already exist. Use --force to overwrite".to_string(),
            ));
        }

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
        if !force && recipient_path.exists() {
            return Err(SecretError::FileExists(
                "Public key already exists. Use --force to overwrite".to_string(),
            ));
        }
        let identity = age::x25519::Identity::from_str(&fs.read_file_content(key_path)?)
            .map_err(|_| SecretError::Parse("Invalid public key".to_string()))?;
        let new_recipient = identity.to_public().to_string();

        fs.write_atomic(recipient_path, new_recipient.as_bytes(), 0o640, 0o710)?;

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
        if !force && key_path.exists() {
            return Err(SecretError::FileExists(
                "Private key already exists. Use --force to overwrite".to_string(),
            ));
        }
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

    /// Rotate age keypair
    pub fn rotate_secrets_key(
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

        let old_identity = load_identity(&old_key_path)?;

        println!("New Public key: {}", public_key_path.display());
        println!("New Private key: {}", private_key_path.display());
        
        self.roate_keys(&old_identity, &new_recipient, secrets_dir, fs)?;


        if verify {
            match self.verify_keys(&private_key_path, &secrets_dir, fs) {
                Ok(()) => {print!("and verified")}
                Err(e) => {
                return Err(SecretError::Parse(format!(
                "[Warning] {} secrets failed to verify",
                e
            )));
            }
            }
        }

        println!(
            " at {} successfully rotated",
            secrets_dir.display()
        );
        Ok(())
    }

    /// List secret files with their last modified time
    pub fn list_secrets(&self, directory: &Path, fs: &FileManager) -> Result<(), SecretError> {
        let secret_files = fs.list_encrypted_files(directory)?;

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

    // Utility methods
    fn roate_keys(
        &self,
        old_identity: &age::x25519::Identity,
        new_recipient: &age::x25519::Recipient,
        secrets_path: &Path,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let mut n = 0;
        for file in fs.list_encrypted_files(secrets_path)? {
            match self.decrypt_file(&old_identity, &file) {
                Ok(secret) => {
                    self.encrypt_to_file(&file, &new_recipient, &secret, true, fs)?;
                    println!("Secret {} successfully rotated", file.display());
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

    fn verify_keys(
        &self,
        key_path: &Path,
        secrets_dir: &Path,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        if !key_path.exists() {
            return Err(SecretError::InvalidPath(format!(
                "Key path does not exist: {}",
                key_path.display()
            )));
        }

        if !secrets_dir.exists() {
            return Err(SecretError::InvalidPath(format!(
                "Secrets directory does not exist: {}",
                secrets_dir.display()
            )));
        }

        let identity = load_identity(key_path)?;
        let secrets = fs.list_encrypted_files(secrets_dir)?;
        if secrets.is_empty() {
            eprintln!(
                "Warning: No encrypted files found in {}",
                secrets_dir.display()
            );
            return Ok(());
        }

        let mut errors = 0;
        for secret in secrets {
            match self.decrypt_file(&identity, &secret) {
                Ok(_) => {
                    continue;
                }
                Err(e) => {
                    eprintln!("Failed to decrypt secret {}: {}", secret.display(), e);
                    errors += 1;
                    continue;
                }
            }
        }

        if errors > 0 {
            return Err(SecretError::Parse(format!(
                "[Warning] {} secrets failed to verify",
                errors
            )));
        }

        Ok(())
    }
}

pub fn load_identity(key_path: &Path) -> Result<age::x25519::Identity, SecretError> {
    let key_content = fs::read_to_string(key_path)?;
    SecretString::from(key_content)
        .expose_secret()
        .trim()
        .parse()
        .map_err(|e| SecretError::Parse(format!("Invalid private key: {}", e)))
}

/// Ensure path has .age extension
pub fn ensure_age_extension(path: &Path) -> PathBuf {
    if path.extension().and_then(|ext| ext.to_str()) == Some("age") {
        path.to_path_buf()
    } else {
        path.with_extension("age")
    }
}

pub fn generate_unique_filename(output_dir: &Path) -> Result<PathBuf, SecretError> {
    for _ in 0..10 {
        let random_id = generate_base58(16).map_err(|e| SecretError::Parse(e.to_string()))?;
        let path = output_dir.join(&random_id.expose_secret());
        if !path.exists() {
            return Ok(ensure_age_extension(&path));
        }
    }
    Err(SecretError::InvalidPath(
        "Could not generate unique filename".to_string(),
    ))
}

fn get_key_paths(keys_dir: &Path) -> (PathBuf, PathBuf) {
    let public_key_path = keys_dir.join("secrets.pub");
    let private_key_path = keys_dir.join("secrets.key");
    (public_key_path, private_key_path)
}

