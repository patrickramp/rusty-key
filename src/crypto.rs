// src/crypto.rs
use crate::{errors::SecretError, filesystem::FileManager};
use age::secrecy::{ExposeSecret, SecretString};
use age::{Decryptor, Encryptor};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cryptographic operations for age-encrypted secrets
pub struct CryptoManager;

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
        let (public_key_path, private_key_path) = self.get_key_paths(keys_dir);
        
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

        fs.write_atomic(&public_key_path, recipient.as_bytes(), 0o640)?;
        fs.write_atomic(
            &private_key_path,
            identity.to_string().expose_secret().as_bytes(),
            0o600,
        )?;

        println!("Public key: {}", public_key_path.display());
        println!("Private key: {}", private_key_path.display());
        println!("Secret store initialized at {}", secrets_dir.display());

        Ok(())
    }

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

        self.encrypt_to_file(&output, recipient, &content, force, fs)?;

        println!("Encrypted {} bytes to {}", content.expose_secret().len(), output.display());
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
            self.generate_unique_filename(output_dir)?
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
        let identity = self.load_identity(key_path)?;
        let content = self.decrypt_file(&identity, source)?;

        io::stdout().write_all(content.expose_secret().as_bytes())?;
        io::stdout().flush()?;
        Ok(())
    }

    /// Rotate age keypair
    pub fn rotate_key(&self, key_path: &Path, force: bool, fs: &FileManager) -> Result<(), SecretError> {
        let (public_key_path, private_key_path) = self.get_key_paths(key_path);
        
        if !force && (private_key_path.exists() || public_key_path.exists()) {
            return Err(SecretError::FileExists(
                "Keys already exist. Use --force to overwrite".to_string(),
            ));
        }

        let new_identity = age::x25519::Identity::generate();
        let new_recipient = new_identity.to_public().to_string();

        fs.write_atomic(&public_key_path, new_recipient.as_bytes(), 0o640)?;
        fs.write_atomic(
            &private_key_path,
            new_identity.to_string().expose_secret().as_bytes(),
            0o600,
        )?;

        

        println!("Public key: {}", public_key_path.display());
        println!("Private key: {}", private_key_path.display());
        println!("Keys rotated");
        Ok(())
    }

    /// List secret files with their last modified time
    pub fn list_secrets(&self, directory: &Path, file_manager: &FileManager) -> Result<(), SecretError> {
        let secret_files = file_manager.list_encrypted_files(directory)?;
        
        for secret_file in secret_files {
            let file_metadata = fs::metadata(&secret_file)?;
            let last_modified = file_metadata.modified()?.elapsed().map_err(|e| {
                SecretError::Parse(format!("Failed to retrieve file modified date: {}", e))
            })?;
            
            if let Some(file_name) = secret_file.with_extension("").file_name() {
                println!("{} (Last modified {} days ago)", file_name.to_string_lossy(), last_modified.as_secs() / (60 * 60 * 24));
            } else {
                println!("Invalid file name: {}", secret_file.display());
            }
        }
        
        Ok(())
    }

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

        let identity = self.load_identity(key_path)?;
        let content = self.decrypt_file(&identity, secret)?;

        fs.write_atomic(output, content.expose_secret().as_bytes(), 0o640)?;
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
        let identity = self.load_identity(key_path)?;
        fs.create_secure_dir(output, 0o710)?;

        let encrypted_files = fs.list_encrypted_files(source)?;
        if encrypted_files.is_empty() {
            eprintln!("Warning: No .age files found in {}", source.display());
            return Ok(());
        }

        let (success_count, errors) = self.process_batch_decrypt(
            &encrypted_files,
            output,
            &identity,
            force,
            fs,
        )?;

        self.report_batch_results(success_count, errors, output)
    }

    // Private implementation methods
    fn encrypt_to_file(
        &self,
        output: &Path,
        recipient: age::x25519::Recipient,
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

        let encryptor = Encryptor::with_recipients(
            std::iter::once(&recipient as &dyn age::Recipient)
        ).map_err(|e| SecretError::Parse(format!("Failed to create encryptor: {}", e)))?;

        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(content.expose_secret().as_bytes())?;
        writer.finish()?;

        fs.write_atomic(output, &encrypted, 0o640)?;
        Ok(())
    }

    fn decrypt_file(
        &self,
        identity: &age::x25519::Identity,
        source: &Path,
    ) -> Result<SecretString, SecretError> {
        let encrypted = fs::read(source)?;
        let decryptor = Decryptor::new(&encrypted[..])?;

        let mut decrypted = Vec::new();
        let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
        reader.read_to_end(&mut decrypted)?;

        Ok(SecretString::from(String::from_utf8_lossy(&decrypted).to_string()))
    }

    fn load_identity(&self, key_path: &Path) -> Result<age::x25519::Identity, SecretError> {
        let key_content = fs::read_to_string(key_path)?;
        SecretString::from(key_content)
            .expose_secret()
            .trim()
            .parse()
            .map_err(|e| SecretError::Parse(format!("Invalid private key: {}", e)))
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
        let stem = source
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
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
        fs.write_atomic(&output_path, content.expose_secret().as_bytes(), 0o640)?;
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

    // Utility methods
    fn get_key_paths(&self, keys_dir: &Path) -> (PathBuf, PathBuf) {
        let public_key_path = keys_dir.join("secrets.pub");
        let private_key_path = keys_dir.join("secrets.key");
        (public_key_path, private_key_path)
    }

    fn generate_unique_filename(&self, output_dir: &Path) -> Result<PathBuf, SecretError> {
        for _ in 0..100 {  // Prevent infinite loops
            let random_id = self.generate_random_id();
            let path = output_dir.join(&random_id);
            if !path.exists() {
                return Ok(ensure_age_extension(&path));
            }
        }
        Err(SecretError::InvalidPath("Could not generate unique filename".to_string()))
    }

    fn generate_random_id(&self) -> String {
        const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Mix timestamp with stack address for additional entropy
        let addr = (&timestamp as *const u64 as u64) >> 16;
        let mut mixed = (timestamp ^ addr).wrapping_mul(0x5DEECE66D);

        let mut result = [0u8; 10];
        for byte in &mut result {
            *byte = BASE58[(mixed % 58) as usize];
            mixed /= 58;
        }

        String::from_utf8_lossy(&result).to_string()
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Ensure path has .age extension
fn ensure_age_extension(path: &Path) -> PathBuf {
    if path.extension().and_then(|ext| ext.to_str()) == Some("age") {
        path.to_path_buf()
    } else {
        path.with_extension("age")
    }
}