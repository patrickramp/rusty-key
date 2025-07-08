// src/crypto.rs
use crate::{errors::SecretError, filesystem::FileManager, memory::SecureBuffer};
use age::secrecy::{ExposeSecret, SecretString};
use age::{Decryptor, Encryptor, Identity};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_CACHE_DIR: &str = "/run/rk-cache";

pub struct CryptoManager;

impl CryptoManager {
    pub fn new() -> Self {
        Self
    }

    /// Initialize secret store with new age keypair
    pub fn init_secret_store(
        &self,
        keys_dir: &Path,
        secrets_dir: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let public_key_path = keys_dir.join("secrets.pub");
        let private_key_path = keys_dir.join("secrets.key");

        if !force && (private_key_path.exists() || public_key_path.exists()) {
            return Err(SecretError::FileExists(
                "Master keys already exist. Use --force to overwrite".to_string(),
            ));
        }

        fs.create_dir_all(&keys_dir, 0o710)?;
        fs.create_dir_all(&secrets_dir, 0o750)?;

        // Generate new keypair
        let identity = age::x25519::Identity::generate();
        // Write keys to files
        let recipient = identity.to_public();
        fs.write_secure_file(&public_key_path, recipient.to_string().as_bytes(), 0o640)?;
        let private_key_content = SecretString::from(identity.to_string());
        fs.write_secure_file(&private_key_path, private_key_content.expose_secret().as_bytes(), 0o600)?;

        println!("Public key: {}", public_key_path.display());
        println!("Private key: {}", private_key_path.display());
        println!("Secret store initialized at {}", secrets_dir.display());

        Ok(())
    }

    /// Encrypt a secret using age
    pub fn encrypt_secret(
        &self,
        recipient: &str,
        input: &str,
        output: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let output = ensure_age_extension(output);
        let content = fs.read_input_content(input)?;
        let secure_content = SecureBuffer::new(content.into_bytes());
        
        self.encrypt_to_file(&output, recipient, &secure_content, force, fs)?;
        
        println!("Encrypted {} bytes to {}", secure_content.len(), output.display());
        Ok(())
    }

    /// Quick secret creation with optional auto-decrypt
    pub fn quick_secret(
        &self,
        recipient: &str,
        key_path: &Path,
        input: &str,
        name: &str,
        output_dir: &str,
        auto_decrypt: bool,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let output_file = if name == "random_id" {
            self.find_unique_filename(output_dir)?
        } else {
            format!("{}/{}.age", output_dir, name)
        };
        
        let output_path = Path::new(&output_file);
        self.encrypt_secret(recipient, input, output_path, force, fs)?;
        
        if auto_decrypt {
            let cache_dir = Path::new(DEFAULT_CACHE_DIR);
            let cache_file = cache_dir.join(
                output_path.file_stem()
                    .ok_or_else(|| SecretError::InvalidPath("Invalid filename".to_string()))?
            );
            
            // Default key path for auto-decrypt
            self.decrypt_secret_to_path(key_path, output_path, &cache_file, true, fs)?;
            println!("Auto-decrypted to {}", cache_file.display());
        }
        
        Ok(())
    }

    /// Decrypt a single secret to stdout
    pub fn show_secret(
        &self,
        key_path: &Path,
        source: &Path,
    ) -> Result<(), SecretError> {
        let identity = self.load_identity(key_path)?;
        let secure_content = self.decrypt_file(&identity, source)?;
        
        io::stdout().write_all(secure_content.as_slice())?;
        io::stdout().flush()?;
        
        Ok(())
    }

    /// Decrypt single secret to output path
    pub fn decrypt_secret_to_path(
        &self,
        key_path: &Path,
        source: &Path,
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
        let secure_content = self.decrypt_file(&identity, source)?;
        
        fs.ensure_parent_dir(output)?;
        fs.write_secure_file(output, secure_content.as_slice(), 0o640)?;
        
        Ok(())
    }

    /// Decrypt all secrets with improved error handling
    pub fn decrypt_all_secrets(
        &self,
        key_path: &Path,
        source: &Path,
        output: &Path,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let identity = self.load_identity(key_path)?;
        fs.create_dir_all(output, 0o710)?;

        let (success_count, errors) = self.process_all_age_files(
            source, output, &identity, force, fs
        )?;

        self.report_batch_results(success_count, errors, output)?;
        Ok(())
    }

    // Private helper methods
    fn encrypt_to_file(
        &self,
        output: &Path,
        recipient: &str,
        content: &SecureBuffer,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        if !force && output.exists() {
            return Err(SecretError::FileExists(format!(
                "Output file {} already exists. Use --force to overwrite",
                output.display()
            )));
        }

        let recipient = fs.parse_recipient(recipient)?;
        let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| SecretError::Parse(format!("Failed to create encryptor: {}", e)))?;

        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(content.as_slice())?;
        writer.finish()?;

        fs.write_secure_file(output, &encrypted, 0o640)?;
        Ok(())
    }

    fn decrypt_file(
        &self,
        identity: &age::x25519::Identity,
        source: &Path,
    ) -> Result<SecureBuffer, SecretError> {
        let encrypted = fs::read(source)?;
        let decryptor = Decryptor::new(&encrypted[..])?;
        
        let mut decrypted = Vec::new();
        let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn Identity))?;
        reader.read_to_end(&mut decrypted)?;
        
        Ok(SecureBuffer::new(decrypted))
    }

    fn load_identity(&self, key_path: &Path) -> Result<age::x25519::Identity, SecretError> {
        SecretString::from(fs::read_to_string(key_path)?)
            .expose_secret()
            .trim()
            .parse()
            .map_err(|e| SecretError::Parse(format!("Invalid private key: {}", e)))
    }

    fn find_unique_filename(&self, output_dir: &str) -> Result<String, SecretError> {
        loop {
            let random_id = self.generate_random_id();
            let path = format!("{}/{}.age", output_dir, random_id);
            if !Path::new(&path).exists() {
                return Ok(path);
            }
        }
    }

    fn generate_random_id(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let addr = (&timestamp as *const u64 as u64) << 16;
        let mixed = (timestamp ^ addr).wrapping_mul(1103515245);
        let id = (mixed % 100_000_000) as u32;
        
        format!("{:08}", id)
    }

    fn process_all_age_files(
        &self,
        source: &Path,
        output: &Path,
        identity: &age::x25519::Identity,
        force: bool,
        fs: &FileManager,
    ) -> Result<(usize, Vec<String>), SecretError> {
        let mut success_count = 0;
        let mut errors = Vec::new();

        for entry in fs::read_dir(source)? {
            let path = entry?.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("age") {
                match self.process_single_age_file(&path, output, identity, force, fs) {
                    Ok(()) => success_count += 1,
                    Err(e) => errors.push(format!("Failed to decrypt {}: {}", path.display(), e)),
                }
            }
        }

        Ok((success_count, errors))
    }

    fn process_single_age_file(
        &self,
        source: &Path,
        output_dir: &Path,
        identity: &age::x25519::Identity,
        force: bool,
        fs: &FileManager,
    ) -> Result<(), SecretError> {
        let stem = source.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| SecretError::InvalidPath(format!("Invalid filename: {}", source.display())))?;

        let output_path = output_dir.join(stem);

        if !force && output_path.exists() {
            return Err(SecretError::FileExists(format!(
                "File {} already exists (use --force to overwrite)",
                output_path.display()
            )));
        }

        let secure_content = self.decrypt_file(identity, source)?;
        fs.write_secure_file(&output_path, secure_content.as_slice(), 0o640)?;
        
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

        if success_count == 0 {
            if errors.is_empty() {
                eprintln!("Warning: No .age files found");
            } else {
                return Err(SecretError::InvalidPath("No files could be decrypted".to_string()));
            }
        } else {
            eprintln!("Decrypted {} secrets to {}", success_count, output.display());
        }

        Ok(())
    }
}

fn ensure_age_extension(output: &Path) -> std::path::PathBuf {
    if output.to_string_lossy().ends_with(".age") {
        output.to_path_buf()
    } else {
        output.with_extension("age")
    }
}