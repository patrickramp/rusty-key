mod structs;
mod errors;
mod locks;

use structs::{Cli, Commands, SecureBuffer};
use errors::SecretError;
use locks::FileLockGuard;

use age::secrecy::{ExposeSecret, SecretString};
use age::{Decryptor, Encryptor, Identity};
use clap::Parser;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Minimal encrypted secret management utility for automated deployments 
/// Encrypts secrets at rest using age, provides clean migration to Vault

/// Main function
fn main() -> Result<(), SecretError> {
    match Cli::parse().command {
        Commands::Init { path, force } => init_secret_store(&path, force),
        Commands::Encrypt {
            recipient,
            input,
            target,
            force,
        } => encrypt_secret(&recipient, &input, &target, force),
        Commands::Quick { recipient, input, name, target, force } => quick_secret(&recipient, &input, &name, &target, force),
        Commands::Show { key, source } => show_secret(&key, &source),
        Commands::List { source } => list_secrets(&source),
        Commands::Decrypt {
            key,
            source,
            target,
            force,
        } => decrypt_secret_to_path(&key, &source, &target, force),
        Commands::DecryptAll {
            key,
            source,
            target,
            force,
        } => decrypt_all_secrets(&key, &source, &target, force),
    }
}

/// Initialize secret store with new age keypair
/// Creates directory structure and generates keys with proper permissions
fn init_secret_store(base_path: &Path, force: bool) -> Result<(), SecretError> {
    let keys_dir = base_path.join("keys");
    let secrets_dir = base_path.join("secrets");
    let private_key_path = keys_dir.join("master.key");
    let public_key_path = keys_dir.join("master.pub");

    // Check for existing keys unless force is specified
    if !force && (private_key_path.exists() || public_key_path.exists()) {
        return Err(SecretError::FileExists(
            "Master keys already exist. Use --force to overwrite".to_string(),
        ));
    }

    // Create directory structure
    fs::create_dir_all(&keys_dir)?;
    fs::create_dir_all(&secrets_dir)?;

    // Generate age keypair
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();

    // Use SecretString for private key to ensure it's zeroed
    let private_key_content = SecretString::from(identity.to_string());

    {
        let _lock = FileLockGuard::new(&private_key_path)?;

        // Write private key with restrictive permissions using atomic operation
        let temp_private = private_key_path.with_extension("tmp");
        fs::write(&temp_private, private_key_content.expose_secret())?;
        set_file_permissions(&temp_private, 0o600)?;
        fs::rename(&temp_private, &private_key_path)?;
    }

    {
        let _lock = FileLockGuard::new(&public_key_path)?;

        // Write public key (readable by owner and group)
        let temp_public = public_key_path.with_extension("tmp");
        fs::write(&temp_public, recipient.to_string())?;
        set_file_permissions(&temp_public, 0o640)?;
        fs::rename(&temp_public, &public_key_path)?;
    }

    // Set directory permissions
    set_file_permissions(&keys_dir, 0o710)?;
    set_file_permissions(&secrets_dir, 0o750)?;

    println!("Secret store initialized at {}", base_path.display());
    println!("Private key: {}", private_key_path.display());
    println!("Public key: {}", public_key_path.display());

    Ok(())
}

/// Encrypt a secret using age with overwrite protection
fn encrypt_secret(
    recipient: &str,
    input: &str,
    target: &Path,
    force: bool,
) -> Result<(), SecretError> {
    // Check target path for .age extension if not provided add it
    let target = if !target.to_string_lossy().ends_with(".age") {
        target.with_extension("age")
    } else {
        target.to_path_buf()
    };

    // Check for existing file unless force is specified
    if !force && target.exists() {
        return Err(SecretError::FileExists(format!(
            "Output file {} already exists. Use --force to overwrite",
            target.display()
        )));
    }

    let _lock = FileLockGuard::new(&target)?;

    let recipient = parse_recipient(recipient)?;
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|e| SecretError::Parse(format!("Failed to create encryptor: {}", e)))?;

    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)?;

    // Read input with proper string literal handling
    let content = read_input_content(input)?;
    let secure_content = SecureBuffer::new(content.into_bytes());

    writer.write_all(secure_content.as_slice())?;
    writer.finish()?;

    // Atomic write to prevent partial files
    let temp_path = target.with_extension("tmp");
    fs::write(&temp_path, encrypted)?;
    set_file_permissions(&temp_path, 0o640)?;
    fs::rename(&temp_path, &target)?;
    println!(
        "Encrypted {} bytes to {}",
        secure_content.len(),
        target.display()
    );
    Ok(())
}

/// Quick secret creation
fn quick_secret(recipient: &str, secret: &str, name: &str, target: &str, force: bool) -> Result<(), SecretError> {
    let target_dir = if name == "random_id" {
        // Generate unique random filename
        loop {
            let random_id = generate_random_id();
            let path = format!("{}/{}.age", target, random_id);
            if !Path::new(&path).exists() {
                break path;
            }
        }
    } else {
        // Use provided name, collision checking handled by encrypt_secret via force flag
        format!("{}/{}.age", target, name)
    };
    
    encrypt_secret(recipient, secret, Path::new(&target_dir), force)?;
    Ok(())
}

/// Decrypt a single secret to stdout with memory zeroing
fn show_secret(key_path: &Path, source: &Path) -> Result<(), SecretError> {
    let identity = load_identity(key_path)?;
    let encrypted = fs::read(source)?;

    let decryptor = Decryptor::new(&encrypted[..])?;
    let mut decrypted = Vec::new();
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn Identity))?;
    reader.read_to_end(&mut decrypted)?;

    // Use SecureBuffer to ensure memory is zeroed
    let secure_decrypted = SecureBuffer::new(decrypted);

    // Write to stdout without trailing newline (for scripts)
    io::stdout().write_all(secure_decrypted.as_slice())?;
    io::stdout().flush()?;

    Ok(())
}

/// List secrets in source directory
fn list_secrets(source: &Path) -> Result<(), SecretError> {
    let entries = fs::read_dir(source).map_err(SecretError::Io)?;
    for entry in entries {
        let path = entry.map_err(SecretError::Io)?.path();
        if path.extension().and_then(|s| s.to_str()) == Some("age") {
            println!("{}", path.display());
        }
    }
    Ok(())
}

/// Decrypt single secret to target path with overwrite protection
fn decrypt_secret_to_path(
    key_path: &Path,
    source: &Path,
    target: &Path,
    force: bool,
) -> Result<(), SecretError> {
    // Check for existing file unless force is specified
    if !force && target.exists() {
        return Err(SecretError::FileExists(format!(
            "Output file {} already exists. Use --force to overwrite",
            target.display()
        )));
    }
    // Ensure target directory exists with proper permissions
    let parent_dir = target
        .parent()
        .ok_or_else(|| SecretError::Parse("Unable to determine target parent directory".to_string()))?;
    if !parent_dir.exists() {
        fs::create_dir_all(parent_dir).map_err(SecretError::Io)?;
        set_file_permissions(parent_dir, 0o710)?;
    }
    // Load age identity and decrypt
    let identity = load_identity(key_path)?;
    decrypt_file_to_path(&identity, source, target)
}

/// Decrypt all .age files with concurrent processing and overwrite protection
fn decrypt_all_secrets(
    key_path: &Path,
    source: &Path,
    target: &Path,
    force: bool,
) -> Result<(), SecretError> {
    let identity = load_identity(key_path)?;

    // Ensure target directory exists with proper permissions
    fs::create_dir_all(target)?;
    set_file_permissions(target, 0o710)?;

    let mut decrypted_count = 0;
    let mut errors = Vec::new();

    // Process all .age files in source directory
    for entry in fs::read_dir(source)? {
        let path = entry?.path();

        if path.extension().and_then(|s| s.to_str()) == Some("age") {
            let stem = path.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
                SecretError::InvalidPath(format!("Invalid filename: {}", path.display()))
            })?;

            let target_path = target.join(stem);

            // Check for existing file unless force is specified
            if !force && target_path.exists() {
                errors.push(format!(
                    "File {} already exists (use --force to overwrite)",
                    target_path.display()
                ));
                continue;
            }

            match decrypt_file_to_path(&identity, &path, &target_path) {
                Ok(()) => {
                    set_file_permissions(&target_path, 0o640)?;
                    decrypted_count += 1;
                }
                Err(e) => {
                    errors.push(format!("Failed to decrypt {}: {}", path.display(), e));
                }
            }
        }
    }

    // Report errors but don't fail completely
    for error in &errors {
        eprintln!("Warning: {}", error);
    }

    if decrypted_count == 0 {
        if errors.is_empty() {
            eprintln!("Warning: No .age files found in {}", source.display());
        } else {
            return Err(SecretError::InvalidPath(
                "No files could be decrypted".to_string(),
            ));
        }
    } else {
        eprintln!(
            "Decrypted {} secrets to {}",
            decrypted_count,
            target.display()
        );
    }

    Ok(())
}

/// Read input content with proper string literal vs file path handling
fn read_input_content(input: &str) -> Result<String, SecretError> {
    if input == "-" {
        // Read from stdin
        read_stdin()
    } else if input.starts_with('@') {
        // @filename syntax for explicit file reading
        let filename = &input[1..];
        if !Path::new(filename).exists() {
            return Err(SecretError::InvalidPath(format!(
                "File not found: {}",
                filename
            )));
        }
        let mut content = fs::read_to_string(filename)?;
        // Remove trailing newline for consistency
        if content.ends_with('\n') {
            content.pop();
        }
        Ok(content)
    } else if Path::new(input).exists() {
        // Existing file path
        let mut content = fs::read_to_string(input)?;
        // Remove trailing newline for consistency
        if content.ends_with('\n') {
            content.pop();
        }
        Ok(content)
    } else {
        // Treat as literal string
        Ok(input.to_string())
    }
}

/// Parse recipient from string or file path
fn parse_recipient(recipient: &str) -> Result<age::x25519::Recipient, SecretError> {
    let content = if recipient.starts_with('@') {
        // @filename syntax for explicit file reading
        let filename = &recipient[1..];
        fs::read_to_string(filename).map_err(|e| {
            SecretError::InvalidPath(format!("Failed to read recipient file {}: {}", filename, e))
        })?
    } else if Path::new(recipient).exists() {
        // Existing file path
        fs::read_to_string(recipient).map_err(|e| {
            SecretError::InvalidPath(format!("Failed to read recipient file {}: {}", recipient, e))
        })?
    } else {
        // Parse as direct recipient string
        recipient.to_string()
    };

    content
        .trim()
        .parse()
        .map_err(|e| SecretError::Parse(format!("Invalid recipient: {}", e)))
}

/// Load age identity from private key file with memory protection
fn load_identity(key_path: &Path) -> Result<age::x25519::Identity, SecretError> {
    SecretString::from(fs::read_to_string(key_path)?)
        .expose_secret()
        .trim()
        .parse()
        .map_err(|e| SecretError::Parse(format!("Invalid private key: {}", e)))
}

/// Decrypt encrypted file to target path with atomic write
fn decrypt_file_to_path(
    identity: &age::x25519::Identity,
    source: &Path,
    target: &Path,
) -> Result<(), SecretError> {
    let _lock = FileLockGuard::new(target)?;

    let encrypted = fs::read(source)?;
    let decryptor = Decryptor::new(&encrypted[..])?;

    let mut decrypted = Vec::new();
    let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn Identity))?;
    reader.read_to_end(&mut decrypted)?;

    // Use SecureBuffer to ensure memory is zeroed
    let secure_decrypted = SecureBuffer::new(decrypted);

    // Atomic write to prevent partial files
    let temp_path = target.with_extension("tmp");
    fs::write(&temp_path, secure_decrypted.as_slice())?;
    fs::rename(&temp_path, target)?;

    Ok(())
}

/// Read from stdin and remove trailing newline
fn read_stdin() -> Result<String, SecretError> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    // Remove trailing newline for consistency
    let output = input.trim_end_matches('\n').to_string();

    Ok(output)
}

/// Set file permissions
fn set_file_permissions(path: &Path, mode: u32) -> Result<(), SecretError> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = std::fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

/// Generate a random 8-digit ID from Unix timestamp and random memory address
fn generate_random_id() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    
    let a = (&t as *const u64 as u64) << 16;
    
    let mixed = (t ^ a).wrapping_mul(1103515245);
    let id = (mixed % 100_000_000) as u32;
    format!("{:08}", id)
}


/// Unittests
#[cfg(test)]
mod tests;