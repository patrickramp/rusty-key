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
use std::process;

/// Minimal encrypted secret management utility for automated deployments 
/// Encrypts secrets at rest using age, provides clean migration to Vault

/// Main function
fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { path, force } => init_secret_store(&path, force),
        Commands::Encrypt {
            recipient,
            input,
            target,
            force,
        } => encrypt_secret(&recipient, &input, &target, force),
        Commands::Decrypt { key, input } => decrypt_secret(&key, &input),
        Commands::DecryptOne {
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
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
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
    output: &Path,
    force: bool,
) -> Result<(), SecretError> {
    // Check for existing file unless force is specified
    if !force && output.exists() {
        return Err(SecretError::FileExists(format!(
            "Output file {} already exists. Use --force to overwrite",
            output.display()
        )));
    }

    let _lock = FileLockGuard::new(output)?;

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
    let temp_path = output.with_extension("tmp");
    fs::write(&temp_path, encrypted)?;
    set_file_permissions(&temp_path, 0o640)?;
    fs::rename(&temp_path, output)?;

    println!(
        "Encrypted {} bytes to {}",
        secure_content.len(),
        output.display()
    );
    Ok(())
}

/// Decrypt a single secret to stdout with memory zeroing
fn decrypt_secret(key_path: &Path, input_path: &Path) -> Result<(), SecretError> {
    let identity = load_identity(key_path)?;
    let encrypted = fs::read(input_path)?;

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
        .ok_or_else(|| SecretError::Parse("Unable to get target parent directory".to_string()))?;
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
        let entry = entry?;
        let path = entry.path();

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
    if recipient.starts_with('@') {
        // @filename syntax for explicit file reading
        let filename = &recipient[1..];
        if !Path::new(filename).exists() {
            return Err(SecretError::InvalidPath(format!(
                "Recipient file not found: {}",
                filename
            )));
        }
        let content = fs::read_to_string(filename)?;
        content.trim().parse().map_err(|e| {
            SecretError::Parse(format!("Invalid recipient in file {}: {}", filename, e))
        })
    } else if Path::new(recipient).exists() {
        // Existing file path
        let content = fs::read_to_string(recipient)?;
        content
            .trim()
            .parse()
            .map_err(|e| SecretError::Parse(format!("Invalid recipient in file: {}", e)))
    } else {
        // Parse as direct recipient string
        recipient
            .parse()
            .map_err(|e| SecretError::Parse(format!("Invalid recipient string: {}", e)))
    }
}

/// Load age identity from private key file with memory protection
fn load_identity(key_path: &Path) -> Result<age::x25519::Identity, SecretError> {
    let key_content = fs::read_to_string(key_path)?;
    let secure_key = SecretString::from(key_content);

    secure_key
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

/// Read from stdin with proper error handling
fn read_stdin() -> Result<String, SecretError> {
    let mut content = String::new();
    io::stdin().read_to_string(&mut content)?;

    // Remove trailing newline for consistency
    if content.ends_with('\n') {
        content.pop();
    }

    Ok(content)
}

/// Set file permissions (Unix-only)
fn set_file_permissions(path: &Path, mode: u32) -> Result<(), SecretError> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = std::fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn test_init_secret_store() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        init_secret_store(path, false).unwrap();

        assert!(path.join("keys").exists());
        assert!(path.join("secrets").exists());
        assert!(path.join("keys/master.key").exists());
        assert!(path.join("keys/master.pub").exists());
    }

    #[test]
    fn test_init_secret_store_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        init_secret_store(path, false).unwrap();

        // Check directory permissions
        let keys_metadata = fs::metadata(path.join("keys")).unwrap();
        assert_eq!(keys_metadata.permissions().mode() & 0o777, 0o700);

        let secrets_metadata = fs::metadata(path.join("secrets")).unwrap();
        assert_eq!(secrets_metadata.permissions().mode() & 0o777, 0o750);

        // Check file permissions
        let private_key_metadata = fs::metadata(path.join("keys/master.key")).unwrap();
        assert_eq!(private_key_metadata.permissions().mode() & 0o777, 0o600);

        let public_key_metadata = fs::metadata(path.join("keys/master.pub")).unwrap();
        assert_eq!(public_key_metadata.permissions().mode() & 0o777, 0o640);
    }

    #[test]
    fn test_init_secret_store_no_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        // First init should succeed
        init_secret_store(path, false).unwrap();

        // Second init should fail without --force
        let result = init_secret_store(path, false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SecretError::FileExists(_)));
    }

    #[test]
    fn test_init_secret_store_force_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        // First init
        init_secret_store(path, false).unwrap();
        let original_private = fs::read_to_string(path.join("keys/master.key")).unwrap();

        // Second init with force should succeed and create new keys
        init_secret_store(path, true).unwrap();
        let new_private = fs::read_to_string(path.join("keys/master.key")).unwrap();

        assert_ne!(original_private, new_private);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        init_secret_store(path, false).unwrap();

        let pub_key = path.join("keys/master.pub");
        let priv_key = path.join("keys/master.key");
        let encrypted_file = path.join("test.age");

        // Encrypt
        encrypt_secret(
            &pub_key.to_string_lossy(),
            "test-secret",
            &encrypted_file,
            false,
        )
        .unwrap();

        // Decrypt
        let identity = load_identity(&priv_key).unwrap();
        let encrypted = fs::read(&encrypted_file).unwrap();
        let decryptor = Decryptor::new(&encrypted[..]).unwrap();
        let mut decrypted = Vec::new();
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn Identity))
            .unwrap();
        reader.read_to_end(&mut decrypted).unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), "test-secret");
    }

    #[test]
    fn test_encrypt_no_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        init_secret_store(path, false).unwrap();

        let pub_key = path.join("keys/master.pub");
        let encrypted_file = path.join("test.age");

        // First encrypt should succeed
        encrypt_secret(
            &pub_key.to_string_lossy(),
            "test-secret",
            &encrypted_file,
            false,
        )
        .unwrap();

        // Second encrypt should fail without --force
        let result = encrypt_secret(
            &pub_key.to_string_lossy(),
            "test-secret-2",
            &encrypted_file,
            false,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SecretError::FileExists(_)));
    }

    #[test]
    fn test_decrypt_all_secrets() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        init_secret_store(path, false).unwrap();

        let pub_key = path.join("keys/master.pub");
        let priv_key = path.join("keys/master.key");
        let source_dir = path.join("source");
        let target_dir = path.join("target");

        fs::create_dir_all(&source_dir).unwrap();

        // Create multiple encrypted files
        let secrets = vec![
            ("secret1.age", "value1"),
            ("secret2.age", "value2"),
            ("secret3.age", "value3"),
        ];

        for (filename, value) in &secrets {
            let encrypted_file = source_dir.join(filename);
            encrypt_secret(&pub_key.to_string_lossy(), value, &encrypted_file, false).unwrap();
        }

        // Decrypt all
        decrypt_all_secrets(&priv_key, &source_dir, &target_dir, false).unwrap();

        // Verify all files were decrypted
        for (filename, expected_value) in &secrets {
            let stem = filename.strip_suffix(".age").unwrap();
            let decrypted_file = target_dir.join(stem);
            assert!(decrypted_file.exists());

            let decrypted_content = fs::read_to_string(&decrypted_file).unwrap();
            assert_eq!(&decrypted_content, expected_value);

            // Check file permissions
            let metadata = fs::metadata(&decrypted_file).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
        }
    }

    #[test]
    fn test_string_literal_vs_file_input() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path();

        init_secret_store(path, false).unwrap();

        let pub_key = path.join("keys/master.pub");
        let priv_key = path.join("keys/master.key");

        // Test literal string
        let literal_file = path.join("literal.age");
        encrypt_secret(
            &pub_key.to_string_lossy(),
            "literal-secret-value",
            &literal_file,
            false,
        )
        .unwrap();

        // Test file input with @ syntax
        let input_file = path.join("input.txt");
        fs::write(&input_file, "file-secret-value").unwrap();

        let file_encrypted = path.join("file.age");
        encrypt_secret(
            &pub_key.to_string_lossy(),
            &format!("@{}", input_file.display()),
            &file_encrypted,
            false,
        )
        .unwrap();

        // Verify both decrypt correctly
        let identity = load_identity(&priv_key).unwrap();

        // Check literal
        let literal_encrypted = fs::read(&literal_file).unwrap();
        let literal_decryptor = Decryptor::new(&literal_encrypted[..]).unwrap();
        let mut literal_decrypted = Vec::new();
        let mut literal_reader = literal_decryptor
            .decrypt(std::iter::once(&identity as &dyn Identity))
            .unwrap();
        literal_reader.read_to_end(&mut literal_decrypted).unwrap();
        assert_eq!(
            String::from_utf8(literal_decrypted).unwrap(),
            "literal-secret-value"
        );

        // Check file
        let file_encrypted_data = fs::read(&file_encrypted).unwrap();
        let file_decryptor = Decryptor::new(&file_encrypted_data[..]).unwrap();
        let mut file_decrypted = Vec::new();
        let mut file_reader = file_decryptor
            .decrypt(std::iter::once(&identity as &dyn Identity))
            .unwrap();
        file_reader.read_to_end(&mut file_decrypted).unwrap();
        assert_eq!(
            String::from_utf8(file_decrypted).unwrap(),
            "file-secret-value"
        );
    }
}
