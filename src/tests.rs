/// Unittests for rusty-key
use super::*;
use std::fs;
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
