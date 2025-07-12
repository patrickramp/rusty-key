// src/filesystem.rs
use crate::errors::SecretError;

use parking_lot::Mutex;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Global file locks to prevent concurrent access
static FILE_LOCKS: once_cell::sync::Lazy<Arc<Mutex<HashMap<PathBuf, ()>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// File system operations with security-focused design
pub struct FileManager;

impl FileManager {
    pub fn new() -> Self {
        Self
    }

    /// Create directory with secure permissions
    pub fn create_secure_dir(&self, path: &Path, mode: u32) -> Result<(), SecretError> {
        if path.exists() {
            self.verify_dir_permissions(path, mode)?;
            return Ok(());
        }
        // Create directory
        fs::create_dir_all(path)?;
        self.set_permissions(path, mode)?;
        Ok(())
    }

    /// Write file atomically with exclusive lock
    pub fn write_atomic(
        &self,
        path: &Path,
        content: &[u8],
        file_mode: u32,
        dir_mode: u32,
    ) -> Result<(), SecretError> {
        let _lock = FileLockGuard::acquire(path)?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            self.create_secure_dir(parent, dir_mode)?;
        }

        // Write to temporary file first
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, content)?;
        self.set_permissions(&temp_path, file_mode)?;

        // Atomic rename
        fs::rename(&temp_path, path)?;
        Ok(())
    }

    /// List encrypted files (.age extension)
    pub fn list_encrypted_files(&self, dir: &Path) -> Result<Vec<PathBuf>, SecretError> {
        let mut files = Vec::new();

        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) == Some("age") {
                files.push(path);
            }
        }

        Ok(files)
    }

    /// Parse content from various input sources
    pub fn parse_content(&self, input: &str) -> Result<String, SecretError> {
        let content = match input {
            "-" => self.read_stdin()?,
            input if input.starts_with('@') => {
                let path = &input[1..];
                self.read_file_content(Path::new(path))?
            }
            input if Path::new(input).exists() => self.read_file_content(Path::new(input))?,
            input => input.to_string(),
        };

        Ok(content.trim().to_string())
    }

    /// Parse age recipient from input
    pub fn parse_recipient(&self, input: &str) -> Result<age::x25519::Recipient, SecretError> {
        let content = self.parse_content(input)?;
        content
            .parse()
            .map_err(|e| SecretError::Parse(format!("Invalid recipient: {}", e)))
    }

    /// Securely remove file
    pub fn _secure_remove(&self, path: &Path) -> Result<(), SecretError> {
        if !path.exists() {
            return Err(SecretError::InvalidPath(format!(
                "File does not exist: {}",
                path.display()
            )));
        }

        fs::remove_file(path)?;
        Ok(())
    }

    // Private helper methods
    fn read_stdin(&self) -> Result<String, SecretError> {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        Ok(buffer.trim_end_matches('\n').to_string())
    }

    pub fn read_file_content(&self, path: &Path) -> Result<String, SecretError> {
        if !path.exists() {
            return Err(SecretError::InvalidPath(format!(
                "File not found: {}",
                path.display()
            )));
        }

        fs::read_to_string(path).map_err(|e| {
            SecretError::InvalidPath(format!("Failed to read {}: {}", path.display(), e))
        })
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<(), SecretError> {
        let permissions = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, permissions)?;
        Ok(())
    }

    fn verify_dir_permissions(&self, path: &Path, mode: u32) -> Result<(), SecretError> {
        let metadata = fs::metadata(path).map_err(|_| {
            SecretError::InvalidPath(format!("Cannot read permissions for {}", path.display()))
        })?;

        let current_mode = metadata.permissions().mode() & 0o777;

        if current_mode & !mode != 0 {
            eprintln!(
                "[WARNING] Directory {} has permissive mode {:o} (expected {:o})",
                path.display(),
                current_mode,
                mode
            );
        }
        Ok(())
    }
}

impl Default for FileManager {
    fn default() -> Self {
        Self::new()
    }
}

/// File lock guard for atomic operations
struct FileLockGuard {
    path: PathBuf,
}

impl FileLockGuard {
    fn acquire(path: &Path) -> Result<Self, SecretError> {
        let normalized_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

        let mut locks = FILE_LOCKS.lock();
        if locks.contains_key(&normalized_path) {
            return Err(SecretError::Lock(format!(
                "File {} is already locked",
                path.display()
            )));
        }

        locks.insert(normalized_path.clone(), ());
        Ok(Self {
            path: normalized_path,
        })
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        FILE_LOCKS.lock().remove(&self.path);
    }
}
