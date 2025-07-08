// src/filesystem.rs
use crate::errors::SecretError;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

pub struct FileManager;

impl FileManager {
    pub fn new() -> Self {
        Self
    }

    /// Create directory with specified permissions
    pub fn create_dir_all(&self, path: &Path, mode: u32) -> Result<(), SecretError> {
        fs::create_dir_all(path)?;
        self.set_permissions(path, mode)?;
        Ok(())
    }

    /// Write file with atomic operation and file locking
    pub fn write_secure_file(
        &self,
        path: &Path,
        content: &[u8],
        mode: u32,
    ) -> Result<(), SecretError> {
        let _lock = FileLockGuard::new(path)?;

        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, content)?;
        self.set_permissions(&temp_path, mode)?;
        fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// Ensure parent directory exists
    pub fn ensure_parent_dir(&self, path: &Path) -> Result<(), SecretError> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                self.create_dir_all(parent, 0o710)?;
            }
        }
        Ok(())
    }

    /// List secrets in directory
    pub fn list_secrets(&self, source: &Path) -> Result<(), SecretError> {
        for entry in fs::read_dir(source)? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) == Some("age") {
                println!("{}", path.display());
            }
        }
        Ok(())
    }

    /// Read input content with proper handling of different input types
    pub fn read_input_content(&self, input: &str) -> Result<String, SecretError> {
        match input {
            "-" => self.read_stdin(),
            input if input.starts_with('@') => {
                let filename = &input[1..];
                self.read_file_content(filename)
            }
            input if Path::new(input).exists() => self.read_file_content(input),
            input => Ok(input.to_string()),
        }
    }

    /// Parse recipient from string or file path
    pub fn parse_recipient(&self, recipient: &str) -> Result<age::x25519::Recipient, SecretError> {
        let content = match recipient {
            r if r.starts_with('@') => {
                let filename = &r[1..];
                fs::read_to_string(filename).map_err(|e| {
                    SecretError::InvalidPath(format!(
                        "Failed to read recipient file {}: {}",
                        filename, e
                    ))
                })?
            }
            r if Path::new(r).exists() => fs::read_to_string(r).map_err(|e| {
                SecretError::InvalidPath(format!("Failed to read recipient file {}: {}", r, e))
            })?,
            r => r.to_string(),
        };

        content
            .trim()
            .parse()
            .map_err(|e| SecretError::Parse(format!("Invalid recipient: {}", e)))
    }

    // Private helper methods
    fn read_stdin(&self) -> Result<String, SecretError> {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(input.trim_end_matches('\n').to_string())
    }

    fn read_file_content(&self, path: &str) -> Result<String, SecretError> {
        if !Path::new(path).exists() {
            return Err(SecretError::InvalidPath(format!(
                "File not found: {}",
                path
            )));
        }

        let mut content = fs::read_to_string(path)?;
        if content.ends_with('\n') {
            content.pop();
        }
        Ok(content)
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<(), SecretError> {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, permissions)?;
        Ok(())
    }
}

/// File locks
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Global file locks
static FILE_LOCKS: once_cell::sync::Lazy<Arc<Mutex<HashMap<PathBuf, ()>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Normalize path
fn normalize_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// File lock guard
struct FileLockGuard {
    normalized_path: PathBuf,
}

/// File lock guard implementation
impl FileLockGuard {
    fn new(path: &Path) -> Result<Self, SecretError> {
        let normalized_path = normalize_path(path);

        let mut locks = FILE_LOCKS.lock();
        if locks.contains_key(&normalized_path) {
            return Err(SecretError::Lock(format!(
                "File {} is already being processed",
                path.display()
            )));
        }
        locks.insert(normalized_path.clone(), ());

        Ok(Self { normalized_path })
    }
}

/// Drop implementation
impl Drop for FileLockGuard {
    fn drop(&mut self) {
        FILE_LOCKS.lock().remove(&self.normalized_path);
    }
}
