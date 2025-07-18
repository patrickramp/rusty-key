// src/filesystem.rs
use crate::errors::SecretError;

use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

/// File system operations with security-focused design
pub struct FileManager;

impl FileManager {
    /// Write file atomically with lock
    pub fn write_atomic(
        &self,
        path: &Path,
        content: &[u8],
        file_mode: u32,
        dir_mode: u32,
    ) -> Result<(), SecretError> {
        // Acquire lock
        let _lock = FileLockGuard::acquire(path)?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            self.create_secure_dir(parent, dir_mode)?;
        }

        // Write to temporary file first
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, content)?;
        set_permissions(&temp_path, file_mode)?;

        // Rename to final path
        fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// List files (.age extension) in directory
    pub fn list_age_files(&self, dir: &Path) -> Result<Vec<PathBuf>, SecretError> {
        // Verify source directory exists
        if !dir.exists() {
            return Err(SecretError::FileExists(format!(
                "Source directory {} does not exist",
                dir.display()
            )));
        }

        // Collect files with .age extension to vector
        let mut files = Vec::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) == Some("age") {
                files.push(path);
            }
        }

        if files.is_empty() {
            return Err(SecretError::FileExists(format!(
                "No .age files found in {}",
                dir.display()
            )));
        }

        Ok(files)
    }

    /// Parse age recipient from input
    pub fn parse_recipient(&self, input: &str) -> Result<age::x25519::Recipient, SecretError> {
        let content = self.parse_content(input)?;
        age::x25519::Recipient::from_str(&content)
            .map_err(|e| SecretError::Parse(format!("Invalid recipient: {}", e)))
    }

    /// Parse Identity from file
    pub fn parse_identity_file(&self, input: &Path) -> Result<age::x25519::Identity, SecretError> {
        let key_content = read_file_content(input)?;
        age::x25519::Identity::from_str(&key_content)
            .map_err(|_| SecretError::Parse("Invalid private key".to_string()))
    }

    /// Parse content from various input sources
    pub fn parse_content(&self, input: &str) -> Result<String, SecretError> {
        let content = match input {
            "-" => read_stdin()?,
            input if input.starts_with('@') => {
                let path = &input[1..];
                read_file_content(Path::new(path))?
            }
            input if Path::new(input).exists() => read_file_content(Path::new(input))?,
            input => input.to_string(),
        };

        Ok(content.trim().to_string())
    }

    /// Create directory with secure permissions
    pub fn create_secure_dir(&self, path: &Path, mode: u32) -> Result<(), SecretError> {
        if path.exists() {
            verify_path_permissions(path, mode)?;
            return Ok(());
        }
        // Create directory
        fs::create_dir_all(path)?;
        set_permissions(path, mode)?;
        Ok(())
    }

    /// Check if path exists (dir or file) and check for force
    pub fn overwrite_check(&self, path: &Path, force: bool) -> Result<(), SecretError> {
        if !force && path.exists() {
            return Err(SecretError::FileExists(format!(
                "Output file {} already exists. Use --force to overwrite",
                path.display()
            )));
        }
        Ok(())
    }

    /// Securely remove file with lock
    pub fn _secure_remove(&self, path: &Path) -> Result<(), SecretError> {
        // Acquire lock
        let _lock = FileLockGuard::acquire(path)?;

        // Check if file is writable
        match OpenOptions::new().write(true).open(path) {
            Ok(file) => {
                // Best effort file sync to disk
                let _ = file.sync_all();
            }
            Err(e) => {
                return Err(SecretError::InvalidPath(format!(
                    "Failed to open file {} for deletion: {}",
                    path.display(),
                    e
                )));
            }
        }

        // Remove file 
        fs::remove_file(path).map_err(|e| {
            SecretError::InvalidPath(format!("Failed to remove {}: {}", path.display(), e))
        })?;

        Ok(())
    }
}

/// Private helper functions

// Read content from stdin
fn read_stdin() -> Result<String, SecretError> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    Ok(buffer.trim_end_matches('\n').to_string())
}

// Read content from file
fn read_file_content(path: &Path) -> Result<String, SecretError> {
    if !path.exists() {
        return Err(SecretError::InvalidPath(format!(
            "File not found: {}",
            path.display()
        )));
    }

    fs::read_to_string(path)
        .map_err(|e| SecretError::InvalidPath(format!("Failed to read {}: {}", path.display(), e)))
}

// Set file permissions
fn set_permissions(path: &Path, mode: u32) -> Result<(), SecretError> {
    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

// Verify directory permissions
fn verify_path_permissions(path: &Path, mode: u32) -> Result<(), SecretError> {
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

/// Global file locks to prevent concurrent access
static FILE_LOCKS: Lazy<DashMap<PathBuf, ()>> = Lazy::new(DashMap::new);

/// File lock guard for atomic operations
struct FileLockGuard {
    path: PathBuf,
}

impl FileLockGuard {
    /// Immediately try to acquire a lock on the given path
    pub fn acquire(path: &Path) -> Result<Self, SecretError> {
        Self::try_acquire(path, Some(Duration::from_secs(3)))
    }

    /// Try to acquire a lock with optional timeout
    pub fn try_acquire(path: &Path, timeout: Option<Duration>) -> Result<Self, SecretError> {
        // Handle non-existent paths gracefully by creating parent directories
        let normalized_path = Self::normalize_path(path)?;

        let start_time = Instant::now();
        let mut backoff = Duration::from_millis(50); // Start with shorter backoff
        
        loop {
            // Attempt to insert the lock atomically
            if FILE_LOCKS.insert(normalized_path.clone(), ()).is_none() {
                return Ok(Self {
                    path: normalized_path,
                });
            }

            // Check timeout before sleeping
            if let Some(max_duration) = timeout {
                if start_time.elapsed() >= max_duration {
                    return Err(SecretError::Lock(format!(
                        "Timeout: could not acquire lock on {} within {:?}",
                        normalized_path.display(),
                        max_duration
                    )));
                }
            }

            // Exponential backoff with jitter to reduce thundering herd
            thread::sleep(backoff);
            backoff = std::cmp::min(backoff * 2, Duration::from_millis(1000));
        }
    }

    /// Normalize path handling both existing and non-existing paths
    fn normalize_path(path: &Path) -> Result<PathBuf, SecretError> {
        // Try canonicalize first for existing paths
        if let Ok(canonical) = path.canonicalize() {
            return Ok(canonical);
        }

        // For non-existent paths, manually resolve to absolute path
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| SecretError::Lock(format!("Failed to get current directory: {}", e)))?
                .join(path)
        };

        // Clean up the path (remove . and .. components)
        let mut components = Vec::new();
        for component in absolute.components() {
            match component {
                std::path::Component::CurDir => continue,
                std::path::Component::ParentDir => {
                    if !components.is_empty() {
                        components.pop();
                    }
                }
                _ => components.push(component),
            }
        }

        Ok(components.iter().collect())
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        FILE_LOCKS.remove(&self.path);
        // Consider logging failed removals in debug builds
        #[cfg(debug_assertions)]
        if FILE_LOCKS.contains_key(&self.path) {
            eprintln!("Warning: Failed to remove lock for {}", self.path.display());
        }
    }
}