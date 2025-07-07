use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::errors;
use errors::SecretError;

/// Global file lock manager to prevent concurrent writes
static FILE_LOCKS: once_cell::sync::Lazy<Arc<Mutex<HashMap<PathBuf, ()>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Acquire exclusive lock for file operations
pub fn acquire_file_lock(path: &Path) -> Result<(), SecretError> {
    let canonical_path = path
        .canonicalize()
        .or_else(|_| Ok::<PathBuf, SecretError>(path.to_path_buf()))?;

    let mut locks = FILE_LOCKS.lock();
    if locks.contains_key(&canonical_path) {
        return Err(SecretError::LockError(format!(
            "File {} is already being processed",
            path.display()
        )));
    }
    locks.insert(canonical_path, ());
    Ok(())
}

/// Release file lock
pub fn release_file_lock(path: &Path) {
    if let Ok(canonical_path) = path.canonicalize() {
        FILE_LOCKS.lock().remove(&canonical_path);
    } else {
        FILE_LOCKS.lock().remove(path);
    }
}

/// RAII file lock guard
pub struct FileLockGuard<'a> {
    path: &'a Path,
}

impl<'a> FileLockGuard<'a> {
    pub fn new(path: &'a Path) -> Result<Self, SecretError> {
        acquire_file_lock(path)?;
        Ok(Self { path })
    }
}

impl<'a> Drop for FileLockGuard<'a> {
    fn drop(&mut self) {
        release_file_lock(self.path);
    }
}
