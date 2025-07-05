use std::io;

// Custom error type for clean error handling
#[derive(Debug)]
pub enum SecretError {
    Io(io::Error),
    EncryptAge(age::EncryptError),
    DecryptAge(age::DecryptError),
    Parse(String),
    InvalidPath(String),
    FileExists(String),
    LockError(String),
}

impl From<io::Error> for SecretError {
    fn from(err: io::Error) -> Self {
        SecretError::Io(err)
    }
}

impl From<age::EncryptError> for SecretError {
    fn from(err: age::EncryptError) -> Self {
        SecretError::EncryptAge(err)
    }
}

impl From<age::DecryptError> for SecretError {
    fn from(err: age::DecryptError) -> Self {
        SecretError::DecryptAge(err)
    }
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::Io(e) => write!(f, "IO error: {}", e),
            SecretError::EncryptAge(e) => write!(f, "Age encryption error: {}", e),
            SecretError::DecryptAge(e) => write!(f, "Age decryption error: {}", e),
            SecretError::Parse(e) => write!(f, "Parse error: {}", e),
            SecretError::InvalidPath(e) => write!(f, "Invalid path: {}", e),
            SecretError::FileExists(e) => write!(f, "File exists: {}", e),
            SecretError::LockError(e) => write!(f, "Lock error: {}", e),
        }
    }
}

impl std::error::Error for SecretError {}
