use std::io;

#[derive(Debug)]
pub enum SecretError {
    Io(io::Error),
    Encrypt(age::EncryptError),
    Decrypt(age::DecryptError),
    Parse(String),
    InvalidPath(String),
    FileExists(String),
    Lock(String),
}

impl From<io::Error> for SecretError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<age::EncryptError> for SecretError {
    fn from(err: age::EncryptError) -> Self {
        Self::Encrypt(err)
    }
}

impl From<age::DecryptError> for SecretError {
    fn from(err: age::DecryptError) -> Self {
        Self::Decrypt(err)
    }
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Encrypt(e) => write!(f, "Encryption failed: {}", e),
            Self::Decrypt(e) => write!(f, "Decryption failed: {}", e),
            Self::Parse(msg) => write!(f, "Parse error: {}", msg),
            Self::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            Self::FileExists(msg) => write!(f, "File exists: {}", msg),
            Self::Lock(msg) => write!(f, "Lock error: {}", msg),
        }
    }
}

impl std::error::Error for SecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Encrypt(e) => Some(e),
            Self::Decrypt(e) => Some(e),
            _ => None,
        }
    }
}
