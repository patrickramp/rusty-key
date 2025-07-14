mod decryption;
mod encryption;
mod utils;

use crate::errors::SecretError;
use crate::filesystem::FileManager;
use crate::random::new_secret_string;

use utils::ensure_age_extension;

/// Cryptographic operations for age-encrypted secrets
pub struct CryptoManager;
