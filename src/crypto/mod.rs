mod decryption;
mod encryption;
mod utils;

use crate::errors::SecretError;
use crate::filesystem::FileManager;
use crate::random::generate_base58;

use age::secrecy::{ExposeSecret, SecretString};
use age::{Decryptor, Encryptor};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use utils::{ensure_age_extension, generate_unique_filename, load_identity};

/// Cryptographic operations for age-encrypted secrets
pub struct CryptoManager;
