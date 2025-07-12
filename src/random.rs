// src/random.rs
use age::secrecy::{SecretString, zeroize::Zeroize};
use getrandom::{Error, fill};

// Precomputed base58 alphabet
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
// Precomputed rejection threshold for Base58
const REJECTION_THRESHOLD: u32 = (u32::MAX / 58) * 58;

/// Generate cryptographically secure Base58 string using direct OS entropy
pub fn generate_base58(length: usize) -> Result<SecretString, Error> {
    let mut result = Vec::with_capacity(length);

    // Generate random bytes
    for _ in 0..length {
        let idx = loop {
            let mut bytes = [0u8; 4];
            fill(&mut bytes)?;
            let r = u32::from_ne_bytes(bytes);

            // Zeroize the random bytes immediately after use
            bytes.zeroize();

            if r < REJECTION_THRESHOLD {
                break (r % 58) as usize;
            }
        };
        // Append base58 character to result
        result.push(BASE58_ALPHABET[idx]);
    }
    // Convert to UTF-8 SecretString (Safe to unwrap)
    Ok(SecretString::from(String::from_utf8(result).unwrap()))
}
