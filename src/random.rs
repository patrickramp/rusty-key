// src/random.rs
use age::secrecy::{SecretString, zeroize::Zeroize};
use getrandom::fill;
use crate::errors::SecretError;

// Precomputed base94 alphabet
const BASE94_NO_SPACE: &[u8] = b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
// Precomputed base85 alphabet
const BASE85_Z85_ALPHABET: &[u8] = b".-:+=^!/*?&<>()[]{}@%$#0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
// Precomputed base64 alphabet
const BASE64_URL_ALPHABET: &[u8] = b"-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
// Precomputed base58 alphabet
const BASE58_BTC_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
// Precomputed base36 alphabet
const BASE36_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
// Precomputed base32 alphabet
const BASE32_ALPHABET: &[u8] = b"234567ABCDEFGHIJKLMNOPQRSTUVWXYZ";
// Precomputed base16 (hex) alphabet
const BASE16_HEX_ALPHABET: &[u8] = b"0123456789ABCDEF";

/// Generate cryptographically secure string using direct OS entropy
pub fn new_secret_string(length: usize, base: u64) -> Result<SecretString, SecretError> {
    let alphabet = match base {
        95 => BASE94_NO_SPACE,
        85 => BASE85_Z85_ALPHABET,
        64 => BASE64_URL_ALPHABET,
        58 => BASE58_BTC_ALPHABET,
        36 => BASE36_ALPHABET,
        32 => BASE32_ALPHABET,
        16 => BASE16_HEX_ALPHABET,
        _ => return Err(SecretError::Parse("Invalid base".to_string())),
    };

    let rejection_threshold: u64 = (u64::MAX / base) * base;
    
    // 2x Overallocated buffer do handle rejection threshold
    let buffer_size = length * 8 * 2;
    let mut rng_buffer = vec![0u8; buffer_size];
    fill(&mut rng_buffer).map_err(|e| SecretError::Parse(format!("Failed to fill random buffer: {}", e)))?;
    
    let mut result = Vec::with_capacity(length);
    let mut chunks = rng_buffer.chunks_exact(8); // 8 bytes for u64
    
    while result.len() < length {
        if let Some(chunk) = chunks.next() {
            let bytes: [u8; 8] = chunk.try_into().unwrap();
            let r = u64::from_ne_bytes(bytes);
            if r < rejection_threshold {
                result.push(alphabet[(r % base) as usize]);
            }
        } else {
            return Err(SecretError::Parse("Insufficient random buffer".to_string()));
        }
    }
    
    rng_buffer.zeroize();
    Ok(SecretString::from(String::from_utf8(result).unwrap()))
}