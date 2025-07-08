use age::secrecy::zeroize::Zeroize;

/// Memory-safe container for sensitive data that zeros on drop
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(mut data: Vec<u8>) -> Self {
        // Ensure capacity equals length to prevent leftover data in unused capacity
        data.shrink_to_fit();
        Self { data }
    }

    pub fn _from_slice(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn _is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}