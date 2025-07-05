use age::secrecy::zeroize::Zeroize;

// Memory-safe container for sensitive data that zeros on drop
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Explicitly zero memory before deallocation
        self.data.zeroize();
    }
}
