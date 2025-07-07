use age::secrecy::zeroize::Zeroize;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "secret-manager", version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize secret store with new keypair
    Init {
        /// Base directory for keys and secrets
        #[arg(short, long, default_value = "/var/rusty-key")]
        path: PathBuf,
        /// Force overwrite existing keys
        #[arg(long)]
        force: bool,
    },
    /// Encrypt a secret
    Encrypt {
        /// Public key file or recipient string
        #[arg(short, long)]
        recipient: String,
        /// Input file (use - for stdin)
        #[arg(short, long)]
        input: String,
        /// Output file path
        #[arg(short, long)]
        target: PathBuf,
        /// Force overwrite existing file
        #[arg(long)]
        force: bool,
    },
    /// Decrypt a secret to stdout
    Decrypt {
        /// Private key file path
        #[arg(short, long)]
        key: PathBuf,
        /// Encrypted input file
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Decrypt single secret to path
    DecryptOne {
        /// Private key file path
        #[arg(short, long)]
        key: PathBuf,
        /// Encrypted input file
        #[arg(short, long)]
        source: PathBuf,
        /// Output file path
        #[arg(short, long)]
        target: PathBuf,
        /// Force overwrite existing file
        #[arg(long)]
        force: bool,
    },
    /// Decrypt all secrets in directory to tmpfs
    DecryptAll {
        /// Private key file path
        #[arg(short, long)]
        key: PathBuf,
        /// Directory containing .age files
        #[arg(short, long)]
        source: PathBuf,
        /// Target directory (should be tmpfs)
        #[arg(short, long)]
        target: PathBuf,
        /// Force overwrite existing files
        #[arg(long)]
        force: bool,
    },
}

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
