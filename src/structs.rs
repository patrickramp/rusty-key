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
        /// Secure base directory for keys generation and default secret storage
        #[arg(short, long, default_value = "/var/rusty-key")]
        path: PathBuf,
        /// Force overwrite existing keys
        #[arg(long)]
        force: bool,
    },
    /// Encrypt a secret
    Encrypt {
        /// Public key (path or string)
        #[arg(short, long, default_value = "/var/rusty-key/keys/master.pub")]
        recipient: String,
        /// Input secret (use @<filepath> for file check, "<string>" for literal, or - for stdin)
        #[arg(short, long)]
        input: String,
        /// Target encrypted .age file
        #[arg(short, long)]
        target: PathBuf,
        /// Force overwrite existing file
        #[arg(long)]
        force: bool,
    },
    /// Quick secret creation
    Quick {
        /// Public key (path or string)
        #[arg(short, long, default_value = "/var/rusty-key/keys/master.pub")]
        recipient: String,
        /// Input secret (use @<filepath> for file check, "<string>" for literal, or - for stdin)
        #[arg(short, long)]
        input: String,
        /// Secret name 
        #[arg(short, long, default_value = "random_id")]
        name: String,
        /// Target directory for new quick secrets 
        #[arg(short, long, default_value = "/var/rusty-key/secrets")]
        target: String,
        /// Force overwrite existing file
        #[arg(long)]
        force: bool,
    },
    /// Decrypt single secret to stdout
    Show {
        /// Private key file path
        #[arg(short, long, default_value = "/var/rusty-key/keys/master.key")]
        key: PathBuf,
        /// Encrypted source .age file
        #[arg(short, long)]
        source: PathBuf,
    },
    /// List secrets in source directory
    List {
        /// Directory containing .age files
        #[arg(short, long, default_value = "/var/rusty-key/secrets")]
        source: PathBuf,
    },
    /// Decrypt single secret to path
    Decrypt {
        /// Private key file path
        #[arg(short, long, default_value = "/var/rusty-key/keys/master.key")]
        key: PathBuf,
        /// Encrypted source .age file
        #[arg(short, long)]
        source: PathBuf,
        /// Target file path (unencrypted secret data will be written here)
        #[arg(short, long)]
        target: PathBuf,
        /// Force overwrite existing file
        #[arg(long)]
        force: bool,
    },
    /// Decrypt all secrets in source directory to target
    DecryptAll {
        /// Private key file path
        #[arg(short, long, default_value = "/var/rusty-key/keys/master.key")]
        key: PathBuf,
        /// Directory containing .age files
        #[arg(short, long, default_value = "/var/rusty-key/secrets")]
        source: PathBuf,
        /// Target directory (unencrypted secret data will be written here)
        #[arg(short, long, default_value = "/run/rk-cache")]
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


