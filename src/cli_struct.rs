use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "secret-manager", version = "1.1.0")]
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
        output: PathBuf,
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

