use clap::{Parser, Subcommand};
use std::path::PathBuf;

const DEFAULT_KEYS_DIR: &str = "/var/rusty-key/keys";
const DEFAULT_SECRETS_DIR: &str = "/var/rusty-key/secrets";
const DEFAULT_PRIVATE_KEY: &str = "/var/rusty-key/keys/secrets.key";
const DEFAULT_PUBLIC_KEY: &str = "/var/rusty-key/keys/secrets.pub";
const DEFAULT_CACHE_DIR: &str = "/run/rk-cache";

#[derive(Parser)]
#[command(name = "secret-manager", version = "0.2.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize secret store with new keypair
    Init {
        /// Output directory for new key creation
        #[arg(short, long, default_value = DEFAULT_KEYS_DIR)]
        keys_dir: PathBuf,
        /// Output directory for encrypted secrets
        #[arg(short, long, default_value = DEFAULT_SECRETS_DIR)]
        secrets_dir: PathBuf,
        /// Force overwrite existing keys
        #[arg(long)]
        force: bool,
    },

    /// Encrypt a secret to specified file
    Encrypt {
        /// Public key path or string
        #[arg(short, long, default_value = DEFAULT_PUBLIC_KEY)]
        recipient: String,
        /// Input (@file, - for stdin, or literal)
        #[arg(short, long)]
        input: String,
        /// Output encrypted file path
        #[arg(short, long)]
        output: PathBuf,
        /// Force overwrite existing file
        #[arg(long)]
        force: bool,
    },

    /// Quick encrypt with auto-naming and optional decrypt
    Quick {
        /// Public key path or string
        #[arg(short, long, default_value = DEFAULT_PUBLIC_KEY)]
        recipient: String,
        /// Private key file path
        #[arg(short, long, default_value = DEFAULT_PRIVATE_KEY)]
        key_path: PathBuf,
        /// Input (@file, - for stdin, or literal)
        #[arg(short, long)]
        input: String,
        /// Secret name (use "random_id" for generated)
        #[arg(short, long, default_value = "random_id")]
        name: String,
        /// Output directory for encrypted secrets
        #[arg(short, long, default_value = DEFAULT_SECRETS_DIR)]
        output: String,
        /// Auto-decrypt to cache after encryption
        #[arg(short, long)]
        auto_decrypt: bool,
        /// Force overwrite existing file
        #[arg(long)]
        force: bool,
    },

    /// Decrypt and display secret to stdout
    Show {
        /// Private key file path
        #[arg(short, long, default_value = DEFAULT_PRIVATE_KEY)]
        key: PathBuf,
        /// Encrypted source file
        #[arg(short, long)]
        source: PathBuf,
    },

    /// List secrets in directory
    List {
        /// Directory containing .age files
        #[arg(short, long, default_value = DEFAULT_SECRETS_DIR)]
        source: PathBuf,
    },

    /// Decrypt secret to file
    Decrypt {
        /// Private key file path
        #[arg(short, long, default_value = DEFAULT_PRIVATE_KEY)]
        key: PathBuf,
        /// Encrypted source file
        #[arg(short, long)]
        source: PathBuf,
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
        /// Force overwrite existing file
        #[arg(long)]
        force: bool,
    },

    /// Decrypt all secrets to directory
    DecryptAll {
        /// Private key file path
        #[arg(short, long, default_value = DEFAULT_PRIVATE_KEY)]
        key: PathBuf,
        /// Directory containing .age files
        #[arg(short, long, default_value = DEFAULT_SECRETS_DIR)]
        source: PathBuf,
        /// Output directory for decrypted files
        #[arg(short, long, default_value = DEFAULT_CACHE_DIR)]
        output: PathBuf,
        /// Force overwrite existing files
        #[arg(long)]
        force: bool,
    },
}
