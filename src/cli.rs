use clap::{Parser, Subcommand};
use std::path::PathBuf;

// Default paths - can be overridden by environment variables
const DEFAULT_KEYS_DIR: &str = "/var/rusty-key/keys";
const DEFAULT_SECRETS_DIR: &str = "/var/rusty-key/secrets";
const DEFAULT_PRIVATE_KEY: &str = "/var/rusty-key/keys/secrets.key";
const DEFAULT_PUBLIC_KEY: &str = "/var/rusty-key/keys/secrets.pub";
const DEFAULT_CACHE_DIR: &str = "/run/rk-cache";

/// Helper function to get environment variable or fall back to default
fn env_or_default(env_var: &str, default: &str) -> &str {
    &std::env::var(env_var).unwrap_or_else(|_| default.to_string())
}

#[derive(Parser)]
#[command(
    name = "rusty-key",
    about = "Encrypted secrets manager using age encryption",
    version = "0.2.0",
    long_about = "A secure secrets manager built with Rust, using age encryption for \
                  protecting sensitive data with public key cryptography."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize new secret store and generate keypair
    Init {
        /// Directory for key storage
        /// Environment: RUSTY_KEY_KEYS_DAULT_KEYS_DIR)IR
        #[arg(
            short = 'k',
            long = "keys-dir",
            default_value = DEFAULT_KEYS_DIR
        )]
        keys_dir: PathBuf,

        /// Directory for encrypted secrets storage
        /// Environment: RUSTY_KEY_SECRETS_DIR
        #[arg(
            short = 's',
            long = "secrets-dir",
            default_value = env_or_default("RUSTY_KEY_SECRETS_DIR", DEFAULT_SECRETS_DIR).into()
        )]
        secrets_dir: PathBuf,

        /// Force overwrite existing keys and directories
        #[arg(long)]
        force: bool,
    },

    /// Encrypt a secret to specified file
    Encrypt {
        /// Public key for encryption (@file, - for stdin, or literal key)
        /// Environment: RUSTY_KEY_PUBLIC_KEY
        #[arg(
            short = 'r',
            long = "recipient",
            default_value = env_or_default("RUSTY_KEY_PUBLIC_KEY", DEFAULT_PUBLIC_KEY).into()
        )]
        recipient: String,

        /// Input source (@file, - for stdin, or literal value)
        #[arg(short = 'i', long = "input")]
        input: String,

        /// Output path for encrypted file
        #[arg(short = 'o', long = "output")]
        output: PathBuf,

        /// Force overwrite existing output file
        #[arg(long)]
        force: bool,
    },

    /// Quick encrypt with auto-naming and optional auto-decrypt
    Quick {
        /// Public key for encryption (@file, - for stdin, or literal key)
        /// Environment: RUSTY_KEY_PUBLIC_KEY
        #[arg(
            short = 'r',
            long = "recipient",
            default_value = env_or_default("RUSTY_KEY_PUBLIC_KEY", DEFAULT_PUBLIC_KEY).into()
        )]
        recipient: String,

        /// Private key file path for optional auto-decrypt
        /// Environment: RUSTY_KEY_PRIVATE_KEY
        #[arg(
            short = 'k',
            long = "key-path",
            default_value = env_or_default("RUSTY_KEY_PRIVATE_KEY", DEFAULT_PRIVATE_KEY).into()
        )]
        key_path: PathBuf,

        /// Input source (@file, - for stdin, or literal value)
        #[arg(short = 'i', long = "input")]
        input: String,

        /// Secret identifier name
        #[arg(short = 'n', long = "name", default_value = "random_id")]
        name: String,

        /// Output directory for encrypted secrets
        /// Environment: RUSTY_KEY_SECRETS_DIR
        #[arg(
            short = 'o',
            long = "output",
            default_value = env_or_default("RUSTY_KEY_SECRETS_DIR", DEFAULT_SECRETS_DIR).into()
        )]
        output: PathBuf,

        /// Cache directory for decrypted secrets
        /// Environment: RUSTY_KEY_CACHE_DIR
        #[arg(
            short = 'c',
            long = "cache",
            default_value = env_or_default("RUSTY_KEY_CACHE_DIR", DEFAULT_CACHE_DIR).into()
        )]
        cache: PathBuf,

        /// Automatically decrypt secret to cache directory after encryption
        #[arg(short = 'a', long = "auto-decrypt")]
        auto_decrypt: bool,

        /// Force overwrite existing files
        #[arg(long)]
        force: bool,
    },

    /// Decrypt and display a single secret to stdout
    Show {
        /// Private key file path
        /// Environment: RUSTY_KEY_PRIVATE_KEY
        #[arg(
            short = 'k',
            long = "key",
            default_value = env_or_default("RUSTY_KEY_PRIVATE_KEY", DEFAULT_PRIVATE_KEY).into()
        )]
        key: PathBuf,

        /// Encrypted source file path
        #[arg(short = 's', long = "source")]
        source: PathBuf,
    },

    /// List all encrypted .age secrets in directory
    List {
        /// Directory containing .age encrypted files
        /// Environment: RUSTY_KEY_SECRETS_DIR
        #[arg(
            short = 's',
            long = "source",
            default_value = env_or_default("RUSTY_KEY_SECRETS_DIR", DEFAULT_SECRETS_DIR).into()
        )]
        source: PathBuf,
    },

    /// Decrypt single secret to specified file
    Decrypt {
        /// Private key file path
        /// Environment: RUSTY_KEY_PRIVATE_KEY
        #[arg(
            short = 'k',
            long = "key",
            default_value = env_or_default("RUSTY_KEY_PRIVATE_KEY", DEFAULT_PRIVATE_KEY).into()
        )]
        key: PathBuf,

        /// Input path for encrypted file
        #[arg(short = 'i', long = "input")]
        input: PathBuf,

        /// Output path for decrypted file
        #[arg(short = 'o', long = "output")]
        output: PathBuf,

        /// Force overwrite existing output file
        #[arg(long)]
        force: bool,
    },

    /// Decrypt all secrets from directory to output directory
    DecryptAll {
        /// Private key file path
        /// Environment: RUSTY_KEY_PRIVATE_KEY
        #[arg(
            short = 'k',
            long = "key",
            default_value = env_or_default("RUSTY_KEY_PRIVATE_KEY", DEFAULT_PRIVATE_KEY).into()
        )]
        key: PathBuf,

        /// Source directory containing .age encrypted files
        /// Environment: RUSTY_KEY_SECRETS_DIR
        #[arg(
            short = 's',
            long = "source",
            default_value = env_or_default("RUSTY_KEY_SECRETS_DIR", DEFAULT_SECRETS_DIR).into()
        )]
        source: PathBuf,

        /// Output directory for decrypted files
        /// Environment: RUSTY_KEY_CACHE_DIR
        #[arg(
            short = 'o',
            long = "output",
            default_value = env_or_default("RUSTY_KEY_CACHE_DIR", DEFAULT_CACHE_DIR).into()
        )]
        output: PathBuf,

        /// Force overwrite existing output files
        #[arg(long)]
        force: bool,
    },
}
