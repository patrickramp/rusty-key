use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rusty-key",
    about = "Encrypted secrets manager using age encryption",
    version = "0.3.0",
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
        #[arg(short = 'k', long = "keys-dir", default_value = "/etc/rusty-key/keys")]
        keys_dir: PathBuf,

        /// Directory for encrypted secrets storage
        #[arg(short = 's', long = "secrets-dir", default_value = "/etc/rusty-key/secrets")]
        secrets_dir: PathBuf,

        /// Force overwrite existing keys and permissions
        #[arg(long)]
        force: bool,
    },

    /// Generate new identity (private key)
     NewIdentity {
        /// Output path for new private key
        #[arg(short = 'k', long = "key-path", default_value = "/etc/rusty-key/keys/new_identity.key")]
        key_path: PathBuf,

        /// Force overwrite existing private key
        #[arg(long)]
        force: bool,
    },

    /// Generate new recipient (public key) from existing identity
    NewRecipient {
        /// Path to private key file
        #[arg(short = 'k', long = "key-path", default_value = "/etc/rusty-key/keys/secrets.key")]
        key_path: PathBuf,

        /// Output path for new recipient key
        #[arg(short = 'r', long = "recipient-path", default_value = "/etc/rusty-key/keys/new_recipient.pub")]
        recipient_path: PathBuf,

        /// Force overwrite existing public key
        #[arg(long)]
        force: bool,
    },

    /// Encrypt a secret to specified file
    Encrypt {
        /// Public key for encryption (@file, - for stdin, or literal key)
        #[arg(short = 'r', long = "recipient", default_value = "/etc/rusty-key/keys/secrets.pub")]
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

    /// Encrypt with auto-naming and optional auto-decrypt
    Quick {
        /// Public recipient key for encryption (@file, - for stdin, or literal key)
        #[arg(short = 'r', long = "recipient", default_value = "/etc/rusty-key/keys/secrets.pub")]
        recipient: String,

        /// Private key file path for optional auto-decrypt
        #[arg(short = 'k', long = "key-path", default_value = "/etc/rusty-key/keys/secrets.key")]
        key_path: PathBuf,

        /// Input source (@file, - for stdin, or literal value)
        #[arg(short = 'i', long = "input")]
        input: String,

        /// Secret identifier name
        #[arg(short = 'n', long = "name", default_value = "random_id")]
        name: String,

        /// Output directory for encrypted secrets
        #[arg(short = 'o', long = "output", default_value = "/etc/rusty-key/secrets")]
        output: PathBuf,

        /// Cache directory for decrypted secrets
        #[arg(short = 'c', long = "cache", default_value = "/run/rusty-key/cache")]
        cache: PathBuf,

        /// Automatically decrypt secret to cache directory after encryption
        #[arg(short = 'a', long = "auto-decrypt")]
        auto_decrypt: bool,

        /// Force overwrite existing files
        #[arg(long)]
        force: bool,
    },

    /// Decrypt and print a single secret to stdout (USE WITH CAUTION)
    Show {
        /// Private key file path
        #[arg(short = 'k', long = "key", default_value = "/etc/rusty-key/keys/secrets.key")]
        key: PathBuf,

        /// Encrypted .age source file
        #[arg(short = 's', long = "source")]
        source: PathBuf,
    },

    /// Rotate encryption keys and re-encrypt all secrets
    Rotate {
        /// Old private key file path
        #[arg(short = 'k', long = "old-key", default_value = "/etc/rusty-key/keys/secrets.key")]
        old_key: PathBuf,

        /// Directory for new key creation
        #[arg(short = 'n', long = "new-keys", default_value = "/etc/rusty-key/new_keys")]
        new_keys_dir: PathBuf,
        
        /// Directory containing encrypted .age secrets
        #[arg(short = 's', long = "secrets-dir", default_value = "/etc/rusty-key/secrets")]
        secrets_dir: PathBuf,

        /// Verify new key roundtrip
        #[arg(short = 'v', long = "verify")]
        verify: bool,

        /// Force overwrite existing keys and directories
        #[arg(long)]
        force: bool,
    },

    /// List all encrypted .age secrets in directory
    List {
        /// Directory containing encrypted .age files
        #[arg(short = 's', long = "secrets-dir", default_value = "/etc/rusty-key/secrets")]
        secrets_dir: PathBuf,
    },

    /// Decrypt single secret to output file
    Decrypt {
        /// Private key file path
        #[arg(short = 'k', long = "key", default_value = "/etc/rusty-key/keys/secrets.key")]
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

    /// Decrypt all secrets from source directory to output directory
    DecryptAll {
        /// Private key file path
        #[arg(short = 'k', long = "key", default_value = "/etc/rusty-key/keys/secrets.key")]
        key: PathBuf,

        /// Source directory containing .age encrypted files
        #[arg(short = 's', long = "source", default_value = "/etc/rusty-key/secrets")]
        source: PathBuf,

        /// Output directory for decrypted files
        #[arg(short = 'o', long = "output", default_value = "/run/rusty-key/cache")]
        output: PathBuf,

        /// Force overwrite existing output files
        #[arg(long)]
        force: bool,
    },
}