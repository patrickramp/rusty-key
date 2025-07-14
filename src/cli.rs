use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rusty-key",
    about = "Encrypted secrets manager using age encryption",
    version = "0.4.0",
    long_about = "A secure secrets manager built with Rust, using age encryption for \
                  protecting sensitive data with public key cryptography."
)]
pub struct Cli {
    #[command(subcommand)]
    pub commands: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    // ═══════════════════════════════════════════════════════════════════════════════
    // INITIALIZATION & SETUP
    // ═══════════════════════════════════════════════════════════════════════════════
    
    /// Initialize new secret store and generate keypair
    Init {
        /// Directory for key storage
        #[arg(short, long, env = "RUSTY_KEY_KEYS_DIR", default_value = "/etc/rusty-key/keys")]
        keys_dir: PathBuf,

        /// Directory for encrypted secrets storage
        #[arg(short, long, env = "RUSTY_KEY_SECRETS_DIR", default_value = "/var/lib/rusty-key/secrets")]
        secrets_dir: PathBuf,

        /// Force overwrite existing keys and permissions
        #[arg(long)]
        force: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════════════
    // KEY MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════════
    
    /// Generate new identity (private key)
    Identity {
        /// Path for new private key file
        #[arg(short, long, env = "RUSTY_KEY_IDENTITY_PATH", default_value = "/etc/rusty-key/keys/identity.key")]
        identity_path: PathBuf,

        /// Force overwrite existing private key
        #[arg(long)]
        force: bool,
    },

    /// Generate recipient (public key) from existing identity
    Recipient {
        /// Path to private key file
        #[arg(short, long, env = "RUSTY_KEY_IDENTITY_PATH", default_value = "/etc/rusty-key/keys/identity.key")]
        identity_path: PathBuf,

        /// Output path for recipient key
        #[arg(short, long, env = "RUSTY_KEY_RECIPIENT_PATH", default_value = "/etc/rusty-key/keys/recipient.pub")]
        recipient_path: PathBuf,

        /// Force overwrite existing public key
        #[arg(long)]
        force: bool,
    },

    /// Generate new encryption keys and re-encrypt all secrets
    RotateKeys {
        /// Path to current identity (private key) file
        #[arg(short, long, env = "RUSTY_KEY_IDENTITY_PATH", default_value = "/etc/rusty-key/keys/identity.key")]
        identity_path: PathBuf,

        /// Directory for new key creation
        #[arg(short, long, env = "RUSTY_KEY_NEW_KEYS_DIR", default_value = "/etc/rusty-key/keys")]
        new_keys_dir: PathBuf,
        
        /// Directory containing encrypted secrets
        #[arg(short, long, env = "RUSTY_KEY_SECRETS_DIR", default_value = "/var/lib/rusty-key/secrets")]
        secrets_dir: PathBuf,

        /// Verify new key roundtrip after rotation
        #[arg(short, long)]
        verify: bool,

        /// Force overwrite of new keys
        #[arg(long)]
        force: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════════════
    // ENCRYPTION OPERATIONS
    // ═══════════════════════════════════════════════════════════════════════════════
    
    /// Encrypt input to specified output path
    Encrypt {
        /// Recipient key for encryption (@file, - for stdin, or literal key)
        #[arg(short, long, env = "RUSTY_KEY_RECIPIENT_PATH", default_value = "/etc/rusty-key/keys/recipient.pub")]
        recipient: String,

        /// Input source (@file, - for stdin, or literal value)
        #[arg(short, long, env = "RUSTY_KEY_INPUT")]
        input: String,

        /// Output path for encrypted file
        #[arg(short, long, env = "RUSTY_KEY_OUTPUT")]
        output: PathBuf,

        /// Force overwrite existing output file
        #[arg(long)]
        force: bool,
    },
    
    /// Create new named secret with secure random value
    Secret {
        /// Recipient key for encryption (@file, - for stdin, or literal key)
        #[arg(short, long, env = "RUSTY_KEY_RECIPIENT_PATH", default_value = "/etc/rusty-key/keys/recipient.pub")]
        recipient: String,

        /// Private key file path for optional auto-decrypt
        #[arg(short, long, env = "RUSTY_KEY_IDENTITY_PATH", default_value = "/etc/rusty-key/keys/identity.key")]
        identity_path: PathBuf,

        /// Secret name
        #[arg(short, long, env = "RUSTY_KEY_SECRET_NAME")]
        name: String,

        /// Length of secret characters
        #[arg(short, long, env = "RUSTY_KEY_SECRET_LENGTH", default_value = "32")]
        length: usize,

        /// Base encoding: 16(Hex), 32(RFC4648), 36(Alphanumeric), 58(BTC), 64(URL-Safe), 85(Z85), 94(ASCII)
        #[arg(short, long, env = "RUSTY_KEY_BASE_ENCODING", default_value = "58")]
        base: u64,

        /// Output directory for encrypted secrets
        #[arg(short, long, env = "RUSTY_KEY_SECRETS_DIR", default_value = "/var/lib/rusty-key/secrets")]
        output_dir: PathBuf,

        /// Cache directory for optional auto decrypt
        #[arg(short, long, env = "RUSTY_KEY_CACHE_DIR", default_value = "/run/rusty-key/cache")]
        cache_dir: PathBuf,

        /// Automatically decrypt secret to cache directory after encryption
        #[arg(short, long)]
        auto_decrypt: bool,

        /// Force overwrite existing files
        #[arg(long)]
        force: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════════════
    // DECRYPTION OPERATIONS
    // ═══════════════════════════════════════════════════════════════════════════════
    
    /// Decrypt single secret to output path
    Decrypt {
        /// Private key file path
        #[arg(short, long, env = "RUSTY_KEY_IDENTITY_PATH", default_value = "/etc/rusty-key/keys/identity.key")]
        identity_path: PathBuf,

        /// Input path for encrypted file
        #[arg(short, long, env = "RUSTY_KEY_INPUT")]
        input: PathBuf,

        /// Output path for decrypted file
        #[arg(short, long, env = "RUSTY_KEY_OUTPUT")]
        output: PathBuf,

        /// Force overwrite existing output file
        #[arg(long)]
        force: bool,
    },

    /// Decrypt and print secret to stdout (NOT SECURE)
    Show {
        /// Private key file path
        #[arg(short, long, env = "RUSTY_KEY_IDENTITY_PATH", default_value = "/etc/rusty-key/keys/identity.key")]
        identity_path: PathBuf,

        /// Encrypted source file
        #[arg(short, long, env = "RUSTY_KEY_INPUT")]
        input: PathBuf,
    },

    /// Decrypt all secrets from source directory to output directory
    DecryptAll {
        /// Private key file path
        #[arg(short, long, env = "RUSTY_KEY_IDENTITY_PATH", default_value = "/etc/rusty-key/keys/identity.key")]
        identity_path: PathBuf,

        /// Source directory containing encrypted files
        #[arg(short, long, env = "RUSTY_KEY_SECRETS_DIR", default_value = "/var/lib/rusty-key/secrets")]
        secrets_dir: PathBuf,

        /// Output directory for decrypted files
        #[arg(short, long, env = "RUSTY_KEY_CACHE_DIR", default_value = "/run/rusty-key/cache")]
        output_dir: PathBuf,

        /// Force overwrite existing output files
        #[arg(long)]
        force: bool,
    },

    /// Decrypt all secrets to .env file format
    ToEnv {
        /// Path to private key file
        #[arg(short, long, env = "RUSTY_KEY_IDENTITY_PATH", default_value = "/etc/rusty-key/keys/identity.key")]
        identity_path: PathBuf,

        /// Source directory containing encrypted files
        #[arg(short, long, env = "RUSTY_KEY_SECRETS_DIR", default_value = "/var/lib/rusty-key/secrets")]
        secrets_dir: PathBuf,

        /// Output path for .env file   
        #[arg(short, long, env = "RUSTY_KEY_OUTPUT")]
        output: PathBuf,

        /// Force overwrite existing .env file
        #[arg(long)]
        force: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════════════
    // SECRET ROTATION
    // ═══════════════════════════════════════════════════════════════════════════════
    
    /// Rotate content of single encrypted secret
    RotateSecret {
        /// Private key file path
        #[arg(short, long, env = "RUSTY_KEY_IDENTITY_PATH", default_value = "/etc/rusty-key/keys/identity.key")]
        identity_path: PathBuf,

        /// Recipient key for encryption (@file, - for stdin, or literal key)
        #[arg(short, long, env = "RUSTY_KEY_RECIPIENT_PATH", default_value = "/etc/rusty-key/keys/recipient.pub")]
        recipient: String,

        /// Encrypted source file
        #[arg(short, long, env = "RUSTY_KEY_INPUT")]
        input: PathBuf,

        /// Base encoding: 16(Hex), 32(RFC4648), 36(Alphanumeric), 58(BTC), 64(URL-Safe), 85(Z85), 94(ASCII)
        #[arg(short, long, env = "RUSTY_KEY_BASE_ENCODING", default_value = "58")]
        base: u64,

        /// Safe mode: Create backup before overwriting
        #[arg(short, long)]
        safe: bool,
    },

    /// Rotate content of all secrets in directory
    RotateAll {
        /// Private key file path
        #[arg(short, long, env = "RUSTY_KEY_IDENTITY_PATH", default_value = "/etc/rusty-key/keys/identity.key")]
        identity_path: PathBuf,

        /// Recipient key for encryption (@file, - for stdin, or literal key)
        #[arg(short, long, env = "RUSTY_KEY_RECIPIENT_PATH", default_value = "/etc/rusty-key/keys/recipient.pub")]
        recipient: String,

        /// Directory containing encrypted secrets
        #[arg(short, long, env = "RUSTY_KEY_SECRETS_DIR", default_value = "/var/lib/rusty-key/secrets")]
        secrets_dir: PathBuf,

        /// Base encoding: 16(Hex), 32(RFC4648), 36(Alphanumeric), 58(BTC), 64(URL-Safe), 85(Z85), 94(ASCII)
        #[arg(short, long, env = "RUSTY_KEY_BASE_ENCODING", default_value = "58")]
        base: u64,

        /// Safe mode: Create backup before overwriting
        #[arg(short, long)]
        safe: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════════════
    // UTILITIES
    // ═══════════════════════════════════════════════════════════════════════════════
    
    /// List all encrypted secrets in directory
    List {
        /// Directory containing encrypted files
        #[arg(short, long, env = "RUSTY_KEY_SECRETS_DIR", default_value = "/var/lib/rusty-key/secrets")]
        secrets_dir: PathBuf,
    },
}