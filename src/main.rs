mod cli;
mod crypto;
mod errors;
mod filesystem;
mod random;

use cli::{Cli, Commands};
use crypto::{CryptoManager};
use filesystem::FileManager;
use errors::SecretError;

use clap::Parser;

/// Minimal encrypted secret management utility for automated deployments
/// Encrypts secrets at rest using age, provides clean migration to Vault
fn main() -> Result<(), SecretError> {
    let cli = Cli::parse();
    let crypto = CryptoManager;
    let fs = FileManager;

    match cli.commands {
        Commands::Init {
            keys_dir,
            secrets_dir,
            force,
        } => crypto.init_store(&keys_dir, &secrets_dir, force, &fs),

        Commands::GenIdentity { key_path, force } => crypto.new_identity(&key_path, force, &fs),

        Commands::GenRecipient {
            key_path,
            recipient_path,
            force,
        } => crypto.new_recipient(&key_path, &recipient_path, force, &fs),

        Commands::RotateKeys {
            old_key,
            new_keys_dir,
            secrets_dir,
            verify,
            force,
        } => crypto.rotate_encryption_keys(&old_key, &new_keys_dir, &secrets_dir, verify, force, &fs),

        Commands::Encrypt {
            recipient,
            input,
            output,
            force,
        } => crypto.new_secret(&recipient, &input, &output, force, &fs),

        Commands::Decrypt {
            key_path,
            input,
            output,
            force,
        } => crypto.open_secret_to_file(&key_path, &input, &output, force, &fs),

        Commands::Generate {
            recipient,
            key_path,
            name,
            length,
            base,
            output,
            cache,
            auto_decrypt,
            force,
        } => crypto.quick_secret(
            &recipient,
            &key_path,
            &name,
            length,
            base,
            &output,
            &cache,
            auto_decrypt,
            force,
            &fs,
        ),

        Commands::Show { key_path, source } => crypto.show_secret(&key_path, &source, &fs),

        Commands::RotateSecret {
            key_path,
            secret_path,
            recipient,
            base: u64,
            verify,
        } => crypto.rotate_secret(&key_path, secret_path, recipient, base, verify, &fs),

        Commands::List { secrets_dir } => crypto.list_secrets(&secrets_dir, &fs),

        Commands::DecryptAll {
            key_path,
            source,
            output,
            force,
        } => crypto.open_all_secrets(&key_path, &source, &output, force, &fs),

        Commands::RotateAll {
            key_path,
            recipient,
            secrets_dir,
            verify,
            force,
        } => crypto.rotate_secrets(&key_path, &recipient, &secrets_dir, verify, force, &fs),
    }
}