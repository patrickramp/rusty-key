mod cli;
mod crypto;
mod errors;
mod filesystem;
mod random;

use cli::{Cli, Commands};
use crypto::{CryptoManager};
use errors::SecretError;

use clap::Parser;

/// Minimal encrypted secret management utility for automated deployments
/// Encrypts secrets at rest using age, provides clean migration to Vault
fn main() -> Result<(), SecretError> {
    let cli = Cli::parse();
    let crypto = CryptoManager;

    match cli.commands {
        Commands::Init {
            keys_dir,
            secrets_dir,
            force,
        } => crypto.init_store(&keys_dir, &secrets_dir, force),

        Commands::GenId { key_path, force } => crypto.new_identity(&key_path, force),

        Commands::GenRecipt {
            key_path,
            recipient_path,
            force,
        } => crypto.new_recipient(&key_path, &recipient_path, force),

        Commands::RotateKeys {
            key_path,
            new_keys_dir,
            secrets_dir,
            verify,
            force,
        } => crypto.rotate_encryption_keys(&key_path, &new_keys_dir, &secrets_dir, verify, force),

        Commands::Encrypt {
            recipient,
            input,
            output,
            force,
        } => crypto.new_secret(&recipient, &input, &output, force),

        Commands::Decrypt {
            key_path,
            input,
            output,
            force,
        } => crypto.decrypt_path_to_path(&key_path, &input, &output, force),

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
        ),

        Commands::Show { key_path, source } => crypto.show_secret(&key_path, &source),

        Commands::RotateSecret {
            key_path,
            recipient,
            source,
            base,
        } => crypto.rotate_secret(&key_path, &recipient, &source, base),

        Commands::List { secrets_dir } => crypto.list_secrets(&secrets_dir),

        Commands::DecryptAll {
            key_path,
            source,
            output,
            force,
        } => crypto.decrypt_all_secrets(&key_path, &source, &output, force),

        Commands::RotateAll {
            key_path,
            recipient,
            secrets_dir,
            base,
        } => crypto.rotate_all_secrets(&key_path, &recipient, &secrets_dir, base),
    }
}