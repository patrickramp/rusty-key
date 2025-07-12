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
    let crypto = CryptoManager::new();
    let fs = FileManager::new();

    match cli.command {
        Commands::Init {
            keys_dir,
            secrets_dir,
            force,
        } => crypto.init_store(&keys_dir, &secrets_dir, force, &fs),
        Commands::NewRecipient {
            key_path,
            recipient_path,
            force,
        } => crypto.new_recipient(&key_path, &recipient_path, force, &fs),
        Commands::NewIdentity { key_path, force } => crypto.new_identity(&key_path, force, &fs),
        Commands::Encrypt {
            recipient,
            input,
            output,
            force,
        } => crypto.encrypt_secret(&recipient, &input, &output, force, &fs),
        Commands::Quick {
            recipient,
            key_path,
            input,
            name,
            output,
            cache,
            auto_decrypt,
            force,
        } => crypto.quick_secret(
            &recipient,
            &key_path,
            &input,
            &name,
            &output,
            &cache,
            auto_decrypt,
            force,
            &fs,
        ),
        Commands::Show { key, source } => crypto.show_secret(&key, &source),
        Commands::Rotate {
            old_key,
            new_keys_dir,
            secrets_dir,
            verify,
            force,
        } => crypto.rotate_secrets_key(&old_key, &new_keys_dir, &secrets_dir, verify, force, &fs),
        Commands::List { secrets_dir } => crypto.list_secrets(&secrets_dir, &fs),
        Commands::Decrypt {
            key,
            input,
            output,
            force,
        } => crypto.decrypt_to_file(&key, &input, &output, force, &fs),
        Commands::DecryptAll {
            key,
            source,
            output,
            force,
        } => crypto.decrypt_all_secrets(&key, &source, &output, force, &fs),
    }
}
