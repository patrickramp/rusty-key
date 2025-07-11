mod cli;
mod crypto;
mod errors;
mod filesystem;
//mod memory;


use cli::{Cli, Commands};
use crypto::CryptoManager;
use errors::SecretError;
use filesystem::FileManager;

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
            public_path,
        } => crypto.new_recipient(&key_path, &public_path, &fs),
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
        } => crypto.quick_secret(&recipient, &key_path, &input, &name, &output, &cache, auto_decrypt, force, &fs),
        Commands::Show { key, source } => crypto.show_secret(&key, &source),
        Commands::Rotate { old_key, new_keys_dir, secrets_dir, force } => crypto.rotate_secrets_key(&old_key, &new_keys_dir, &secrets_dir, force, &fs),
        Commands::List { source } => crypto.list_secrets(&source, &fs),
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
