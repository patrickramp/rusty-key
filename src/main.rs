mod cli;
mod crypto;
mod errors;
mod filesystem;
mod random;

use cli::{Cli, Commands};
use crypto::CryptoManager;
use errors::SecretError;

use clap::Parser;

/// Minimal encrypted secret management utility for automated deployments
/// Encrypts secrets at rest using age, provides clean migration to Vault
fn main() -> Result<(), SecretError> {
    let cli = Cli::parse();
    let crypto = CryptoManager;

    match cli.commands {
        // ═══════════════════════════════════════════════════════════════════════════════
        // INITIALIZATION & SETUP
        // ═══════════════════════════════════════════════════════════════════════════════
        
        Commands::Init {
            keys_dir,
            secrets_dir,
            force,
        } => crypto.init_store(&keys_dir, &secrets_dir, force),

        // ═══════════════════════════════════════════════════════════════════════════════
        // KEY MANAGEMENT
        // ═══════════════════════════════════════════════════════════════════════════════
        
        Commands::Identity {
            identity_path, 
            force 
        } => crypto.new_identity(&identity_path, force),

        Commands::Recipient {
            identity_path,
            recipient_path,
            force,
        } => crypto.new_recipient(&identity_path, &recipient_path, force),

        Commands::RotateKeys {
            identity_path,
            new_keys_dir,
            secrets_dir,
            verify,
            force,
        } => crypto.rotate_encryption_keys(&identity_path, &new_keys_dir, &secrets_dir, verify, force),

        // ═══════════════════════════════════════════════════════════════════════════════
        // ENCRYPTION OPERATIONS
        // ═══════════════════════════════════════════════════════════════════════════════
        
        Commands::Encrypt {
            recipient,
            input,
            output,
            force,
        } => crypto.new_secret(&recipient, &input, &output, force),

        Commands::Secret {
            recipient,
            identity_path,
            name,
            length,
            base,
            output_dir,
            cache_dir,
            auto_decrypt,
            force,
        } => crypto.quick_secret(
            &recipient,
            &identity_path,
            &name,
            length,
            base,
            &output_dir,
            &cache_dir,
            auto_decrypt,
            force,
        ),

        // ═══════════════════════════════════════════════════════════════════════════════
        // DECRYPTION OPERATIONS
        // ═══════════════════════════════════════════════════════════════════════════════
        
        Commands::Decrypt {
            identity_path,
            input,
            output,
            force,
        } => crypto.decrypt_path_to_path(&identity_path, &input, &output, force),

        Commands::Show { 
            identity_path, 
            input 
        } => crypto.show_secret(&identity_path, &input),

        Commands::DecryptAll {
            identity_path,
            secrets_dir,
            output_dir,
            force,
        } => crypto.decrypt_all_secrets(&identity_path, &secrets_dir, &output_dir, force),

        Commands::ToEnv {
            identity_path,
            secrets_dir,
            output,
            force,
        } => crypto.decrypt_to_env(&identity_path, &secrets_dir, &output, force),

        // ═══════════════════════════════════════════════════════════════════════════════
        // SECRET ROTATION
        // ═══════════════════════════════════════════════════════════════════════════════
        
        Commands::RotateSecret {
            identity_path,
            recipient,
            input,
            base,
            safe,
        } => crypto.rotate_secret(&identity_path, &recipient, &input, base, safe),

        Commands::RotateAll {
            identity_path,
            recipient,
            secrets_dir,
            base,
            safe,
        } => crypto.rotate_all_secrets(&identity_path, &recipient, &secrets_dir, base, safe),

        // ═══════════════════════════════════════════════════════════════════════════════
        // UTILITIES
        // ═══════════════════════════════════════════════════════════════════════════════
        
        Commands::List { 
            secrets_dir 
        } => crypto.list_secrets(&secrets_dir),
    }
}