#!/bin/bash
# new-secret.sh - Quick secret encryption wrapper
# Usage: ./new-secret.sh <secret-name> [secret-value]

set -euo pipefail

# Configuration
SECRETS_DIR="/var/rusty-key"
PUBLIC_KEY="$SECRETS_DIR/keys/master.pub"
SECRETS_STORE="$SECRETS_DIR/secrets"
RUSTY_KEY_BIN="/usr/local/bin/rusty-key"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

show_help() {
    cat <<EOF
Usage: $0 <secret-name> [secret-value]

Encrypt secrets using your rusty-key CLI tool.

Arguments:
    secret-name     Name of the secret (will create <name>.age)
    secret-value    Secret value (optional, will prompt if not provided)

Examples:
    $0 db-password                    # Prompts for password
    $0 api-key "sk-1234567890"        # Direct value
    $0 ssh-key @~/.ssh/id_rsa         # From file
    echo "secret" | $0 pipe-secret -  # From stdin

Environment:
    SECRETS_DIR     Base directory (default: /etc/secrets)
    RUSTY_KEY_BIN   Path to rusty-key binary

Options:
    -h, --help      Show this help
    -f, --force     Overwrite existing secrets
    -l, --list      List existing secrets
    -v, --verify    Verify secret after encryption
EOF
}

# Check if secret manager is available
check_RUSTY_KEY_BIN() {
    if ! command -v "$RUSTY_KEY_BIN" &>/dev/null; then
        log_error "rusty-key not found in PATH"
        log_error "Install it or set RUSTY_KEY_BIN environment variable"
        exit 1
    fi
}

# Check if secret store is initialized
check_initialized() {
    if [[ ! -f "$PUBLIC_KEY" ]]; then
        log_error "Secret store not initialized at $SECRETS_DIR"
        log_info "Run: $RUSTY_KEY_BIN init --path $SECRETS_DIR"
        exit 1
    fi
}

# List existing secrets
list_secrets() {
    local store="${SECRETS_STORE:-./secrets}"

    if [[ ! -d "$store" ]]; then
        log_warn "No secrets directory found: $store"
        return 0
    fi

    local files=()
    while IFS= read -r -d '' file; do
        files+=("$file")
    done < <(find "$store" -maxdepth 1 -type f -name "*.age" -print0)

    if [[ ${#files[@]} -eq 0 ]]; then
        log_warn "No secrets found in $store"
        return 0
    fi

    log_info "Existing secrets in $store:"
    for file in "${files[@]}"; do
        basename "${file}" .age
    done
    log_info "Total: ${#files[@]} secrets"
}

# Validate secret name
validate_secret_name() {
    local name="$1"

    # Check for valid characters (alphanumeric, hyphens, underscores)
    if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log_error "Invalid secret name: $name"
        log_error "Use only alphanumeric characters, hyphens, and underscores"
        exit 1
    fi

    # Check length
    if [[ ${#name} -gt 50 ]]; then
        log_error "Secret name too long (max 50 characters): $name"
        exit 1
    fi
}

# Prompt for secret value securely
prompt_secret() {
    local secret_value

    log_info "Enter secret value (input hidden):"
    read -r -s -p "> " secret_value
    echo # Add newline after hidden input

    if [[ -z "$secret_value" ]]; then
        log_error "Empty secret value not allowed"
        exit 1
    fi

    echo "$secret_value"
}

# Verify encrypted secret
verify_secret() {
    local secret_name="$1"
    local original_value="$2"
    local encrypted_file="$SECRETS_STORE/${secret_name}.age"
    local private_key="$SECRETS_DIR/keys/master.key"

    if [[ ! -f "$private_key" ]]; then
        log_warn "Cannot verify: private key not accessible"
        return 0
    fi

    log_info "Verifying encrypted secret..."

    # Decrypt and compare (be careful with output)
    local decrypted_value
    if decrypted_value=$("$RUSTY_KEY_BIN" decrypt --key "$private_key" --input "$encrypted_file" 2>/dev/null); then
        if [[ "$decrypted_value" == "$original_value" ]]; then
            log_info "✓ Verification successful"
        else
            log_error "✗ Verification failed: decrypted value doesn't match"
            exit 1
        fi
    else
        log_error "✗ Verification failed: could not decrypt"
        exit 1
    fi
}

# Main encryption function
encrypt_secret() {
    local secret_name="$1"
    local secret_value="$2"
    local force="$3"
    local verify="$4"

    validate_secret_name "$secret_name"

    local encrypted_file="$SECRETS_STORE/${secret_name}.age"

    # Check if secret already exists
    if [[ -f "$encrypted_file" && "$force" != "true" ]]; then
        log_error "Secret '$secret_name' already exists"
        log_info "Use --force to overwrite"
        exit 1
    fi

    # Create secrets directory if it doesn't exist
    mkdir -p "$SECRETS_STORE"

    # Encrypt the secret
    log_info "Encrypting secret '$secret_name'..."

    if "$RUSTY_KEY_BIN" encrypt \
        --recipient "$PUBLIC_KEY" \
        --input "$secret_value" \
        --output "$encrypted_file" \
        ${force:+--force} \
        2>/dev/null; then

        log_info "✓ Secret encrypted successfully: $encrypted_file"

        # Verify if requested
        if [[ "$verify" == "true" ]]; then
            verify_secret "$secret_name" "$secret_value"
        fi

        # Show file info
        log_info "File size: $(stat -c%s "$encrypted_file") bytes"
        log_info "Permissions: $(stat -c%a "$encrypted_file")"

    else
        log_error "Failed to encrypt secret"
        exit 1
    fi
}

# Parse command line arguments
main() {
    local secret_name=""
    local secret_value=""
    local force="false"
    local verify="false"

    while [[ $# -gt 0 ]]; do
        case $1 in
        -h | --help)
            show_help
            exit 0
            ;;
        -f | --force)
            force="true"
            shift
            ;;
        -l | --list)
            check_RUSTY_KEY_BIN
            check_initialized
            list_secrets
            exit 0
            ;;
        -v | --verify)
            verify="true"
            shift
            ;;
        -*)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
        *)
            if [[ -z "$secret_name" ]]; then
                secret_name="$1"
            elif [[ -z "$secret_value" ]]; then
                secret_value="$1"
            else
                log_error "Too many arguments"
                show_help
                exit 1
            fi
            shift
            ;;
        esac
    done

    # Validate arguments
    if [[ -z "$secret_name" ]]; then
        log_error "Secret name required"
        show_help
        exit 1
    fi

    # Prerequisites
    check_RUSTY_KEY_BIN
    check_initialized

    # Get secret value if not provided
    if [[ -z "$secret_value" ]]; then
        secret_value=$(prompt_secret)
    elif [[ "$secret_value" == "-" ]]; then
        # Read from stdin
        secret_value=$(cat)
    fi

    # Encrypt the secret
    encrypt_secret "$secret_name" "$secret_value" "$force" "$verify"
}

# Run main function
main "$@"

exit 0