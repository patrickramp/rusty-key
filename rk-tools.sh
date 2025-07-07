#!/bin/bash
# rk-tools.sh - Secure secret encryption wrapper
# Usage: ./rk-tools.sh <secret-name> [secret-value]

set -euo pipefail

# Security: Clear environment and set restrictive defaults
export PATH="/usr/local/bin:/usr/bin:/bin"
umask 077

# Configuration - Readonly after setting
readonly SECRETS_DIR="${SECRETS_DIR:-/var/rusty-key}"
readonly PUBLIC_KEY="$SECRETS_DIR/keys/master.pub"
readonly SECRETS_STORE="$SECRETS_DIR/secrets"
readonly RUSTY_KEY_BIN="${RUSTY_KEY_BIN:-/usr/local/bin/rusty-key}"
readonly SCRIPT_NAME="$(basename "$0")"

# Security limits
readonly MAX_SECRET_SIZE=1048576 # 1MB max secret size
readonly MAX_SECRET_NAME_LEN=50
readonly SECRET_NAME_PATTERN='^[a-zA-Z0-9_-]+$'

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Global cleanup trap
cleanup() {
    local exit_code=$?
    # Clear any sensitive variables
    unset secret_value temp_file temp_input
    # Remove temporary files if they exist
    [[ -n "${temp_file:-}" && -f "$temp_file" ]] && rm -f -- "$temp_file"
    [[ -n "${temp_input:-}" && -f "$temp_input" ]] && rm -f -- "$temp_input"
    exit $exit_code
}
trap cleanup EXIT INT TERM

# Logging functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Security check: ensure we're not running as root unless necessary
check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        log_warn "Running as root - ensure this is necessary"
        if [[ ! -w "$SECRETS_DIR" ]]; then
            log_error "Root privileges required but secrets directory not writable"
            exit 1
        fi
    fi
}

# Help with security notes
show_help() {
    cat <<EOF
Usage: $SCRIPT_NAME <secret-name> [secret-value]

Securely encrypt secrets using rusty-key with age encryption.

Arguments:
    secret-name     Name of the secret (alphanumeric, -, _ only)
    secret-value    Secret value (optional, will prompt securely)

Examples:
    $SCRIPT_NAME db-password                    # Secure prompt
    $SCRIPT_NAME api-key "sk-1234567890"        # Direct (less secure)
    $SCRIPT_NAME ssh-key @~/.ssh/id_rsa         # From file
    echo "secret" | $SCRIPT_NAME pipe-secret -  # From stdin

Security Features:
    • Validates secret name format and length
    • Clears sensitive data from memory
    • Prevents command injection
    • Limits secret size to $MAX_SECRET_SIZE bytes

Environment:
    SECRETS_DIR     Base directory (default: /var/rusty-key)
    RUSTY_KEY_BIN   Path to rusty-key binary

Options:
    -h, --help      Show this help
    -f, --force     Overwrite existing secrets
    -l, --list      List existing secrets
    -v, --verify    Verify secret after encryption
    -q, --quiet     Suppress info messages
    --check         Verify system setup

Files:
    $PUBLIC_KEY
    $SECRETS_STORE/*.age
EOF
}

# System checks
check_system() {
    local errors=0

    # Check binary exists and is executable
    if ! command -v "$RUSTY_KEY_BIN" &>/dev/null; then
        log_error "rusty-key not found: $RUSTY_KEY_BIN"
        log_error "Install rusty-key or set RUSTY_KEY_BIN environment variable"
        ((errors++))
    fi

    # Check if secrets directory is writable
    if [[ ! -d "$SECRETS_DIR" ]]; then
        if ! mkdir -p "$SECRETS_DIR" 2>/dev/null; then
            log_error "Cannot create secrets directory: $SECRETS_DIR"
            ((errors++))
        fi
    fi

    # Check if initialized
    if [[ ! -f "$PUBLIC_KEY" ]]; then
        log_error "Secret store not initialized at $SECRETS_DIR"
        log_info "Run: $RUSTY_KEY_BIN init --path $SECRETS_DIR"
        ((errors++))
    fi

    # Check secrets store directory
    if [[ ! -d "$SECRETS_STORE" ]]; then
        if ! mkdir -p "$SECRETS_STORE" 2>/dev/null; then
            log_error "Cannot create secrets store: $SECRETS_STORE"
            ((errors++))
        fi
    fi

    if [[ $errors -gt 0 ]]; then
        log_error "System check failed with $errors errors"
        exit 1
    fi
}

# Secret listing with file info
list_secrets() {
    if [[ ! -d "$SECRETS_STORE" ]]; then
        log_warn "No secrets directory found: $SECRETS_STORE"
        return 0
    fi

    local files=()
    local total_size=0

    # Use find with explicit security settings
    while IFS= read -r -d '' file; do
        files+=("$file")
        if [[ -f "$file" ]]; then
            local size
            size=$(stat -c%s "$file" 2>/dev/null || echo 0)
            total_size=$((total_size + size))
        fi
    done < <(find "$SECRETS_STORE" -maxdepth 1 -type f -name "*.age" -print0 2>/dev/null)

    if [[ ${#files[@]} -eq 0 ]]; then
        log_warn "No secrets found in $SECRETS_STORE"
        return 0
    fi

    log_info "Existing secrets in $SECRETS_STORE:"
    for file in "${files[@]}"; do
        local basename_file
        basename_file=$(basename "$file" .age)
        local size
        size=$(stat -c%s "$file" 2>/dev/null || echo "?")
        local perms
        perms=$(stat -c%a "$file" 2>/dev/null || echo "?")
        local file_owner
        file_owner=$(stat -c%U "$file" 2>/dev/null || echo "?")
        local file_group
        file_group=$(stat -c%G "$file" 2>/dev/null || echo "?") 

        echo "  $basename_file [${size}b] ($perms $file_owner:$file_group)"
    done
    log_info "Total: ${#files[@]} secrets, ${total_size} bytes"
}

# Secret name validation
validate_secret_name() {
    local name="$1"

    # Check length
    if [[ ${#name} -gt $MAX_SECRET_NAME_LEN ]]; then
        log_error "Secret name too long (max $MAX_SECRET_NAME_LEN characters): $name"
        exit 1
    fi
    
    # Check for valid characters
    if [[ ! "$name" =~ $SECRET_NAME_PATTERN ]]; then
        log_error "Invalid secret name: $name"
        log_error "Use only alphanumeric characters, hyphens, and underscores"
        exit 1
    fi
}

# Secure secret prompt with validation
prompt_secret() {
    local secret_value
    local confirm_value

    log_info "Enter secret value (input hidden):"
    read -r -s -p "> " secret_value
    echo >&2  # Send newline to stderr, not stdout

    if [[ -z "$secret_value" ]]; then
        log_error "Empty secret value not allowed"
        exit 1
    fi
    
    # Check secret size
    if [[ ${#secret_value} -gt $MAX_SECRET_SIZE ]]; then
        log_error "Secret too large (max $MAX_SECRET_SIZE bytes)"
        exit 1
    fi

    # Confirm for interactive sessions
    if [[ -t 0 ]]; then
        log_info "Confirm secret value:"
        read -r -s -p "> " confirm_value
        echo >&2  # Send newline to stderr, not stdout
        
        if [[ "$secret_value" != "$confirm_value" ]]; then
            log_error "Secret values don't match"
            exit 1
        fi
    fi

    printf '%s' "$secret_value"  # Use printf instead of echo to avoid newlines
}

# Secret verification with error handling
verify_secret() {
    local secret_name="$1"
    local original_value="$2"
    local encrypted_file="$SECRETS_STORE/${secret_name}.age"
    local private_key="$SECRETS_DIR/keys/master.key"

    if [[ ! -f "$private_key" ]]; then
        log_warn "Cannot verify: private key not accessible at $private_key"
        return 0
    fi

    log_info "Verifying encrypted secret..."

    # Create temporary file for decryption
    local temp_file
    temp_file=$(mktemp)

    # Decrypt to temp file
    if "$RUSTY_KEY_BIN" decrypt \
        --key "$private_key" \
        --input "$encrypted_file" \
        --output "$temp_file" 2>/dev/null; then

        local decrypted_value
        decrypted_value=$(cat "$temp_file")

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

    # Clean up temp file
    rm -f "$temp_file"
}

# Main encryption function
encrypt_secret() {
    local secret_name="$1"
    local secret_value="$2"
    local force="$3"
    local verify="$4"
    local quiet="${5:-false}"

    validate_secret_name "$secret_name"

    # Check secret size
    if [[ ${#secret_value} -gt $MAX_SECRET_SIZE ]]; then
        log_error "Secret too large (${#secret_value} bytes, max $MAX_SECRET_SIZE)"
        exit 1
    fi

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
    [[ "$quiet" != "true" ]] && log_info "Encrypting secret '$secret_name'..."

    # Use temporary file for input to avoid command line exposure
    local temp_input
    temp_input=$(mktemp)

    echo -n "$secret_value" >"$temp_input"

    if "$RUSTY_KEY_BIN" encrypt \
        --recipient "$PUBLIC_KEY" \
        --input "$temp_input" \
        --output "$encrypted_file" 2>/dev/null; then

        [[ "$quiet" != "true" ]] && log_info "✓ Secret encrypted successfully: $encrypted_file"

        # Verify if requested
        if [[ "$verify" == "true" ]]; then
            verify_secret "$secret_name" "$secret_value"
        fi

        # Show file info
        if [[ "$quiet" != "true" ]]; then
            local file_size
            file_size=$(stat -c%s "$encrypted_file" 2>/dev/null || echo "?")
            local file_perms
            file_perms=$(stat -c%a "$encrypted_file" 2>/dev/null || echo "?")
            local file_owner
            file_owner=$(stat -c%U "$encrypted_file" 2>/dev/null || echo "?")
            local file_group
            file_group=$(stat -c%G "$encrypted_file" 2>/dev/null || echo "?")

            log_info "File: $encrypted_file"
            log_info "Size: ${file_size} bytes"
            log_info "Permissions: ${file_perms} (${file_owner}:${file_group})"
        fi

    else
        log_error "Failed to encrypt secret"
        exit 1
    fi

    # Clean up temp file
    rm -f "$temp_input"
}

# Main function with better argument parsing
main() {
    local secret_name=""
    local secret_value=""
    local force="false"
    local verify="false"
    local quiet="false"

    # Security check first
    check_privileges

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
            check_system
            list_secrets
            exit 0
            ;;
        -v | --verify)
            verify="true"
            shift
            ;;
        -q | --quiet)
            quiet="true"
            shift
            ;;
        --check)
            check_system
            log_info "System check passed"
            exit 0
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

    # System checks
    check_system

    # Get secret value if not provided
    if [[ -z "$secret_value" ]]; then
        secret_value=$(prompt_secret)
    elif [[ "$secret_value" == "-" ]]; then
        # Read from stdin with size limit
        secret_value=$(head -c $MAX_SECRET_SIZE)
        if [[ ${#secret_value} -eq $MAX_SECRET_SIZE ]]; then
            log_error "Secret from stdin too large (max $MAX_SECRET_SIZE bytes)"
            exit 1
        fi
    elif [[ "$secret_value" =~ ^@(.+)$ ]]; then
        # Read from file
        local file_path="${BASH_REMATCH[1]}"
        if [[ ! -f "$file_path" ]]; then
            log_error "File not found: $file_path"
            exit 1
        fi
        secret_value=$(head -c $MAX_SECRET_SIZE "$file_path")
        if [[ ${#secret_value} -eq $MAX_SECRET_SIZE ]]; then
            log_error "File too large (max $MAX_SECRET_SIZE bytes)"
            exit 1
        fi
    fi

    # Encrypt the secret
    encrypt_secret "$secret_name" "$secret_value" "$force" "$verify" "$quiet"
}

# Run main function
main "$@"
