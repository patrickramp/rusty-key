# Secret Manager User Guide & Vault Migration Path

## Overview

This utility provides minimal, secure secret management for container deployments using age encryption. It's designed as a bridge solution with a clean migration path to HashiCorp Vault.

## Core Architecture

- **Encryption**: Uses age (modern, secure file encryption)
- **Storage**: Encrypted secrets at rest with proper filesystem permissions
- **Memory Safety**: Automatic memory zeroing for sensitive data
- **Atomicity**: Atomic file operations prevent partial writes
- **Concurrency**: File locking prevents concurrent access issues

## Installation & Setup

### Prerequisites

```bash
# Ensure you have Rust installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone <your-repo>
cd rusty-key
cargo build --release

# Install to system path
sudo cp target/release/rusty-key /usr/local/bin/
```

### Directory Structure

```
/var/rusty-key/
├── keys/
│   ├── master.key    # Private key (0600)
│   └── master.pub    # Public key (0640)
└── secrets/
    ├── db-password.age
    ├── api-key.age
    └── tls-cert.age
```

## Usage Guide

### 1. Initialize Secret Store

```bash
# Initialize with default path
rusty-key init

# Initialize with custom path
rusty-key init --path /srv/secrets

# Force overwrite existing keys
rusty-key init --path /opt/secrets --force
```

**Security Notes:**
- Keys directory gets `0700` permissions (owner only)
- Secrets directory gets `0750` permissions (owner + group)
- Private key gets `0600` permissions
- Public key gets `0640` permissions

### 2. Encrypt Secrets

```bash
# Encrypt literal string
rusty-key encrypt \
    --recipient /var/rusty-key/keys/master.pub \
    --input "my-secret-password" \
    --output /var/rusty-key/secrets/db-password.age

# Encrypt from file (@ syntax for explicit file reading)
rusty-key encrypt \
    --recipient /var/rusty-key/keys/master.pub \
    --input @/tmp/secret.txt \
    --output /var/rusty-key/secrets/api-key.age

# Encrypt from stdin
echo "secret-value" | rusty-key encrypt \
    --recipient /var/rusty-key/keys/master.pub \
    --input - \
    --output /var/rusty-key/secrets/token.age

# Force overwrite existing encrypted file
rusty-key encrypt \
    --recipient /var/rusty-key/keys/master.pub \
    --input "new-secret" \
    --output /var/rusty-key/secrets/existing.age \
    --force
```

### 3. Decrypt Secrets

```bash
# Decrypt single secret to stdout
rusty-key decrypt \
    --key /var/rusty-key/keys/master.key \
    --input /var/rusty-key/secrets/db-password.age

# Use in shell scripts
DB_PASSWORD=$(rusty-key decrypt \
    --key /var/rusty-key/keys/master.key \
    --input /var/rusty-key/secrets/db-password.age)
```

### 4. Decrypt All Secrets (Container Runtime)

```bash
# Decrypt all secrets to tmpfs for container runtime
rusty-key decrypt-all \
    --key /var/rusty-key/keys/master.key \
    --source /var/rusty-key/secrets \
    --target /tmp/secrets \
    --force

# Verify tmpfs mount
mount | grep /tmp/secrets
# Should show: tmpfs on /tmp/secrets type tmpfs
```



## Container Integration

### Docker Compose Example

```yaml
version: '3.8'
services:
  app:
    image: my-app:latest
    volumes:
      - /opt/secrets:/secrets:ro
      - secrets-tmpfs:/tmp/secrets:rw
    environment:
      - SECRET_PATH=/tmp/secrets
    command: |
      sh -c "
        rusty-key decrypt-all \
          --key /secrets/keys/master.key \
          --source /secrets/secrets \
          --target /tmp/secrets &&
        exec my-app
      "
    tmpfs:
      - /tmp/secrets:rw,noexec,nosuid,size=10m

volumes:
  secrets-tmpfs:
    driver: tmpfs
```

### Systemd Service Example

```ini
[Unit]
Description=Lightwight secret manager
After=network.target

[Service]
Type=forking
User=app
Group=app
Environment=SECRET_PATH=/tmp/secrets
ExecStartPre=/usr/local/bin/rusty-key decrypt-all \
    --key /var/rusty-key/keys/master.key \
    --source /var/rusty-key/secrets \
    --target /run/rk-cache
ExecStart=/usr/local/bin/my-app
ExecStopPost=/bin/rm -rf /run/rk-cache
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/tmp

[Install]
WantedBy=multi-user.target
```

## Security Best Practices

### Create Secrets Group

```bash
# Create the group (safe if already exists)
sudo groupadd --system secrets

```

### File System Security

```bash
# Secure the secrets directory
sudo chown -R root:secrets /var/rusty-key
sudo chmod -R g+rX /var/rusty-key
sudo chmod 700 /var/rusty-key/keys

# Add application users to secrets group
sudo usermod -a -G secrets app-user
```

### Backup Strategy

```bash
# Backup encrypted secrets (safe for off-site storage)
tar -czf secrets-backup-$(date +%Y%m%d).tar.gz /var/rusty-key/secrets/

# Backup keys (requires secure storage)
tar -czf keys-backup-$(date +%Y%m%d).tar.gz /var/rusty-key/keys/
gpg --encrypt --armor -r backup@company.com keys-backup-*.tar.gz
```

### Key Rotation

```bash
# Generate new keypair
rusty-key init --path /opt/secrets-new

# Re-encrypt all secrets with new key
for secret in /var/rusty-key/secrets/*.age; do
    filename=$(basename "$secret" .age)
    
    # Decrypt with old key, encrypt with new key
    rusty-key decrypt \
        --key /var/rusty-key/keys/master.key \
        --input "$secret" | \
    rusty-key encrypt \
        --recipient /opt/secrets-new/keys/master.pub \
        --input - \
        --output "/opt/secrets-new/secrets/$filename.age"
done

# Atomic switch
sudo mv /opt/secrets /opt/secrets-old
sudo mv /opt/secrets-new /opt/secrets
```

## Migration Path to HashiCorp Vault

### Phase 1: Parallel Operation

```bash
#!/bin/bash
# vault-migration-sync.sh

VAULT_ADDR="https://vault.company.com:8200"
VAULT_TOKEN="your-token"

# Export all secrets to Vault
for secret_file in /var/rusty-key/secrets/*.age; do
    secret_name=$(basename "$secret_file" .age)
    secret_value=$(rusty-key decrypt \
        --key /var/rusty-key/keys/master.key \
        --input "$secret_file")
    
    # Write to Vault KV v2
    vault kv put secret/app/"$secret_name" value="$secret_value"
    
    echo "Migrated $secret_name to Vault"
done
```

### Phase 2: Vault-First with Fallback

```bash
#!/bin/bash
# vault-with-fallback.sh

get_secret() {
    local secret_name=$1
    
    # Try Vault first
    if vault kv get -field=value secret/app/"$secret_name" 2>/dev/null; then
        return 0
    fi
    
    # Fallback to age encryption
    if [ -f "/var/rusty-key/secrets/$secret_name.age" ]; then
        rusty-key decrypt \
            --key /var/rusty-key/keys/master.key \
            --input "/var/rusty-key/secrets/$secret_name.age"
        return 0
    fi
    
    echo "Secret $secret_name not found in Vault or local store" >&2
    return 1
}

# Usage
DB_PASSWORD=$(get_secret "db-password")
```

### Phase 3: Vault-Only

```bash
#!/bin/bash
# vault-only.sh

# Remove age-encrypted secrets after confirming Vault migration
vault kv list secret/app/ | while read -r secret_name; do
    if [ -f "/var/rusty-key/secrets/$secret_name.age" ]; then
        # Verify secret exists in Vault
        if vault kv get secret/app/"$secret_name" >/dev/null 2>&1; then
            echo "Removing $secret_name.age (confirmed in Vault)"
            rm "/var/rusty-key/secrets/$secret_name.age"
        else
            echo "WARNING: $secret_name.age exists but not found in Vault"
        fi
    fi
done
```

### Vault Integration Script

```bash
#!/bin/bash
# vault-integration.sh

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-https://vault.company.com:8200}"
VAULT_ROLE="${VAULT_ROLE:-app-role}"
SECRET_PATH="${SECRET_PATH:-secret/app}"

# Authenticate with Vault using AppRole
vault_auth() {
    local role_id_file="/etc/vault/role-id"
    local secret_id_file="/etc/vault/secret-id"
    
    if [[ -f "$role_id_file" && -f "$secret_id_file" ]]; then
        vault write auth/approle/login \
            role_id="$(cat "$role_id_file")" \
            secret_id="$(cat "$secret_id_file")" \
            -format=json | jq -r '.auth.client_token'
    else
        echo "Vault credentials not found" >&2
        exit 1
    fi
}

# Get secret from Vault
get_vault_secret() {
    local secret_name=$1
    local vault_token
    
    vault_token=$(vault_auth)
    VAULT_TOKEN="$vault_token" vault kv get -field=value "$SECRET_PATH/$secret_name"
}

# Main execution
main() {
    local secret_name=$1
    
    # Try Vault first
    if get_vault_secret "$secret_name" 2>/dev/null; then
        exit 0
    fi
    
    # Fallback to age encryption
    if [[ -f "/var/rusty-key/secrets/$secret_name.age" ]]; then
        rusty-key decrypt \
            --key /var/rusty-key/keys/master.key \
            --input "/var/rusty-key/secrets/$secret_name.age"
        exit 0
    fi
    
    echo "Secret $secret_name not found" >&2
    exit 1
}

main "$@"
```

## Monitoring & Alerting

### Health Check Script

```bash
#!/bin/bash
# secret-health-check.sh

check_secret_store() {
    local base_path="/opt/secrets"
    
    # Check directory permissions
    if [[ "$(stat -c %a "$base_path/keys")" != "700" ]]; then
        echo "ERROR: Keys directory has incorrect permissions"
        return 1
    fi
    
    # Check key files exist and have correct permissions
    if [[ ! -f "$base_path/keys/master.key" ]]; then
        echo "ERROR: Master key not found"
        return 1
    fi
    
    if [[ "$(stat -c %a "$base_path/keys/master.key")" != "600" ]]; then
        echo "ERROR: Master key has incorrect permissions"
        return 1
    fi
    
    # Test encryption/decryption
    local test_secret="health-check-$(date +%s)"
    local temp_file="/tmp/health-check.age"
    
    if ! rusty-key encrypt \
        --recipient "$base_path/keys/master.pub" \
        --input "$test_secret" \
        --output "$temp_file" \
        --force; then
        echo "ERROR: Encryption test failed"
        return 1
    fi
    
    local decrypted
    if ! decrypted=$(rusty-key decrypt \
        --key "$base_path/keys/master.key" \
        --input "$temp_file"); then
        echo "ERROR: Decryption test failed"
        return 1
    fi
    
    if [[ "$decrypted" != "$test_secret" ]]; then
        echo "ERROR: Encryption/decryption mismatch"
        return 1
    fi
    
    rm -f "$temp_file"
    echo "OK: Secret store healthy"
}

check_secret_store
```

## Performance Considerations

- **Memory**: Secrets are automatically zeroed from memory
- **Concurrency**: File locking prevents race conditions
- **Atomic Operations**: Temporary files ensure no partial writes
- **Permissions**: Strict filesystem permissions prevent unauthorized access

## Migration Timeline

1. **Week 1-2**: Deploy rusty-key alongside existing systems
2. **Week 3-4**: Migrate secrets to encrypted storage
3. **Week 5-6**: Set up Vault infrastructure
4. **Week 7-8**: Parallel operation with Vault sync
5. **Week 9-10**: Switch to Vault-first with fallback
6. **Week 11-12**: Remove age-encrypted secrets, Vault-only operation

This approach provides a secure, production-ready secret management solution with a clear path to enterprise-grade secret management via Vault.